package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// Watching QUIC (Hysteria). Its packets are encrypted, but two things show
// through:
//
//   - an Initial packet's long header isn't covered by header protection,
//     so "sent an Initial and nothing came back for the stall time" is the
//     unanswered handshake, as with TLS;
//   - a server has to acknowledge every packet that asks for it within its
//     max_ack_delay (25ms) plus a round trip, and the client re-sends what
//     goes unacknowledged. So when the client sends, again and again, and
//     nothing at all comes back for the stall time, the server is gone.
//     Loss alone never silences a path for seconds.
//
// Packets that only acknowledge go out right after something arrived, so
// only packets sent well after the last arrival start the clock. During a
// download the client only acknowledges: a freeze then goes unseen until it
// sends again (a request, or a new handshake after the idle timeout), which
// is why such servers also get a slow check on a timer.

// ackGrace is how long after a packet arrives the client may send packets
// that only acknowledge it.
const ackGrace = time.Second

// quicUndecided is how many packets may go out, before one that looks like
// QUIC, until the socket is taken for something else (noise packets come
// first).
const quicUndecided = 16

// quicWatch follows one socket's packets.
type quicWatch struct {
	stall  time.Duration
	grace  time.Duration // ackGrace
	report func(Trouble)

	mu sync.Mutex
	// quic: the socket carries QUIC; skipped counts packets sent before
	// that was clear, off that it doesn't.
	quic    bool
	skipped int
	off     bool
	// hello: an Initial went out and nothing has come back yet.
	hello bool
	got   int
	last  time.Time
	// since is when the client first sent after ackGrace without anything
	// arriving, and sends how often it sent since.
	since  time.Time
	sends  int
	timer  *time.Timer
	closed bool
}

func (q *quicWatch) sent(b []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.off || len(b) == 0 {
		return
	}
	if !q.quic {
		switch {
		case quicInitial(b):
			q.quic = true
			q.hello = q.got == 0
		case quicShort(b):
			q.quic = true
		default:
			if q.skipped++; q.skipped > quicUndecided {
				q.off = true
			}
			return
		}
	}
	now := time.Now()
	if q.hello || now.Sub(q.last) > q.grace {
		if q.since.IsZero() {
			q.since, q.sends = now, 0
			q.arm()
		}
		q.sends++
	}
}

func (q *quicWatch) received(packets int) {
	if packets <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.got += packets
	q.last = time.Now()
	q.hello = false
	q.since, q.sends = time.Time{}, 0
	if q.timer != nil {
		q.timer.Stop()
	}
}

func (q *quicWatch) arm() {
	if q.timer == nil {
		q.timer = time.AfterFunc(q.stall, q.silent)
		return
	}
	q.timer.Reset(q.stall)
}

func (q *quicWatch) silent() {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case q.closed || q.since.IsZero():
		return
	case q.hello:
		q.troubleLocked(fmt.Sprintf("the server didn't answer a QUIC handshake for %s", q.stall))
	case q.sends >= 2:
		q.troubleLocked(fmt.Sprintf("the server stopped answering over QUIC (nothing for %s while sending)", q.stall))
	default:
		// A single packet unanswered: a goodbye (CONNECTION_CLOSE) asks
		// for nothing back. Start over with the next one.
		q.since = time.Time{}
	}
}

// troubleLocked reports once per socket.
func (q *quicWatch) troubleLocked(detail string) {
	q.closeLocked()
	go q.report(Trouble{Kind: "stall", Detail: detail})
}

func (q *quicWatch) closeLocked() {
	q.closed = true
	if q.timer != nil {
		q.timer.Stop()
	}
}

func (q *quicWatch) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closeLocked()
}

// quicInitial reports whether b starts with a QUIC v1 or v2 Initial packet.
func quicInitial(b []byte) bool {
	if len(b) < 5 || b[0]&0xc0 != 0xc0 {
		return false
	}
	typ := b[0] >> 4 & 3
	switch binary.BigEndian.Uint32(b[1:5]) {
	case 1:
		return typ == 0
	case 0x6b3343cf:
		return typ == 1
	}
	return false
}

// quicShort reports whether b starts like a QUIC short header packet (a
// socket opened mid-connection, when Hysteria hops ports).
func quicShort(b []byte) bool { return len(b) > 0 && b[0]&0xc0 == 0x40 }

// watchedPacketConn is a UDP socket whose packets a quicWatch follows. It
// offers what quic-go looks for on a *net.UDPConn (socket options, OOB for
// GSO and ECN, batch reads), so QUIC runs as fast as on the bare socket.
type watchedPacketConn struct {
	conn  net.PacketConn
	udp   *net.UDPConn
	batch *ipv4.PacketConn
	q     *quicWatch
}

func newWatchedPacketConn(udp *net.UDPConn, stall time.Duration, report func(Trouble)) *watchedPacketConn {
	c := newWatchedPacket(udp, stall, report)
	c.udp, c.batch = udp, ipv4.NewPacketConn(udp)
	return c
}

// newWatchedPacket watches any packet connection, without the extras.
func newWatchedPacket(conn net.PacketConn, stall time.Duration, report func(Trouble)) *watchedPacketConn {
	return &watchedPacketConn{conn: conn, q: &quicWatch{stall: stall, grace: ackGrace, report: report}}
}

func (c *watchedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.conn.ReadFrom(p)
	if err == nil {
		c.q.received(1)
	}
	return n, addr, err
}

func (c *watchedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.q.sent(p)
	return c.conn.WriteTo(p, addr)
}

func (c *watchedPacketConn) Close() error {
	c.q.close()
	return c.conn.Close()
}

func (c *watchedPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *watchedPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *watchedPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *watchedPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var errNotUDP = errors.New("not a UDP socket")

func (c *watchedPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.udp == nil {
		return nil, errNotUDP
	}
	return c.udp.SyscallConn()
}

func (c *watchedPacketConn) SetReadBuffer(n int) error {
	if c.udp == nil {
		return errNotUDP
	}
	return c.udp.SetReadBuffer(n)
}

func (c *watchedPacketConn) SetWriteBuffer(n int) error {
	if c.udp == nil {
		return errNotUDP
	}
	return c.udp.SetWriteBuffer(n)
}

func (c *watchedPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if c.udp == nil {
		return 0, 0, 0, nil, errNotUDP
	}
	n, oobn, flags, addr, err = c.udp.ReadMsgUDP(b, oob)
	if err == nil {
		c.q.received(1)
	}
	return
}

func (c *watchedPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if c.udp == nil {
		return 0, 0, errNotUDP
	}
	c.q.sent(b)
	return c.udp.WriteMsgUDP(b, oob, addr)
}

// ReadBatch is how quic-go reads several packets at once; without it, it
// would read the socket directly, unseen.
func (c *watchedPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if c.batch == nil {
		return 0, errNotUDP
	}
	n, err := c.batch.ReadBatch(ms, flags)
	c.q.received(n)
	return n, err
}
