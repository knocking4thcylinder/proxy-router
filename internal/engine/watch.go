package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// Watching the server in use: instead of testing it on a timer, the
// connections Xray opens to it are watched for the signs of a server going
// bad, and only those prompt a test. A connection is in trouble when:
//
//   - the server doesn't answer the TLS handshake within the stall time;
//   - data stops in the middle of a TLS record for the stall time. Censors
//     that freeze a connection after ~16 KB leave it open with a record
//     half received; a working server always finishes a record it started.
//     (Proxies hide traffic in TLS, so the server's side is TLS records:
//     REALITY, TLS, and what Vision copies through directly. Connections
//     that turn out not to be TLS are only watched for the rest.)
//   - it's reset, or the server closes it in the middle of a record;
//   - the server closes it right after the TLS handshake, before any real
//     answer to the client's request: how servers turn away a revoked,
//     expired or blocked key;
//   - it can't be opened.
//
// Requests that are simply waiting for an answer (long polls, idle
// keep-alives) sit between records, so they don't count. QUIC sockets
// (Hysteria) are watched as watch_quic.go says.

// Trouble is what a watched connection ran into.
type Trouble struct {
	// Kind is "stall", "cut" or "dial".
	Kind   string
	Detail string
}

func (t Trouble) String() string { return t.Detail }

// Watcher reports Trouble on the connections the running instance opens
// for one outbound. Xray dials through a process-wide dialer, so there is
// one Watcher per process.
type Watcher struct {
	tag     string
	trouble chan Trouble

	mu    sync.Mutex
	on    bool
	stall time.Duration
	// gen changes whenever watching starts or stops: connections opened
	// before then belong to another instance, or to another server.
	gen int
}

var (
	watcherOnce sync.Once
	watcher     *Watcher
	// base is the dialer the Watcher wraps; ControlSockets adds to it.
	base *internet.DefaultSystemDialer
)

// WatchOutbound returns the process's Watcher of connections for the
// outbound tagged tag (or chained behind it). It's off until Start.
func WatchOutbound(tag string) *Watcher {
	watcherOnce.Do(func() {
		watcher = &Watcher{tag: tag, trouble: make(chan Trouble, 8)}
		base = &internet.DefaultSystemDialer{}
		internet.UseAlternativeSystemDialer(&watchDialer{base: base, w: watcher})
	})
	return watcher
}

// Trouble delivers what watched connections run into. It drops reports
// while the receiver is behind: one is enough to act on.
func (w *Watcher) Trouble() <-chan Trouble { return w.trouble }

// Start watches connections opened from now on, counting stall as the
// longest a record may stay half received. Earlier reports are dropped.
func (w *Watcher) Start(stall time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.on, w.stall = true, stall
	w.restartLocked()
}

// Stop stops watching; nothing opened until the next Start is reported.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.on = false
	w.restartLocked()
}

func (w *Watcher) restartLocked() {
	w.gen++
	for {
		select {
		case <-w.trouble:
		default:
			return
		}
	}
}

// current returns the generation and stall time to watch a new connection
// with, ok false when not watching.
func (w *Watcher) current() (gen int, stall time.Duration, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.gen, w.stall, w.on
}

func (w *Watcher) report(gen int, t Trouble) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.on || gen != w.gen {
		return
	}
	select {
	case w.trouble <- t:
	default:
	}
}

// watches reports whether a connection dialed with ctx is for the watched
// outbound, directly or as the first hop of a chain (dialerProxy, fragment).
func (w *Watcher) watches(ctx context.Context) bool {
	for _, ob := range session.OutboundsFromContext(ctx) {
		if ob.Tag == w.tag {
			return true
		}
	}
	return false
}

// Coverage is how much of a server's trouble the Watcher can see.
type Coverage int

const (
	// Unwatched: its connections can't be followed (XHTTP over HTTP/3,
	// mKCP, WireGuard), so only a check on a timer notices trouble.
	Unwatched Coverage = iota
	// PartlyWatched: QUIC (Hysteria). A server that stops answering is
	// seen as soon as the client sends, but during a download the client
	// only acknowledges, so a freeze then goes unseen until it sends again.
	PartlyWatched
	// Watched: TCP, followed record by record.
	Watched
)

// WatchCoverage says how much of s's trouble the Watcher can see. Pools
// aren't watched at all.
func WatchCoverage(s *share.Server) Coverage {
	if s.Pool != nil {
		return Unwatched
	}
	var ob struct {
		Protocol       string `json:"protocol"`
		StreamSettings struct {
			Network     string `json:"network"`
			Security    string `json:"security"`
			TLSSettings struct {
				ALPN []string `json:"alpn"`
			} `json:"tlsSettings"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(s.Outbound, &ob); err != nil {
		return Unwatched
	}
	st := ob.StreamSettings
	switch {
	case ob.Protocol == "hysteria" || st.Network == "hysteria":
		return PartlyWatched
	case ob.Protocol == "wireguard":
		return Unwatched
	}
	switch st.Network {
	case "kcp", "mkcp", "quic":
		return Unwatched
	case "xhttp", "splithttp":
		// Xray's XHTTP speaks HTTP/3 when h3 is the only ALPN, and opens
		// its QUIC connection its own way.
		if st.Security == "tls" && len(st.TLSSettings.ALPN) == 1 && st.TLSSettings.ALPN[0] == "h3" {
			return Unwatched
		}
	}
	return Watched
}

type watchDialer struct {
	base *internet.DefaultSystemDialer
	w    *Watcher
}

func (d *watchDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	gen, stall, on := d.w.current()
	if !on || !d.w.watches(ctx) {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	report := func(t Trouble) { d.w.report(gen, t) }
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
	switch {
	case err != nil:
		if dest.Network == xnet.Network_TCP && ctx.Err() == nil {
			report(Trouble{Kind: "dial", Detail: fmt.Sprintf("can't connect to %s: %s", dest.NetAddr(), shortError(err))})
		}
		return nil, err
	case dest.Network == xnet.Network_TCP:
		return newWatchedConn(conn, stall, report), nil
	}
	// UDP: QUIC transports take only Xray's own wrapper, around the
	// socket itself (see watchedPacketConn).
	if pw, ok := conn.(*internet.PacketConnWrapper); ok {
		if udp, ok := pw.PacketConn.(*net.UDPConn); ok {
			return &internet.PacketConnWrapper{PacketConn: newWatchedPacketConn(udp, stall, report), Dest: pw.Dest}, nil
		}
	}
	return conn, nil
}

func (d *watchDialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

// watchedConn follows the TLS records the server sends.
type watchedConn struct {
	net.Conn
	report func(Trouble)
	stall  time.Duration

	mu sync.Mutex
	// records parses the incoming stream; nil once it isn't TLS.
	records *recordReader
	// got counts bytes received, to say where a connection stopped.
	got int64
	// hello: a TLS handshake was sent and awaits the server's answer.
	hello bool
	wrote bool
	// tls: the connection began with a TLS handshake. requested is when
	// the client first wrote after the server's answer to it (finishing
	// the handshake, then its request), and gotThen what had come by then.
	tls       bool
	requested time.Time
	gotThen   int64
	timer     *time.Timer
	closed    bool
}

// rejectBytes is the most a server sends after the handshake and still
// counts as turning the client away: session tickets and a close_notify,
// not an answer.
const rejectBytes = 1024

func newWatchedConn(c net.Conn, stall time.Duration, report func(Trouble)) *watchedConn {
	return &watchedConn{Conn: c, report: report, stall: stall, records: &recordReader{}}
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return n, err
	}
	c.got += int64(n)
	if c.records != nil && !c.records.feed(p[:n]) {
		c.records = nil
	}
	mid := c.records != nil && c.records.mid()
	if n > 0 {
		c.hello = false
	}
	switch {
	case err == nil:
		if mid {
			c.armLocked()
		} else if c.timer != nil && !c.hello {
			c.timer.Stop()
		}
	case errors.Is(err, net.ErrClosed):
	case errors.Is(err, io.EOF):
		switch {
		case mid:
			c.troubleLocked("cut", fmt.Sprintf("the server closed a connection mid-transfer after %s", kb(c.got)))
		case c.rejectedLocked():
			c.troubleLocked("cut", "the server closed a connection right after the handshake (account rejected?)")
		}
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, syscall.EPIPE):
		c.troubleLocked("cut", fmt.Sprintf("a connection was cut after %s: %s", kb(c.got), shortError(err)))
	}
	return n, err
}

// rejectedLocked reports whether the server, closing the connection now,
// is turning the client away: the TLS handshake got an answer, and then
// the server hung up before sending back anything more than bookkeeping,
// promptly. Connections that carried data, or idled for a while, end
// normally.
func (c *watchedConn) rejectedLocked() bool {
	switch {
	case !c.tls || c.got == 0:
		return false
	case c.requested.IsZero():
		return true
	}
	return c.got-c.gotThen <= rejectBytes && time.Since(c.requested) < c.stall
}

// armLocked (re)starts the stall timer: data has to keep coming until the
// record is complete.
func (c *watchedConn) armLocked() {
	if c.timer == nil {
		c.timer = time.AfterFunc(c.stall, c.stalled)
		return
	}
	c.timer.Reset(c.stall)
}

// Write notices a TLS handshake starting: a server answers that at once,
// whatever the connection is for.
func (c *watchedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.wrote && len(p) > 0 {
		c.wrote = true
		if len(p) >= 3 && p[0] == 22 && p[1] == 3 && c.got == 0 && !c.closed {
			c.hello, c.tls = true, true
			c.armLocked()
		}
	} else if c.tls && c.got > 0 && c.requested.IsZero() && len(p) > 0 {
		c.requested, c.gotThen = time.Now(), c.got
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *watchedConn) stalled() {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closed:
	case c.hello:
		c.troubleLocked("stall", fmt.Sprintf("the server didn't answer a TLS handshake for %s", c.stall))
	case c.records != nil && c.records.mid():
		c.troubleLocked("stall", fmt.Sprintf("a connection froze mid-transfer after %s (nothing for %s)", kb(c.got), c.stall))
	}
}

// troubleLocked reports once per connection.
func (c *watchedConn) troubleLocked(kind, detail string) {
	c.closedLocked()
	go c.report(Trouble{Kind: kind, Detail: detail})
}

func (c *watchedConn) closedLocked() {
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
}

func (c *watchedConn) Close() error {
	c.mu.Lock()
	c.closedLocked()
	c.mu.Unlock()
	return c.Conn.Close()
}

// recordReader follows TLS record boundaries in a byte stream.
type recordReader struct {
	header [5]byte
	// have counts header bytes read; once 5, left is what the record
	// still needs.
	have int
	left int
}

// maxRecord allows TLS 1.2's ciphertext expansion (2^14 + 2048).
const maxRecord = 1<<14 + 2048

// feed consumes b, returning false if it isn't a stream of TLS records.
func (r *recordReader) feed(b []byte) bool {
	for len(b) > 0 {
		if r.have < len(r.header) {
			k := copy(r.header[r.have:], b)
			r.have += k
			b = b[k:]
			if r.have < len(r.header) {
				return true
			}
			h := r.header
			if h[0] < 20 || h[0] > 24 || h[1] != 3 || h[2] > 4 {
				return false
			}
			r.left = int(h[3])<<8 | int(h[4])
			if r.left > maxRecord {
				return false
			}
		}
		k := min(r.left, len(b))
		r.left -= k
		b = b[k:]
		if r.left == 0 {
			r.have = 0
		}
	}
	return true
}

// mid reports whether a record has started and not finished.
func (r *recordReader) mid() bool { return r.have > 0 }

// shortError drops the address prefix of net errors, which the caller
// already names.
func shortError(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	var sys *os.SyscallError
	if errors.As(err, &sys) {
		err = sys.Err
	}
	return err.Error()
}
