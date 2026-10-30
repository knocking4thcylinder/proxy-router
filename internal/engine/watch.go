package engine

import (
	"context"
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
//   - it can't be opened.
//
// Requests that are simply waiting for an answer (long polls, idle
// keep-alives) sit between records, so they don't count.

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

type watchDialer struct {
	base *internet.DefaultSystemDialer
	w    *Watcher
}

func (d *watchDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	gen, stall, on := d.w.current()
	// UDP transports (QUIC) need their packet connection as it is.
	if !on || dest.Network != xnet.Network_TCP || !d.w.watches(ctx) {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
	if err != nil {
		if ctx.Err() == nil {
			d.w.report(gen, Trouble{Kind: "dial", Detail: fmt.Sprintf("can't connect to %s: %s", dest.NetAddr(), shortError(err))})
		}
		return nil, err
	}
	return newWatchedConn(conn, stall, func(t Trouble) { d.w.report(gen, t) }), nil
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
	hello  bool
	wrote  bool
	timer  *time.Timer
	closed bool
}

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
		if mid {
			c.troubleLocked("cut", fmt.Sprintf("the server closed a connection mid-transfer after %s", kb(c.got)))
		}
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, syscall.EPIPE):
		c.troubleLocked("cut", fmt.Sprintf("a connection was cut after %s: %s", kb(c.got), shortError(err)))
	}
	return n, err
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
			c.hello = true
			c.armLocked()
		}
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
