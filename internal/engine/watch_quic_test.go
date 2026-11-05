package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// fakePacketConn hands ReadFrom what the test puts in in.
type fakePacketConn struct {
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{in: make(chan []byte, 64), closed: make(chan struct{})}
}

var fakeAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-f.in:
		return copy(p, b), fakeAddr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}
func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (f *fakePacketConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}
func (f *fakePacketConn) LocalAddr() net.Addr              { return fakeAddr }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// quicPair is a watched fake socket: send writes a packet, answer has the
// server's next packet arrive.
func quicPair(t *testing.T, stall, grace time.Duration) (send func([]byte), answer func(), trouble <-chan Trouble) {
	t.Helper()
	f := newFakePacketConn()
	tr := make(chan Trouble, 4)
	c := newWatchedPacket(f, stall, func(x Trouble) { tr <- x })
	c.q.grace = grace
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := c.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	send = func(b []byte) { c.WriteTo(b, fakeAddr) }
	answer = func() {
		f.in <- []byte{0x41, 1, 2, 3}
		time.Sleep(5 * time.Millisecond) // let the reader take it
	}
	return send, answer, tr
}

var (
	initial = append([]byte{0xc3, 0, 0, 0, 1}, make([]byte, 1200)...)
	short   = []byte{0x47, 9, 9, 9, 9}
)

func TestQUICWatch(t *testing.T) {
	const stall, grace = 150 * time.Millisecond, 50 * time.Millisecond

	t.Run("initial unanswered", func(t *testing.T) {
		send, _, trouble := quicPair(t, stall, grace)
		send(initial)
		expectTrouble(t, trouble, "stall", "didn't answer a QUIC handshake")
	})
	t.Run("sending into silence", func(t *testing.T) {
		send, answer, trouble := quicPair(t, stall, grace)
		send(initial)
		answer()
		send(short) // acknowledging, right away
		time.Sleep(2 * grace)
		// A request, then its retransmissions: nothing comes back.
		for range 3 {
			send(short)
			time.Sleep(stall / 4)
		}
		expectTrouble(t, trouble, "stall", "stopped answering over QUIC")
	})
	t.Run("loss", func(t *testing.T) {
		send, answer, trouble := quicPair(t, stall, grace)
		send(initial)
		answer()
		deadline := time.Now().Add(6 * stall)
		for i := 0; time.Now().Before(deadline); i++ {
			send(short)
			if i%3 != 2 { // every third packet is lost
				answer()
			}
			time.Sleep(stall / 5)
		}
		expectNoTrouble(t, trouble, 2*stall)
	})
	t.Run("idle", func(t *testing.T) {
		send, answer, trouble := quicPair(t, stall, grace)
		send(initial)
		answer()
		send(short) // the last acknowledgment of a download
		expectNoTrouble(t, trouble, 3*stall)
	})
	t.Run("goodbye", func(t *testing.T) {
		send, answer, trouble := quicPair(t, stall, grace)
		send(initial)
		answer()
		time.Sleep(2 * grace)
		send(short) // CONNECTION_CLOSE asks for nothing back
		expectNoTrouble(t, trouble, 3*stall)
	})
	t.Run("not QUIC", func(t *testing.T) {
		send, _, trouble := quicPair(t, stall, grace)
		for range quicUndecided + 1 {
			send([]byte{0x01, 0, 0, 0})
		}
		send(initial)
		send(short)
		time.Sleep(stall / 2)
		send(short)
		expectNoTrouble(t, trouble, 3*stall)
	})
}

func TestQUICInitial(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want bool
	}{
		{initial, true},
		{[]byte{0xd0, 0x6b, 0x33, 0x43, 0xcf}, true}, // v2 Initial
		{[]byte{0xe3, 0, 0, 0, 1}, false},            // v1 Handshake
		{[]byte{0xc3, 0, 0, 0, 2}, false},            // unknown version
		{short, false},
	} {
		if got := quicInitial(c.b); got != c.want {
			t.Errorf("%x: %v, want %v", c.b, got, c.want)
		}
	}
}

func TestWatchCoverage(t *testing.T) {
	for link, want := range map[string]Coverage{
		"vless://" + testUUID + "@1.2.3.4:443?type=tcp&security=tls&sni=a#t":            Watched,
		"vless://" + testUUID + "@1.2.3.4:443?type=xhttp&security=tls&sni=a&alpn=h2#x2": Watched,
		"vless://" + testUUID + "@1.2.3.4:443?type=xhttp&security=tls&sni=a&alpn=h3#x3": Unwatched,
		"vless://" + testUUID + "@1.2.3.4:443?type=kcp&headerType=none#k":               Unwatched,
		"hysteria2://pass@1.2.3.4:443/?sni=a#h":                                         PartlyWatched,
		"hysteria2://pass@1.2.3.4:443/?sni=a&obfs=salamander&obfs-password=x#hs":        PartlyWatched,
	} {
		s, err := share.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		if got := WatchCoverage(s); got != want {
			t.Errorf("%s: %v, want %v", s.Name, got, want)
		}
	}
}

// udpRelay forwards UDP to addr; while silent is set it drops what the
// server sends back, as a censor blocking the server does.
func udpRelay(t *testing.T, addr string, silent *atomic.Bool) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	server, _ := net.ResolveUDPAddr("udp", addr)
	var mu sync.Mutex
	ups := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, client, err := l.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			up := ups[client.String()]
			if up == nil {
				if up, err = net.DialUDP("udp", nil, server); err != nil {
					mu.Unlock()
					continue
				}
				ups[client.String()] = up
				t.Cleanup(func() { up.Close() })
				go func() {
					b := make([]byte, 65536)
					for {
						n, err := up.Read(b)
						if err != nil {
							return
						}
						if !silent.Load() {
							l.WriteTo(b[:n], client)
						}
					}
				}()
			}
			mu.Unlock()
			up.Write(buf[:n])
		}
	}()
	return l.LocalAddr().String()
}

// The Watcher sees a real Hysteria2 server stop answering once the client
// sends again, and stays quiet while it works.
func TestWatcherCatchesASilentHysteriaServer(t *testing.T) {
	cert := newCert(t)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1<<20))
	}))
	defer site.Close()
	port := freePort(t, true)
	startServer(t, map[string]any{"protocol": "hysteria", "port": port,
		"settings": map[string]any{"version": 2, "clients": []any{map[string]any{"auth": "hy2pass"}}},
		"streamSettings": map[string]any{
			"network": "hysteria", "security": "tls", "tlsSettings": cert.tlsSettings("h3"),
			"hysteriaSettings": map[string]any{"version": 2},
		}})
	var silent atomic.Bool
	relay := udpRelay(t, fmt.Sprintf("127.0.0.1:%d", port), &silent)
	s, err := share.ParseLink(fmt.Sprintf("hysteria2://hy2pass@%s/?sni=localhost&pinSHA256=%s#hy2", relay, cert.sha256))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := s.Outbounds("proxy")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := Start(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": obs})
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	w := WatchOutbound("proxy")
	w.Start(time.Second)
	defer w.Stop()
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination("tcp:" + addr)
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}}
	fetch := func() error {
		resp, err := client.Get(site.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	for range 3 {
		if err := fetch(); err != nil {
			t.Fatalf("working server: %v", err)
		}
	}
	time.Sleep(2 * ackGrace) // idle, as between page loads
	expectNoTrouble(t, w.Trouble(), time.Second)

	silent.Store(true)
	if err := fetch(); err == nil {
		t.Fatal("fetched through a silent server")
	}
	expectTrouble(t, w.Trouble(), "stall", "stopped answering over QUIC")
}
