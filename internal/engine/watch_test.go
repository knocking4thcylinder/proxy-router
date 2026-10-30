package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func record(typ byte, body int) []byte {
	return append([]byte{typ, 3, 3, byte(body >> 8), byte(body)}, make([]byte, body)...)
}

// Record boundaries are found however the stream is split up.
func TestRecordReader(t *testing.T) {
	stream := append(append(append(record(22, 90), record(20, 1)...), record(23, 0)...), record(23, 16401)...)
	ends := map[int]bool{95: true, 101: true, 106: true, len(stream): true}
	for _, chunk := range []int{1, 2, 5, 7, 100, len(stream)} {
		var r recordReader
		for i := 0; i < len(stream); i += chunk {
			end := min(i+chunk, len(stream))
			if !r.feed(stream[i:end]) {
				t.Fatalf("chunk %d: rejected at %d", chunk, i)
			}
			if r.mid() == ends[end] {
				t.Errorf("chunk %d: mid %v after %d bytes", chunk, r.mid(), end)
			}
		}
	}
	for _, bad := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\n"),
		{23, 2, 0, 0, 1},       // not TLS 1.x
		{23, 3, 3, 0xff, 0xff}, // too long
	} {
		var r recordReader
		if r.feed(bad) {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// watchPair connects a watched client connection to a server side.
func watchPair(t *testing.T, stall time.Duration) (*watchedConn, *net.TCPConn, <-chan Trouble) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	trouble := make(chan Trouble, 4)
	wc := newWatchedConn(c, stall, func(tr Trouble) { trouble <- tr })
	t.Cleanup(func() { wc.Close(); s.Close() })
	// Read like a proxy does, until the connection ends.
	go func() { _, _ = io.Copy(io.Discard, wc) }()
	return wc, s.(*net.TCPConn), trouble
}

func expectTrouble(t *testing.T, trouble <-chan Trouble, kind, detail string) {
	t.Helper()
	select {
	case tr := <-trouble:
		if tr.Kind != kind || !strings.Contains(tr.Detail, detail) {
			t.Errorf("got %s: %q; want %s: %q", tr.Kind, tr.Detail, kind, detail)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("no trouble; want %s", kind)
	}
}

func expectNoTrouble(t *testing.T, trouble <-chan Trouble, wait time.Duration) {
	t.Helper()
	select {
	case tr := <-trouble:
		t.Errorf("got %s: %q; want none", tr.Kind, tr.Detail)
	case <-time.After(wait):
	}
}

func TestWatchedConn(t *testing.T) {
	const stall = 100 * time.Millisecond

	t.Run("frozen mid-record", func(t *testing.T) {
		_, s, trouble := watchPair(t, stall)
		s.Write(record(23, 100)[:60])
		expectTrouble(t, trouble, "stall", "froze mid-transfer after 0 KB")
	})
	t.Run("slow but moving", func(t *testing.T) {
		_, s, trouble := watchPair(t, stall)
		rec := record(23, 100)
		for i := range rec {
			s.Write(rec[i : i+1])
			time.Sleep(stall / 10)
		}
		expectNoTrouble(t, trouble, 3*stall)
	})
	t.Run("idle between records", func(t *testing.T) {
		wc, s, trouble := watchPair(t, stall)
		wc.Write([]byte{22, 3, 1, 0, 1, 0})
		s.Write(record(22, 50))
		s.Write(record(23, 2000))
		// A request waiting for its answer (a long poll) is fine.
		wc.Write(record(23, 30))
		expectNoTrouble(t, trouble, 3*stall)
	})
	t.Run("handshake unanswered", func(t *testing.T) {
		wc, _, trouble := watchPair(t, stall)
		wc.Write([]byte{22, 3, 1, 0, 1, 0})
		expectTrouble(t, trouble, "stall", "didn't answer a TLS handshake")
	})
	t.Run("not TLS", func(t *testing.T) {
		wc, s, trouble := watchPair(t, stall)
		wc.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		s.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"))
		expectNoTrouble(t, trouble, 3*stall)
	})
	t.Run("closed mid-record", func(t *testing.T) {
		_, s, trouble := watchPair(t, stall)
		s.Write(record(23, 18000)[:17000])
		s.Close()
		expectTrouble(t, trouble, "cut", "closed a connection mid-transfer after 17 KB")
	})
	t.Run("reset", func(t *testing.T) {
		_, s, trouble := watchPair(t, stall)
		s.Write(record(23, 10))
		s.SetLinger(0)
		s.Close()
		expectTrouble(t, trouble, "cut", "was cut after 0 KB")
	})
	t.Run("closed here", func(t *testing.T) {
		wc, s, trouble := watchPair(t, stall)
		s.Write(record(23, 100)[:50])
		time.Sleep(stall / 4)
		wc.Close()
		expectNoTrouble(t, trouble, 3*stall)
	})
}

// freezingRelay forwards TCP to addr, but stops passing the server's data
// on after cut bytes per connection (0: never), leaving the connection
// open, as the censor's "16 KB freeze" does.
func freezingRelay(t *testing.T, addr string, cut *atomic.Int64) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s, err := net.Dial("tcp", addr)
				if err != nil {
					return
				}
				defer s.Close()
				go func() { _, _ = io.Copy(s, c) }()
				limit := cut.Load()
				if limit == 0 {
					_, _ = io.Copy(c, s)
					return
				}
				_, _ = io.CopyN(c, s, limit)
				// Swallow the rest, like a censor dropping packets.
				_, _ = io.Copy(io.Discard, s)
			}()
		}
	}()
	return l.Addr().String()
}

// The Watcher sees a real server, over VLESS+TLS+Vision, freeze after
// 16 KB, and stay quiet while it works, including after Vision starts
// copying the inner TLS directly.
func TestWatcherCatchesAFrozenServer(t *testing.T) {
	cert := newCert(t)
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 256<<10))
	}))
	site.TLS = &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}}
	site.StartTLS()
	defer site.Close()

	port := freePort(t, false)
	startServer(t, map[string]any{"protocol": "vless", "port": port,
		"settings":       map[string]any{"clients": []any{map[string]any{"id": testUUID, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
		"streamSettings": map[string]any{"network": "raw", "security": "tls", "tlsSettings": cert.tlsSettings()}})
	var cut atomic.Int64
	relay := freezingRelay(t, fmt.Sprintf("127.0.0.1:%d", port), &cut)
	host, rport, _ := splitHostPort(relay)
	inst, err := Start(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": rport,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": map[string]any{"network": "raw", "security": "tls", "tlsSettings": map[string]any{
				"serverName": "localhost", "fingerprint": "chrome", "pinnedPeerCertSha256": cert.sha256}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	w := WatchOutbound("proxy")
	w.Start(300 * time.Millisecond)
	defer w.Stop()
	fetch := func() error {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
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
	expectNoTrouble(t, w.Trouble(), time.Second)

	cut.Store(16 << 10)
	if err := fetch(); err == nil {
		t.Fatal("the frozen download finished")
	}
	expectTrouble(t, w.Trouble(), "stall", "froze mid-transfer after 16 KB")

	// Testing servers (ping, use --fastest) isn't the running proxy's
	// traffic.
	s, err := share.ParseLink(fmt.Sprintf("vless://%s@%s?type=tcp&security=tls&sni=localhost&fp=chrome&flow=xtls-rprx-vision&pcs=%s#t",
		testUUID, relay, cert.sha256))
	if err != nil {
		t.Fatal(err)
	}
	client, stop, err := ProxyClient(s, PingOptions{}, site.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if _, err := Download(context.Background(), client, site.URL, 300*time.Millisecond, 3*time.Second); err == nil {
		t.Error("the frozen test download finished")
	}
	stop()
	expectNoTrouble(t, w.Trouble(), time.Second)

	// Stopped, nothing is reported.
	w.Stop()
	_ = fetch()
	expectNoTrouble(t, w.Trouble(), time.Second)
}

// Connections that can't be opened are trouble too.
func TestWatcherReportsUnreachableServer(t *testing.T) {
	port := freePort(t, false) // nothing listens there
	inst, err := Start(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	w := WatchOutbound("proxy")
	w.Start(time.Second)
	defer w.Stop()
	conn, err := core.Dial(context.Background(), inst, xnet.TCPDestination(xnet.DomainAddress("example.com"), 80))
	if err == nil {
		conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		conn.Read(make([]byte, 1))
		conn.Close()
	}
	expectTrouble(t, w.Trouble(), "dial", fmt.Sprintf("can't connect to 127.0.0.1:%d", port))
}
