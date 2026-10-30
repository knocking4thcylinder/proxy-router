package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// cuttingProxy is an HTTP CONNECT proxy that answers every tunnelled
// request with 204, except /down, a 256 KB download it stops sending after
// cut bytes (0: never), the way a censor cuts a connection after ~16 KB
// and leaves it hanging.
func cuttingProxy(t *testing.T, cut int) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				if req, err := http.ReadRequest(br); err != nil || req.Method != http.MethodConnect {
					return
				}
				fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.URL.Path != "/down" {
					fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\n\r\n")
					return
				}
				const size = 256 << 10
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
				n := size
				if cut > 0 {
					n = cut
				}
				if _, err := conn.Write(make([]byte, n)); err != nil || cut == 0 {
					return
				}
				<-done
			}()
		}
	}()
	return l.Addr().String()
}

func proxyServer(t *testing.T, addr, name string) *share.Server {
	t.Helper()
	s, err := share.ParseLink("http://" + addr + "#" + name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A server that answers the latency request but cuts the download fails;
// one that delivers it reports a speed.
func TestPingFailsServersWhoseDownloadStalls(t *testing.T) {
	good := proxyServer(t, cuttingProxy(t, 0), "good")
	cut := proxyServer(t, cuttingProxy(t, 16<<10), "cut")
	results := Ping(context.Background(), []config.Entry{{Index: 1, Server: good}, {Index: 2, Server: cut}}, PingOptions{
		URL: "http://probe.invalid/ping", DownloadURL: "http://probe.invalid/down",
		Timeout: time.Second, Parallel: 2,
	})
	if r := results[0]; r.Err != nil || r.Speed <= 0 {
		t.Errorf("good server: err %v, speed %v; want a speed", r.Err, r.Speed)
	}
	if r := results[1]; !errors.Is(r.Err, ErrStalled) || !strings.Contains(r.Err.Error(), "after 16 KB") {
		t.Errorf("cut server: err %v; want stalled after 16 KB", r.Err)
	}
}

// Without a download URL, ping is the latency request alone.
func TestPingWithoutDownloadURL(t *testing.T) {
	cut := proxyServer(t, cuttingProxy(t, 16<<10), "cut")
	r := Ping(context.Background(), []config.Entry{{Index: 1, Server: cut}}, PingOptions{
		URL: "http://probe.invalid/ping", Timeout: time.Second, Parallel: 1,
	})[0]
	if r.Err != nil || r.Speed != 0 {
		t.Errorf("err %v, speed %v; want success without a speed", r.Err, r.Speed)
	}
}

// A test site refusing (not 200) isn't the server's fault.
func TestDownloadRefusedIsUnmeasured(t *testing.T) {
	s := proxyServer(t, cuttingProxy(t, 0), "s")
	client, stop, err := ProxyClient(s, PingOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	d, err := Download(context.Background(), client, "http://probe.invalid/other", time.Second, 2*time.Second)
	if err != nil || !d.Unmeasured || d.Speed() != 0 {
		t.Errorf("got %+v, %v; want unmeasured", d, err)
	}
}

// CheckOutbound goes through the given outbound of a running instance,
// whatever its routing says.
func TestCheckOutboundUsesTheTaggedOutbound(t *testing.T) {
	good, cut := cuttingProxy(t, 0), cuttingProxy(t, 16<<10)
	outbound := func(tag, addr string) map[string]any {
		host, port, _ := splitHostPort(addr)
		return map[string]any{"tag": tag, "protocol": "http",
			"settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port}}}}
	}
	inst, err := Start(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		// The first outbound is where routing sends everything.
		"outbounds": []any{outbound("other", good), outbound("proxy", cut)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	_, err = CheckOutbound(context.Background(), inst, "proxy", "http://probe.invalid/down", 500*time.Millisecond, 5*time.Second)
	if !errors.Is(err, ErrStalled) {
		t.Errorf("through proxy: %v; want stalled", err)
	}
	d, err := CheckOutbound(context.Background(), inst, "other", "http://probe.invalid/down", 500*time.Millisecond, 5*time.Second)
	if err != nil || d.Bytes != 256<<10 {
		t.Errorf("through other: %+v, %v; want all 256 KB", d, err)
	}
}

// A download that keeps going, but too slowly, fails as too slow.
func TestDownloadTooSlow(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			for range 1000 {
				if _, err := w.Write([]byte{0}); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(10 * time.Millisecond)
			}
		})}
		_ = srv.Serve(l)
	}()
	_, err = Download(context.Background(), http.DefaultClient, "http://"+l.Addr().String()+"/", time.Second, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "too slow") || errors.Is(err, ErrStalled) {
		t.Errorf("got %v; want too slow", err)
	}
}
