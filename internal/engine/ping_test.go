package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// A blocked proxy proves that progress is delivered before the batch returns.
// A mixed pool also must not count as finished until all its members finish.
func TestPingProgressStreamsAndAggregatesPools(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	proxy := func(name string, blocked, fail bool) *share.Server {
		t.Helper()
		addr := connectProxy(t, func(w http.ResponseWriter, r *http.Request) {
			if blocked {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			if fail {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == "/country" {
				fmt.Fprintln(w, "FI")
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})
		s, err := share.ParseLink("http://" + addr + "#" + name)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	fast := proxy("fast", false, false)
	slow := proxy("slow", true, false)
	dead := proxy("dead", false, true)
	pool := &share.Server{Name: "pool", Pool: &share.Pool{Members: []json.RawMessage{slow.Outbound, dead.Outbound}}}
	entries := []config.Entry{{Index: 1, Server: fast}, {Index: 2, Server: pool}}
	updates := make(chan PingProgress, 3)
	finished := make(chan []PingResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		finished <- Ping(ctx, entries, PingOptions{
			URL: "http://probe.invalid/ping", ExitURL: "http://probe.invalid/country",
			Timeout: 3 * time.Second, Parallel: 3,
			OnProgress: func(p PingProgress) { updates <- p },
		})
	}()
	var progress []PingProgress
	for len(progress) < 2 {
		select {
		case p := <-updates:
			progress = append(progress, p)
		case <-ctx.Done():
			t.Fatal("no progress while a pool member was blocked")
		}
	}
	select {
	case <-finished:
		t.Fatal("batch finished before the slow proxy was released")
	default:
	}
	for _, p := range progress {
		if p.Result.Entry.Index == 1 && (!p.EntryDone || p.Result.Exit != "FI" || p.Result.Err != nil) {
			t.Fatalf("bad completed single-server result: %+v", p)
		}
		if p.Result.Entry.Index == 2 && p.EntryDone {
			t.Fatal("pool was marked finished with a pending member")
		}
	}
	close(release)
	select {
	case results := <-finished:
		progress = append(progress, <-updates)
		for i, p := range progress {
			if p.Completed != i+1 || p.Total != 3 {
				t.Fatalf("bad probe counters: %+v", p)
			}
		}
		last := progress[2]
		if !last.EntryDone || last.Result.Entry.Index != 2 || last.Result.Alive != 1 || last.Result.Members != 2 || last.Result.Exit != "FI" || last.Result.Err != nil {
			t.Fatalf("bad final pool progress: %+v", last)
		}
		if len(results) != 2 || results[0].Entry.Index != 1 || results[1].Entry.Index != 2 {
			t.Fatalf("results lost entry order: %+v", results)
		}
		if results[1].Latency != last.Result.Latency || results[1].Alive != 1 {
			t.Fatalf("progress differs from final pool result: %+v", results[1])
		}
	case <-ctx.Done():
		t.Fatal("batch did not finish after releasing the slow proxy")
	}
}

// connectProxy starts an HTTP proxy that answers every request tunnelled
// through it with serve, whatever the destination, and returns its
// host:port. (Xray's http outbound always tunnels with CONNECT.)
func connectProxy(t *testing.T, serve http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		req, err := http.ReadRequest(rw.Reader)
		if err != nil {
			return
		}
		rec := httptest.NewRecorder()
		serve(rec, req.WithContext(r.Context()))
		_ = rec.Result().Write(conn)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestControlSocketsCoversPing: every socket a ping opens, TCP or UDP, goes
// through ControlSockets, which is how ping gets around the TUN. It runs
// in a child process: the control can't be removed again.
func TestControlSocketsCoversPing(t *testing.T) {
	if os.Getenv("PROXY_ROUTER_CONTROL_CHILD") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestControlSocketsCoversPing$", "-test.v")
		cmd.Env = append(os.Environ(), "PROXY_ROUTER_CONTROL_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "--- PASS") {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	var mu sync.Mutex
	seen := map[string]int{}
	if err := ControlSockets(func(network, _ string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		seen[network[:3]]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	tcp, err := share.ParseLink("http://" + connectProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}) + "#tcp")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t, true)
	startServer(t, map[string]any{"protocol": "vless", "port": port,
		"settings":       map[string]any{"clients": []any{map[string]any{"id": testUUID}}, "decryption": "none"},
		"streamSettings": map[string]any{"network": "kcp", "kcpSettings": map[string]any{}}})
	udp, err := share.ParseLink(fmt.Sprintf("vless://%s@127.0.0.1:%d?type=kcp&headerType=none#udp", testUUID, port))
	if err != nil {
		t.Fatal(err)
	}
	results := Ping(context.Background(), []config.Entry{{Index: 1, Server: tcp}, {Index: 2, Server: udp}},
		PingOptions{URL: target.URL, Timeout: 5 * time.Second, Parallel: 2})
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s: %v", r.Entry.Server.Name, r.Err)
		}
	}
	if seen["tcp"] == 0 || seen["udp"] == 0 {
		t.Errorf("controlled sockets: %v; want both TCP and UDP", seen)
	}
}
