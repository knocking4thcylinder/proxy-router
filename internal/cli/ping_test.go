package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestPingDownloadParallelConfig(t *testing.T) {
	for _, tc := range []struct {
		name, setting string
		want          int
	}{
		{"legacy", "", 4},
		{"configured", "  download_parallel: 7\n", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			yaml := "bind_interface: none\nresolve_locally: false\nping:\n  per_endpoint: 2\n" + tc.setting
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			opts, _ := (&env{cfg: cfg}).pingOptions(16)
			if opts.DownloadParallel != tc.want {
				t.Errorf("DownloadParallel = %d, want %d", opts.DownloadParallel, tc.want)
			}
		})
	}
}

func TestPingPrintsResultsWhileOtherProbesArePending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	entries := make([]config.Entry, 2)
	for i, name := range []string{"fast", "slow"} {
		addr := connectProxy(t, func(w http.ResponseWriter, r *http.Request) {
			if name == "slow" {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		})
		s, err := share.ParseLink("http://" + addr + "#" + name)
		if err != nil {
			t.Fatal(err)
		}
		entries[i] = config.Entry{Index: i + 1, Server: s}
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	lines := make(chan string, 20)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer writer.Close()
		pingWithProgress(ctx, entries, engine.PingOptions{
			URL: "http://probe.invalid/ping", Timeout: 3 * time.Second, Parallel: 2,
		}, writer, false)
	}()
	var output []string
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("progress stream ended before the fast result: %v", output)
			}
			output = append(output, line)
			if strings.Contains(line, "[1/2] OK") && strings.Contains(line, "#1 fast") {
				goto streamed
			}
		case <-ctx.Done():
			t.Fatalf("fast result was not printed while slow probe was pending: %v", output)
		}
	}

streamed:
	select {
	case <-finished:
		t.Fatal("batch finished with a blocked probe")
	default:
	}
	close(release)
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("progress runner did not return")
	}
	for line := range lines {
		output = append(output, line)
	}
	text := strings.Join(output, "\n")
	if !strings.HasPrefix(text, "Testing 2 servers") || !strings.Contains(text, "[2/2] OK") || !strings.Contains(text, "2 reachable, 0 failed") {
		t.Fatalf("missing progress or summary: %s", text)
	}
	if strings.ContainsAny(text, "\r\x1b") {
		t.Fatalf("non-terminal output contains control codes: %q", text)
	}
}

func TestPingResultsAreReadableAndSorted(t *testing.T) {
	entry := func(index int, name string) config.Entry {
		return config.Entry{Index: index, Group: "ALL VPN", Server: &share.Server{Name: name}}
	}
	results := []engine.PingResult{
		{Entry: entry(4, "failed"), Err: errors.New("Client.Timeout exceeded")},
		{Entry: entry(3, "unknown"), Latency: time.Second, Exit: "?"},
		{Entry: entry(2, "🇫🇮 Авто"), Latency: 180 * time.Millisecond, Alive: 4, Members: 5, Exit: "FI"},
		{Entry: entry(1, "🇩🇪 Германия"), Latency: 176 * time.Millisecond, Exit: "DE"},
	}
	var out bytes.Buffer
	if err := writePingResults(&out, results, 2, true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"fastest first; * selected", "EXIT COUNTRY", "Germany (DE)", "Finland (FI)", "unknown (lookup failed)", "failed: timeout", "POOL", "4/5 alive", "fastest responding member"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if !(strings.Index(text, "Германия") < strings.Index(text, "Авто") && strings.Index(text, "Авто") < strings.Index(text, "unknown") && strings.Index(text, "unknown") < strings.Index(text, "failed: timeout")) {
		t.Errorf("results are not sorted: %s", text)
	}
	if !strings.Contains(text, "*  2") {
		t.Errorf("selected server was not marked: %s", text)
	}
	out.Reset()
	if err := writePingResults(&out, results[:1], 0, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "EXIT COUNTRY") || strings.Contains(out.String(), "POOL") {
		t.Errorf("unneeded columns: %s", out.String())
	}
}

func TestPingResultsShowSpeedFailuresWithoutMarkingServersDead(t *testing.T) {
	entry := func(index int, name string) config.Entry {
		return config.Entry{Index: index, Group: "ALL VPN", Server: &share.Server{Name: name}}
	}
	results := []engine.PingResult{
		{Entry: entry(1, "stalled"), Latency: 50 * time.Millisecond, SpeedErr: engine.ErrStalled},
		{Entry: entry(2, "slow"), Latency: 80 * time.Millisecond, SpeedErr: fmt.Errorf("download %w: 3 KB in 15s", engine.ErrTooSlow)},
		{Entry: entry(3, "measured"), Latency: 300 * time.Millisecond, Speed: 1e6},
		{Entry: entry(4, "unmeasured"), Latency: 20 * time.Millisecond},
	}
	var out bytes.Buffer
	if err := writePingResults(&out, results, 0, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"SPEED", "stalled", "too slow", "8.0 Mbit/s", "A failed speed test doesn't mean the server is down"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "failed: stalled") || strings.Contains(text, "failed: too slow") {
		t.Errorf("speed failures look like dead servers: %s", text)
	}
	order := []string{"measured", "unmeasured", "stalled", "slow"}
	last := -1
	for _, name := range order {
		i := strings.Index(text, name)
		if i <= last {
			t.Fatalf("%s out of order in:\n%s", name, text)
		}
		last = i
	}
}

func TestPingTerminalProgressStaysOnOneLine(t *testing.T) {
	var out bytes.Buffer
	p := pingDisplay{out: &out, total: 110, width: 40, start: time.Now()}
	p.draw()
	p.update(engine.PingProgress{
		Result:    engine.PingResult{Entry: config.Entry{Index: 8, Server: &share.Server{Name: "fast\nserver"}}, Latency: 176 * time.Millisecond},
		Completed: 1, Total: 118, EntryDone: true,
	})
	parts := strings.Split(out.String(), "\r\x1b[2K")
	status := parts[len(parts)-1]
	if len(status) >= p.width || strings.Contains(status, "\n") || !strings.Contains(status, "1/110 servers") {
		t.Fatalf("status wraps or loses progress: %q", status)
	}
	if !strings.Contains(out.String(), "#8 fast server | 176ms") {
		t.Fatalf("result was not printed on a single line: %q", out.String())
	}
}

func TestPingTerminalProgressShowsOverlappingLatencyAndSpeeds(t *testing.T) {
	var out bytes.Buffer
	entry := func(index int, name string) config.Entry {
		return config.Entry{Index: index, Server: &share.Server{Name: name}}
	}
	first := engine.PingResult{Entry: entry(1, "first"), Latency: 20 * time.Millisecond}
	p := pingDisplay{out: &out, total: 4, width: 120, start: time.Now()}
	p.update(engine.PingProgress{Result: first, Completed: 3, Total: 10, SpeedTotal: 1, EntryDone: true})
	if status := pingStatus(out.String()); !strings.Contains(status, "speeds 0/1") {
		t.Fatalf("first eligible download missing from progress: %q", status)
	}
	first.Speed = 1e6
	p.update(engine.PingProgress{Result: first, Completed: 1, Total: 2, SpeedTotal: 2, Phase: engine.PhaseSpeed})
	status := pingStatus(out.String())
	for _, want := range []string{"1/4 servers", "probes 3/10", "speeds 1/2"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status %q is missing %q", status, want)
		}
	}

	// The speed total only covers reachable servers found so far, so it
	// grows while latency probes are still running.
	p.update(engine.PingProgress{Result: first, Completed: 2, Total: 4, SpeedTotal: 4, Phase: engine.PhaseSpeed})
	status = pingStatus(out.String())
	for _, want := range []string{"probes 3/10", "speeds 2/4"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status %q is missing %q after the speed total grew", status, want)
		}
	}

	// Once every latency probe has finished, its counter leaves the line.
	second := engine.PingResult{Entry: entry(2, "second"), Latency: 30 * time.Millisecond}
	p.update(engine.PingProgress{Result: second, Completed: 10, Total: 10, SpeedTotal: 4, EntryDone: true})
	status = pingStatus(out.String())
	if strings.Contains(status, "probes") || !strings.Contains(status, "speeds 2/4") {
		t.Fatalf("finished latency probes still shown, or speeds lost: %q", status)
	}
}

func TestPingTerminalProgressKeepsBothCountsWhenNarrow(t *testing.T) {
	var out bytes.Buffer
	entry := config.Entry{Index: 1, Server: &share.Server{Name: "one"}}
	p := pingDisplay{out: &out, total: 110, width: 40, start: time.Now()}
	p.update(engine.PingProgress{
		Result:    engine.PingResult{Entry: entry, Latency: 20 * time.Millisecond},
		Completed: 1, Total: 118, EntryDone: true,
	})
	p.update(engine.PingProgress{
		Result:    engine.PingResult{Entry: entry, Latency: 20 * time.Millisecond, Speed: 1e6},
		Completed: 1, Total: 2, SpeedTotal: 2, Phase: engine.PhaseSpeed,
	})
	status := pingStatus(out.String())
	if len(status) >= p.width || strings.Contains(status, "\n") {
		t.Fatalf("status wraps: %q", status)
	}
	for _, want := range []string{"1/110", "probes 1/118", "speeds 1/2"} {
		if !strings.Contains(status, want) {
			t.Fatalf("narrow status %q is missing %q", status, want)
		}
	}
}

func pingStatus(out string) string {
	parts := strings.Split(out, "\r\x1b[2K")
	return parts[len(parts)-1]
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

// The speed test is opt-in: the default runs the latency request only,
// --speed adds the download. A server on a closed loopback port answers
// the request phase instantly by failing, and the header line says which
// phases the run had.
func TestPingSpeedFlag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	dead, err := share.ParseLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:1?type=tcp&security=none#dead")
	if err != nil {
		t.Fatal(err)
	}
	st.Subscriptions = []*config.Subscription{{Name: "sub", Servers: []*share.Server{dead}}}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		t.Helper()
		cmd := pingCmd()
		cmd.SetArgs(args)
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return out.String() + errOut.String()
	}

	if got := run(); !strings.Contains(got, "HTTP request through each proxy") || strings.Contains(got, "download") {
		t.Errorf("default ping advertised a download phase:\n%s", got)
	}
	if got := run("--speed"); !strings.Contains(got, "HTTP request and download through each proxy") {
		t.Errorf("--speed lost the download phase:\n%s", got)
	}
}
