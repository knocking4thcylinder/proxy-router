package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

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
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if name == "slow" {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		entries[i] = config.Entry{Index: i + 1, Server: &share.Server{Name: name, Outbound: json.RawMessage(fmt.Sprintf(
			`{"protocol":"freedom","settings":{"redirect":%q}}`, strings.TrimPrefix(srv.URL, "http://")))}}
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
