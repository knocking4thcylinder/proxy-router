package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

const useTestPingURL = "http://probe.invalid/ping"
const useTestDownloadURL = "http://probe.invalid/download"

func TestScanFastest(t *testing.T) {
	single := useTestServer(t, "single", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	member := useTestServer(t, "member", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			_, _ = w.Write([]byte("measured"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	pool := &share.Server{Name: "pool", Pool: &share.Pool{Members: []json.RawMessage{member.Outbound}}}
	blocked, err := share.ParseLink("http://blocked.invalid:8080#blocked")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		budget      time.Duration
		blocked     bool
		pool        bool
		downloadURL string
		want        *share.Server
	}{
		{"measured at budget", 500 * time.Millisecond, true, true, useTestDownloadURL, pool},
		{"first speed after budget", time.Nanosecond, true, true, useTestDownloadURL, pool},
		{"latency after budget", time.Nanosecond, true, false, "", single},
		{"all tests finish", time.Hour, false, true, useTestDownloadURL, pool},
		{"no speed measured", time.Hour, false, false, useTestDownloadURL, single},
		{"exhaustive preserves pool preference", 0, false, true, useTestDownloadURL, single},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			opts := engine.PingOptions{URL: useTestPingURL, DownloadURL: tc.downloadURL, Timeout: time.Second, Parallel: 2}
			var entries []config.Entry
			if tc.blocked {
				// No endpoint limit makes the resolver block inside a probe.
				// Keep that probe stuck until the selection has returned.
				lookupStarted, releaseLookup := make(chan struct{}), make(chan struct{})
				defer close(releaseLookup)
				opts.Resolve = func(string) (string, error) {
					close(lookupStarted)
					<-releaseLookup
					return "127.0.0.1", nil
				}
				entries = append(entries, config.Entry{Index: 1, Server: blocked})
				defer func() {
					select {
					case <-lookupStarted:
					default:
						t.Error("blocked probe never entered its resolver")
					}
				}()
			}
			entries = append(entries, config.Entry{Index: 2, Server: single})
			if tc.pool {
				entries = append(entries, config.Entry{Index: 3, Server: pool})
			}
			var sawSpeed bool
			opts.OnProgress = func(p engine.PingProgress) {
				sawSpeed = sawSpeed || p.Phase == engine.PhaseSpeed && p.Result.Speed > 0
			}
			start := time.Now()
			best, ok := scanFastest(ctx, entries, opts, tc.budget)
			if !ok || best.Entry.Server != tc.want || (best.Speed > 0) != (tc.want == pool) {
				t.Fatalf("picked %+v (found %v), want %s", best, ok, tc.want.Name)
			}
			if tc.pool && !sawSpeed {
				t.Error("scan did not report its speed measurement")
			}
			if tc.blocked && time.Since(start) < tc.budget {
				t.Error("scan returned before the budget")
			}
		})
	}
}

func TestUseFastestPersistsAgainstCurrentState(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		exhaustive   bool
	}{
		{"quick canceled", "cancel", false},
		{"exhaustive canceled", "cancel", true},
		{"reordered", "reorder", false},
		{"replaced", "replace", true},
		{"removed", "remove", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"use", "--fastest", "--group", "VPN"}
			if tc.exhaustive {
				args = append(args, "--exhaustive")
			}
			dir := t.TempDir()
			t.Setenv("PROXY_ROUTER_HOME", dir)
			yaml := "bind_interface: none\nresolve_locally: false\nping:\n  url: " + useTestPingURL + "\n  download_url: " + useTestDownloadURL + "\n"
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			started, release := make(chan struct{}), make(chan struct{})
			finishDownload := sync.OnceFunc(func() { close(release) })
			defer finishDownload()
			candidate := useTestServer(t, "candidate", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/download" {
					close(started)
					<-release
					_, _ = w.Write([]byte("measured"))
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
			st, err := config.LoadState(dir)
			if err != nil {
				t.Fatal(err)
			}
			st.Manual = []*share.Server{{Name: "original"}}
			st.Subscriptions = []*config.Subscription{{Name: "VPN", Servers: []*share.Server{candidate}}}
			want := config.Selection{Group: config.ManualGroup, Name: "original"}
			st.Selected = &want
			if err := st.Save(); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := newRootCmd(args)
			var out bytes.Buffer
			cmd.SetOut(&out)
			finished := make(chan error, 1)
			go func() { finished <- cmd.ExecuteContext(ctx) }()
			select {
			case <-started:
			case err := <-finished:
				t.Fatalf("command returned before probing: %v", err)
			case <-ctx.Done():
				t.Fatal("download probe did not start")
			}
			var wantErr string
			switch tc.action {
			case "cancel":
				cancel()
			case "reorder":
				st.Subscriptions = append([]*config.Subscription{{Name: "New", Servers: []*share.Server{{Name: "added"}}}}, st.Subscriptions...)
				st.Subscriptions[1].UserAgent = "new agent"
				want = config.Selection{Group: "VPN", Name: "candidate", Auto: true, AutoGroup: "VPN"}
			case "replace":
				replacement, err := share.ParseLink("http://127.0.0.1:1#candidate")
				if err != nil {
					t.Fatal(err)
				}
				st.Subscriptions[0].Servers[0] = replacement
				wantErr = "changed during the scan"
			case "remove":
				st.Subscriptions[0].Servers = nil
				wantErr = "was removed during the scan"
			}
			if tc.action != "cancel" {
				st.Selected = &config.Selection{Group: config.ManualGroup, Name: "original"}
				if err := st.Save(); err != nil {
					t.Fatal(err)
				}
				finishDownload()
			}
			select {
			case err = <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("command did not return")
			}
			switch {
			case tc.action == "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("command returned %v, want context.Canceled", err)
				}
			case wantErr != "":
				if err == nil || !strings.Contains(err.Error(), wantErr) {
					t.Fatalf("command returned %v, want %q", err, wantErr)
				}
			case err != nil:
				t.Fatal(err)
			}
			st, err = config.LoadState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if st.Selected == nil || *st.Selected != want {
				t.Fatalf("saved selection %+v, want %+v", st.Selected, want)
			}
			if tc.action == "reorder" {
				if st.Subscription("New") == nil || st.Subscription("VPN").UserAgent != "new agent" {
					t.Fatal("selection overwrote subscription changes")
				}
				if !strings.Contains(out.String(), "fastest: #2 VPN/candidate") {
					t.Fatalf("selection did not report the current index: %s", &out)
				}
			}
		})
	}
}

func useTestServer(t *testing.T, name string, serve http.HandlerFunc) *share.Server {
	t.Helper()
	s, err := share.ParseLink("http://" + connectProxy(t, serve) + "#" + name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
