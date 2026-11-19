package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
			plan := fastestPlan{probe: entries, total: len(entries)}
			var progress bytes.Buffer
			best, ok, scanErr := scanFastest(ctx, plan, opts, tc.budget, t.TempDir(), &progress)
			if scanErr != nil {
				t.Fatalf("scan returned %v", scanErr)
			}
			if !ok || best.Entry.Server != tc.want || (best.Speed > 0) != (tc.want == pool) {
				t.Fatalf("picked %+v (found %v), want %s", best, ok, tc.want.Name)
			}
			if tc.pool && !sawSpeed {
				t.Error("scan did not report its speed measurement")
			}
			if tc.blocked && time.Since(start) < tc.budget {
				t.Error("scan returned before the budget")
			}
			if tc.blocked && tc.budget != 0 {
				// The budget cut the sample short of the blocked server:
				// exactly one entry measured, the rest stay unprobed.
				line := progress.String()
				if strings.ContainsAny(line, "\r\x1b") {
					t.Errorf("non-terminal progress contains control codes: %q", line)
				}
				if !strings.Contains(line, fmt.Sprintf("%d/%d probed", len(entries)-1, len(entries))) {
					t.Errorf("progress %q does not show the probe count", line)
				}
				if !strings.Contains(line, fmt.Sprintf("picked the best of 1 measured; use --exhaustive to test all %d", len(entries))) {
					t.Errorf("progress %q does not note the partial sample", line)
				}
				if tc.want == pool && !strings.Contains(line, "best: pool") {
					t.Errorf("progress %q does not show the best server", line)
				}
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

func TestScanFastestFailsFastWhenNothingMeasurable(t *testing.T) {
	// Shrink the grace so the case runs in well under a second.
	floor := fastestFailFloor
	fastestFailFloor = 100 * time.Millisecond
	t.Cleanup(func() { fastestFailFloor = floor })

	budget := 500 * time.Millisecond
	var entered atomic.Int32
	release := make(chan struct{})
	defer close(release)
	// With no endpoint limit the resolver blocks inside each probe, so
	// both entries occupy their slots without ever answering.
	opts := engine.PingOptions{URL: useTestPingURL, DownloadURL: useTestDownloadURL, Timeout: time.Second, Parallel: 2}
	opts.Resolve = func(string) (string, error) {
		entered.Add(1)
		<-release
		return "127.0.0.1", nil
	}
	var entries []config.Entry
	for _, name := range []string{"stuck1", "stuck2"} {
		s, err := share.ParseLink("http://" + name + ".invalid:8080#" + name)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, config.Entry{Index: len(entries) + 1, Server: s})
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plan := fastestPlan{probe: entries, total: len(entries)}
	start := time.Now()
	best, ok, scanErr := scanFastest(ctx, plan, opts, budget, t.TempDir(), nil)
	elapsed := time.Since(start)
	if ok || best.Entry.Server != nil {
		t.Fatalf("picked %+v (found %v) from a dead subscription", best, ok)
	}
	if scanErr == nil || !strings.Contains(scanErr.Error(), "no server measured a download speed") ||
		!strings.Contains(scanErr.Error(), "use --exhaustive to keep waiting") {
		t.Fatalf("scan error = %v, want a fail-fast message", scanErr)
	}
	// Both probes were really attempted, and none finished.
	if !strings.Contains(scanErr.Error(), "(0 of 2 probed)") {
		t.Errorf("scan error = %v, want the probe count", scanErr)
	}
	if entered.Load() != 2 {
		t.Errorf("%d probes entered their resolver, want 2", entered.Load())
	}
	// The grace gave the probes their chance: budget, then give up.
	if elapsed < budget {
		t.Errorf("gave up after %s, before the budget", elapsed)
	}
	if wait := budget + fastestFailFloor; elapsed > wait+2*time.Second {
		t.Errorf("waited %s, past the grace of %s", elapsed, wait)
	}
}

func TestPlanFastestOrdersProbesByCachedSpeed(t *testing.T) {
	now := time.Now()
	entry := func(name string, index int) config.Entry {
		return config.Entry{Index: index, Group: "g", Server: &share.Server{
			Name: name, Outbound: json.RawMessage(fmt.Sprintf(`{"tag":%q}`, name)),
		}}
	}
	record := func(e config.Entry, speed float64, age time.Duration, fingerprint string) (string, pingCacheRecord) {
		return pingKey(e.Group, e.Server.Name), pingCacheRecord{
			Server: fingerprint, Speed: speed, Latency: time.Second, At: now.Add(-age),
		}
	}
	slow, quick, unknown, fresh, replaced, ancient :=
		entry("slow", 1), entry("quick", 2), entry("unknown", 3), entry("fresh", 4), entry("replaced", 5), entry("ancient", 6)
	entries := []config.Entry{slow, quick, unknown, fresh, replaced, ancient}
	cache := pingCache{Records: map[string]pingCacheRecord{}}
	add := func(e config.Entry, speed float64, age time.Duration, fingerprint string) {
		k, r := record(e, speed, age, fingerprint)
		cache.Records[k] = r
	}
	add(slow, 3, 10*time.Minute, serverFingerprint(slow.Server))
	add(quick, 9, 10*time.Minute, serverFingerprint(quick.Server))
	add(fresh, 5e6, time.Minute, serverFingerprint(fresh.Server))
	// A record keyed for a server that no longer exists, one too old to
	// order by, and one for a name never seen: all unknown.
	add(replaced, 99, 10*time.Minute, "another server")
	add(ancient, 99, 25*time.Hour, serverFingerprint(ancient.Server))

	plan := planFastest(entries, cache, now)
	if len(plan.seed) != 1 || plan.seed[0].Entry.Server != fresh.Server || plan.seed[0].Speed != 5e6 {
		t.Fatalf("seed = %+v, want only the fresh record for fresh", plan.seed)
	}
	if plan.total != len(entries) {
		t.Errorf("total = %d, want %d", plan.total, len(entries))
	}
	want := []config.Entry{quick, slow, unknown, replaced, ancient}
	for i := range want {
		if plan.probe[i].Server != want[i].Server {
			t.Fatalf("probe order = %v, want %v first", serverNames(plan.probe), serverNames(want))
		}
	}
}

func TestPlanFastestProbesAReplacedDuplicate(t *testing.T) {
	now := time.Now()
	first := config.Entry{Index: 1, Group: "g", Server: &share.Server{
		Name: "same", Outbound: json.RawMessage(`{"tag":"first"}`),
	}}
	second := config.Entry{Index: 2, Group: "g", Server: &share.Server{
		Name: "same", Outbound: json.RawMessage(`{"tag":"second"}`),
	}}
	if serverFingerprint(first.Server) == serverFingerprint(second.Server) {
		t.Fatal("different servers under one name share a fingerprint")
	}
	// The first server was measured a moment ago, but the name now resolves
	// to a different server, so its record says nothing about the successor.
	rec := cacheRecord(engine.PingResult{Entry: first, Latency: time.Second, Speed: 1e6}, now)
	cache := pingCache{Records: map[string]pingCacheRecord{
		pingKey(first.Group, first.Server.Name): rec,
	}}
	plan := planFastest([]config.Entry{first, second}, cache, now)
	if len(plan.seed) != 1 || plan.seed[0].Entry.Server != first.Server {
		t.Fatalf("seed = %+v, want only the measured first server", plan.seed)
	}
	if len(plan.probe) != 1 || plan.probe[0].Server != second.Server {
		t.Fatalf("probe = %v, want the replaced duplicate", serverNames(plan.probe))
	}
}

func serverNames(entries []config.Entry) []string {
	names := make([]string, len(entries))
	for i, en := range entries {
		names[i] = en.Server.Name
	}
	return names
}

func TestUseFastestPicksFromFreshCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	yaml := "bind_interface: none\nresolve_locally: false\nping:\n  url: " + useTestPingURL + "\n  download_url: " + useTestDownloadURL + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	// If the cache is wrongly ignored, these handlers see traffic.
	var probed sync.Map
	count := func(name string) http.HandlerFunc {
		return func(http.ResponseWriter, *http.Request) {
			v, _ := probed.LoadOrStore(name, new(int32))
			atomic.AddInt32(v.(*int32), 1)
		}
	}
	slow := useTestServer(t, "slow", count("slow"))
	fast := useTestServer(t, "fast", count("fast"))
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Manual = []*share.Server{slow, fast}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	records := map[string]pingCacheRecord{
		pingKey(config.ManualGroup, "slow"): {Server: serverFingerprint(slow), Speed: 1e6, Latency: 100 * time.Millisecond, At: time.Now()},
		pingKey(config.ManualGroup, "fast"): {Server: serverFingerprint(fast), Speed: 1e7, Latency: 50 * time.Millisecond, At: time.Now()},
	}
	savePingCache(dir, records)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := newRootCmd([]string{"use", "--fastest"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	stderr, restore := swapStderr(t)
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.ExecuteContext(ctx) }()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command did not return without probing")
	}
	restore()
	for _, name := range []string{"slow", "fast"} {
		if v, ok := probed.Load(name); ok {
			t.Errorf("reprobed %s from a fresh cache (%d requests)", name, atomic.LoadInt32(v.(*int32)))
		}
	}
	if !strings.Contains(out.String(), "fastest: #2 manual/fast") {
		t.Fatalf("output %q does not report the cached winner", out.String())
	}
	if !strings.Contains(stderr.String(), "picked from a recent scan") {
		t.Fatalf("stderr %q does not note the cached pick", stderr.String())
	}
	st, err = config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Selection{Group: config.ManualGroup, Name: "fast", Auto: true}
	if st.Selected == nil || *st.Selected != want {
		t.Fatalf("saved selection %+v, want %+v", st.Selected, want)
	}
}

func TestUseFastestSeedsFromPartialCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	yaml := "bind_interface: none\nresolve_locally: false\nping:\n  url: " + useTestPingURL + "\n  download_url: " + useTestDownloadURL + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var probed sync.Map
	counting := func(name string, serve http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			v, _ := probed.LoadOrStore(name, new(int32))
			atomic.AddInt32(v.(*int32), 1)
			serve(w, r)
		}
	}
	cached := useTestServer(t, "cached", counting("cached", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	fresh := useTestServer(t, "fresh", counting("fresh", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			_, _ = w.Write([]byte("measured"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Manual = []*share.Server{cached, fresh}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	// Only "cached" has a record, from a moment ago and far faster than
	// anything this run can measure through the local proxy.
	cachedAt := time.Now()
	savePingCache(dir, map[string]pingCacheRecord{
		pingKey(config.ManualGroup, "cached"): {
			Server: serverFingerprint(cached), Speed: 1e9, Latency: 40 * time.Millisecond, At: cachedAt,
		},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := newRootCmd([]string{"use", "--fastest"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	finished := make(chan error, 1)
	go func() { finished <- cmd.ExecuteContext(ctx) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("command did not return")
	}
	if v, ok := probed.Load("cached"); ok && atomic.LoadInt32(v.(*int32)) != 0 {
		t.Error("probed the entry with a fresh cached record")
	}
	if v, ok := probed.Load("fresh"); !ok || atomic.LoadInt32(v.(*int32)) == 0 {
		t.Error("did not probe the entry without a record")
	}
	if !strings.Contains(out.String(), "fastest: #1 manual/cached") {
		t.Fatalf("output %q does not report the cached winner", out.String())
	}
	// The run measured "fresh" and kept the untouched record for "cached".
	cache := loadPingCache(dir)
	rec, ok := cache.Records[pingKey(config.ManualGroup, "fresh")]
	if !ok || rec.Server != serverFingerprint(fresh) || rec.Speed == 0 || rec.At.Before(cachedAt) {
		t.Fatalf("fresh record = %+v, want this run's measurement", rec)
	}
	rec, ok = cache.Records[pingKey(config.ManualGroup, "cached")]
	if !ok || rec.Speed != 1e9 || !rec.At.Equal(cachedAt) {
		t.Fatalf("cached record = %+v, want the untouched original", rec)
	}
	st, err = config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Selection{Group: config.ManualGroup, Name: "cached", Auto: true}
	if st.Selected == nil || *st.Selected != want {
		t.Fatalf("saved selection %+v, want %+v", st.Selected, want)
	}
}

// swapStderr captures os.Stderr until restore() is called; the test must
// restore before reading the buffer.
func swapStderr(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	var buf bytes.Buffer
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(copied)
	}()
	restore := func() {
		os.Stderr = old
		_ = w.Close()
		<-copied
	}
	t.Cleanup(restore)
	return &buf, restore
}

func useTestServer(t *testing.T, name string, serve http.HandlerFunc) *share.Server {
	t.Helper()
	s, err := share.ParseLink("http://" + connectProxy(t, serve) + "#" + name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
