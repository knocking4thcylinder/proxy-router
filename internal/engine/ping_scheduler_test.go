package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestPingSkipsBusyEndpoint(t *testing.T) {
	proxies := newPingTestProxies(t)
	first := proxies.server("127.0.0.1", "first")
	second := proxies.server("127.0.0.1", "second")
	other := proxies.server("::1", "other")
	entries := pingTestEntries(first, second, first, second, other)
	updates, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 2, PerEndpoint: 1}, false)

	// Keep the first IP occupied until the entry at the tail has answered.
	for range 2 {
		req := awaitPingTest(t, proxies.requests, "a probe on each IP")
		if req.server == "other" {
			req.release()
		}
	}
	u := awaitPingTest(t, updates, "progress with the first IP still busy")
	if u.Result.Entry.Index != entries[4].Index || u.Result.Err != nil || !u.EntryDone || u.Phase != PhaseLatency {
		t.Fatalf("first progress = %+v, want the entry behind the same-IP probes", u)
	}
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "remaining latency results"), false)
	if peak := proxies.peaks(); peak.perIP != 1 {
		t.Errorf("peak simultaneous requests per IP = %d, want 1", peak.perIP)
	}
}

func TestPingRetriesHostnameAndSharesEndpointAcrossAliases(t *testing.T) {
	proxies := newPingTestProxies(t)
	a := proxies.hostnameServer("127.0.0.1", "first.invalid", "first")
	b := proxies.hostnameServer("127.0.0.1", "second.invalid", "second")
	other := proxies.server("::1", "other")
	entries := pingTestEntries(a, b, b, a, other)
	calls := make(map[string]int)
	var mu sync.Mutex
	resolve := func(host string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[host]++
		switch {
		case host == b.Address && calls[host] == 1:
			return "", errors.New("temporary lookup failure")
		case (host == a.Address && calls[host] == 1) || (host == b.Address && calls[host] == 2):
			return "127.0.0.1", nil
		default:
			return "", fmt.Errorf("unexpected lookup for %s", host)
		}
	}
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 3, PerEndpoint: 1, Resolve: resolve}, true)
	// Hold one same-IP probe while the independent address uses another slot.
	var releaseOther func()
	for range 2 {
		req := awaitPingTest(t, proxies.requests, "latency requests on two IPs")
		if req.server == "other" {
			releaseOther = req.release
		}
	}
	if releaseOther == nil {
		t.Fatal("both aliases ran concurrently while the independent IP was waiting")
	}
	releaseOther()
	if req := awaitPingTest(t, proxies.requests, "the independent download while the shared IP is held"); req.server != "other" || req.path != "/down" {
		t.Fatalf("request = %s %s, want other /down", req.server, req.path)
	}
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "results through both aliases"), true)
	if peak := proxies.peaks(); peak.perIP != 1 {
		t.Errorf("peak simultaneous requests per IP = %d, want 1", peak.perIP)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[a.Address] != 1 || calls[b.Address] != 2 {
		t.Errorf("resolver calls = %v, want one successful lookup and one retry", calls)
	}
}

func TestPingStreamsSpeedAndWaitsForEachPool(t *testing.T) {
	proxies := newPingTestProxies(t)
	fast := proxies.server("127.0.0.1", "fast")
	slow := proxies.server("127.0.0.1", "slow")
	single := proxies.server("127.0.0.1", "single")
	unrelated := proxies.server("127.0.0.1", "unrelated")
	pool := &share.Server{Name: "pool", Pool: &share.Pool{Members: []json.RawMessage{slow.Outbound, fast.Outbound}}}
	entries := pingTestEntries(pool, single, unrelated)
	updates, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 4}, true)

	latencies := make(map[string]pingTestRequest)
	for range 4 {
		req := awaitPingTest(t, proxies.requests, "initial latency probes")
		if req.path != "/ping" {
			t.Fatalf("unexpected initial request %s %s", req.server, req.path)
		}
		latencies[req.server] = req
	}
	for _, s := range []*share.Server{fast, slow, single, unrelated} {
		if _, ok := latencies[s.Name]; !ok {
			t.Fatalf("missing latency request for %s", s.Name)
		}
	}
	latencies["fast"].release()
	partial := awaitPingTest(t, updates, "partial pool latency progress")
	if partial.Phase != PhaseLatency || partial.EntryDone || partial.Result.Entry.Index != 1 || partial.Result.Alive != 1 || partial.Result.Members != 2 || partial.Result.Err != nil {
		t.Fatalf("partial pool progress = %+v", partial)
	}
	latencies["single"].release()
	singleLatency := awaitPingTest(t, updates, "single latency progress")
	checkPingTestProgress(t, singleLatency, PhaseLatency, 2, 2)
	if singleLatency.SpeedTotal != 1 {
		t.Fatalf("eligible downloads before the first speed result = %d, want 1", singleLatency.SpeedTotal)
	}
	download := awaitPingTest(t, proxies.requests, "single download with the pool and unrelated latency still pending")
	if download.server != "single" || download.path != "/down" {
		t.Fatalf("first download = %s %s, want single /down", download.server, download.path)
	}
	download.release()
	checkPingTestProgress(t, awaitPingTest(t, updates, "single speed progress before releasing unrelated latency"), PhaseSpeed, 2, 1)

	// Keep slow's elapsed request time greater than fast's measured latency.
	slowRequest := latencies["slow"]
	if delay := time.Until(slowRequest.arrived.Add(partial.Result.Latency + time.Millisecond)); delay > 0 {
		<-time.After(delay)
	}
	poolReleased := time.Now()
	slowRequest.release()
	complete := awaitPingTest(t, updates, "final pool latency progress")
	checkPingTestProgress(t, complete, PhaseLatency, 1, 3)
	if complete.SpeedTotal != 2 {
		t.Fatalf("eligible downloads after the pool finished = %d, want 2", complete.SpeedTotal)
	}
	if complete.Result.Alive != 2 || complete.Result.Members != 2 || complete.Result.Latency != partial.Result.Latency {
		t.Fatalf("completed pool progress did not retain its fastest member: %+v", complete)
	}
	download = awaitPingTest(t, proxies.requests, "pool download")
	if download.server != "fast" || download.path != "/down" || download.arrived.Before(poolReleased) {
		t.Fatalf("pool downloaded through %s %s, want fast /down after both members answered", download.server, download.path)
	}
	download.release()
	checkPingTestProgress(t, awaitPingTest(t, updates, "pool speed progress with unrelated latency still pending"), PhaseSpeed, 1, 2)
	latencies["unrelated"].release()
	checkPingTestProgress(t, awaitPingTest(t, updates, "unrelated latency progress"), PhaseLatency, 3, 4)
	download = awaitPingTest(t, proxies.requests, "unrelated download")
	if download.server != "unrelated" || download.path != "/down" {
		t.Fatalf("last download = %s %s, want unrelated /down", download.server, download.path)
	}
	download.release()
	checkPingTestProgress(t, awaitPingTest(t, updates, "unrelated speed progress"), PhaseSpeed, 3, 3)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "final results"), true)
}

func TestPingReservesEndpointSlotForLatency(t *testing.T) {
	proxies := newPingTestProxies(t)
	a1 := proxies.server("127.0.0.1", "a1")
	a2 := proxies.server("127.0.0.1", "a2")
	a3 := proxies.server("127.0.0.1", "a3")
	a4 := proxies.server("127.0.0.1", "a4")
	b1 := proxies.server("::1", "b1")
	b2 := proxies.server("::1", "b2")
	entries := pingTestEntries(a1, a2, a3, a4, b1, b2)
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 4, PerEndpoint: 2}, true)

	initial := make(map[string]pingTestRequest)
	for range 4 {
		req := awaitPingTest(t, proxies.requests, "initial latency requests on both IPs")
		if req.path != "/ping" {
			t.Fatalf("initial request = %s %s, want /ping", req.server, req.path)
		}
		initial[req.server] = req
	}
	for _, name := range []string{"a1", "a2", "b1", "b2"} {
		if _, ok := initial[name]; !ok {
			t.Fatalf("missing initial latency request for %s", name)
		}
	}
	initial["a1"].release()
	expectPingTestRequest(t, proxies, "a1", "/down")
	initial["a2"].release()
	expectPingTestRequest(t, proxies, "a3", "/ping").release()
	// Keep a1's download running. The next freed slot at that IP must
	// go to latency, while the other IP can still start a download.
	expectPingTestRequest(t, proxies, "a4", "/ping")
	initial["b1"].release()
	expectPingTestRequest(t, proxies, "b1", "/down")
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "mixed-phase results"), true)
	if peak := proxies.peaks(); peak.total != 4 || peak.perIP != 2 {
		t.Errorf("peak requests = %d globally, %d per IP, want 4 globally and 2 per IP", peak.total, peak.perIP)
	}
}

func TestPingSerialPrefersReadyLatency(t *testing.T) {
	proxies := newPingTestProxies(t)
	a := proxies.server("127.0.0.1", "a")
	b := proxies.server("::1", "b")
	entries := pingTestEntries(a, b)
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 1, PerEndpoint: 2}, true)

	expectPingTestRequest(t, proxies, "a", "/ping").release()
	expectPingTestRequest(t, proxies, "b", "/ping").release()
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "serial results"), true)
	if peak := proxies.peaks(); peak.total != 1 {
		t.Errorf("peak simultaneous requests = %d, want 1", peak.total)
	}
}

func TestPingDownloadsBeforeSingleSlotEndpointFinishesLatency(t *testing.T) {
	proxies := newPingTestProxies(t)
	a := proxies.server("127.0.0.1", "a")
	b := proxies.server("127.0.0.1", "b")
	entries := pingTestEntries(a, b, b)
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 2, PerEndpoint: 1}, true)

	expectPingTestRequest(t, proxies, "a", "/ping").release()
	expectPingTestRequest(t, proxies, "a", "/down").release()
	expectPingTestRequest(t, proxies, "b", "/ping")
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "single-slot endpoint results"), true)
}

func TestPingSerialDownloadsWhileWaitingForDNS(t *testing.T) {
	proxies := newPingTestProxies(t)
	a := proxies.server("127.0.0.1", "a")
	b := proxies.hostnameServer("127.0.0.1", "pending.invalid", "b")
	entries := pingTestEntries(a, b)
	lookupStarted, releaseLookup := make(chan struct{}), make(chan struct{})
	notifyLookup := sync.OnceFunc(func() { close(lookupStarted) })
	resolve := func(host string) (string, error) {
		if host != b.Address {
			return "", fmt.Errorf("unexpected lookup for %s", host)
		}
		notifyLookup()
		select {
		case <-releaseLookup:
			return "127.0.0.1", nil
		case <-t.Context().Done():
			return "", t.Context().Err()
		}
	}
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 1, PerEndpoint: 1, Resolve: resolve}, true)

	awaitPingTest(t, lookupStarted, "the hostname lookup to start")
	expectPingTestRequest(t, proxies, "a", "/ping").release()
	expectPingTestRequest(t, proxies, "a", "/down").release()
	close(releaseLookup)
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "results after DNS answers"), true)
}

func TestPingSharesConcurrencyLimitsAcrossPhases(t *testing.T) {
	proxies := newPingTestProxies(t)
	a := proxies.server("127.0.0.1", "a")
	b := proxies.server("::1", "b")
	entries := pingTestEntries(a, b, a, b, a, b, a, b)
	_, finished := startTestPing(t, t.Context(), entries, PingOptions{Parallel: 3, PerEndpoint: 2, DownloadParallel: 6}, true)

	// Keep one latency request active and advance the other slots until they
	// are both running downloads. Either phase may take a free slot.
	anchor := awaitPingTest(t, proxies.requests, "first latency request")
	if anchor.path != "/ping" {
		t.Fatalf("first request = %s, want /ping", anchor.path)
	}
	for range 2 {
		for {
			req := awaitPingTest(t, proxies.requests, "latency or speed alongside the held latency request")
			if req.path == "/down" {
				break
			}
			req.release()
		}
	}
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "mixed-phase results"), true)
	if peak := proxies.peaks(); peak.total != 3 || peak.perIP != 2 {
		t.Errorf("peak requests = %d globally, %d per IP, want 3 globally and 2 per IP", peak.total, peak.perIP)
	}
}

func TestPingCapsConcurrentDownloadsAtFour(t *testing.T) {
	checkPingDownloadLimit(t, PingOptions{Parallel: 8}, 4)
}

func TestPingHonorsDownloadParallel(t *testing.T) {
	t.Run("higher", func(t *testing.T) {
		checkPingDownloadLimit(t, PingOptions{Parallel: 8, PerEndpoint: 4, DownloadParallel: 6}, 6)
	})
	t.Run("lower", func(t *testing.T) {
		checkPingDownloadLimit(t, PingOptions{Parallel: 8, PerEndpoint: 4, DownloadParallel: 2}, 2)
	})
}

func checkPingDownloadLimit(t *testing.T, opts PingOptions, want int) {
	t.Helper()
	proxies := newPingTestProxies(t)
	a := proxies.server("127.0.0.1", "a")
	b := proxies.server("::1", "b")
	entries := pingTestEntries(a, b, a, b, a, b, a, b)
	updates, finished := startTestPing(t, t.Context(), entries, opts, true)

	var latencyReleases []func()
	for range entries {
		req := awaitPingTest(t, proxies.requests, "parallel latency probes")
		if req.path != "/ping" {
			t.Fatalf("initial request = %s, want /ping", req.path)
		}
		// Release these together once all eight have reached the proxy.
		latencyReleases = append(latencyReleases, req.release)
	}
	for _, release := range latencyReleases {
		release()
	}
	for range entries {
		if u := awaitPingTest(t, updates, "all latency callbacks"); u.Phase != PhaseLatency || u.Result.Err != nil {
			t.Fatalf("unexpected progress before downloads were released: %+v", u)
		}
	}
	for range want {
		req := awaitPingTest(t, proxies.requests, "concurrent downloads up to the limit")
		if req.path != "/down" {
			t.Fatalf("request = %s, want /down", req.path)
		}
	}
	// All eight downloads are eligible. Give an excess worker a chance to
	// reach a proxy while the earlier downloads are still held.
	select {
	case req := <-proxies.requests:
		t.Fatalf("request %s %s exceeded the download limit of %d", req.server, req.path, want)
	case <-time.After(300 * time.Millisecond):
	}
	close(proxies.releaseAll)
	checkPingTestResults(t, entries, awaitPingTest(t, finished, "all downloads"), true)
	if peak := proxies.peaks(); peak.downloads != want {
		t.Errorf("peak simultaneous downloads = %d, want %d", peak.downloads, want)
	}
}

func TestPingCancelsActiveAndQueuedDownloads(t *testing.T) {
	proxies := newPingTestProxies(t)
	unmeasured := proxyServer(t, connectProxy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "unmeasured")
	active := proxies.server("127.0.0.1", "active")
	queued := proxies.server("127.0.0.1", "queued")
	entries := pingTestEntries(unmeasured, active, queued)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	updates, finished := startTestPing(t, ctx, entries, PingOptions{Parallel: 1, PerEndpoint: 1}, true)
	for _, name := range []string{"active", "queued"} {
		expectPingTestRequest(t, proxies, name, "/ping").release()
	}
	for i := range entries {
		u := awaitPingTest(t, updates, "latency progress")
		checkPingTestProgress(t, u, PhaseLatency, entries[i].Index, i+1)
		if u.SpeedTotal != i+1 {
			t.Fatalf("eligible downloads = %d, want %d", u.SpeedTotal, i+1)
		}
	}
	u := awaitPingTest(t, updates, "unmeasured download progress")
	if u.Phase != PhaseSpeed || u.Result.Entry.Index != 1 || u.Completed != 1 || u.Total != 3 || u.Result.SpeedErr != nil || u.Result.Speed != 0 {
		t.Fatalf("progress = %+v, want a completed unmeasured download", u)
	}
	expectPingTestRequest(t, proxies, "active", "/down")
	cancel()
	for _, i := range []int{2, 3} {
		checkCanceledPingDownload(t, awaitPingTest(t, updates, "canceled download progress"), i, i, 3)
	}
	results := awaitPingTest(t, finished, "Ping to return on cancellation")
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	for i, r := range results {
		if r.Err != nil || r.Latency <= 0 || r.Speed != 0 || (i == 0 && r.SpeedErr != nil) || (i > 0 && !errors.Is(r.SpeedErr, context.Canceled)) {
			t.Errorf("result %d = %+v, want successful latency with the corresponding speed outcome", i+1, r)
		}
	}
	select {
	case req := <-proxies.requests:
		t.Errorf("unexpected request after cancellation: %s %s", req.server, req.path)
	default:
	}
}

func TestPingCancelsDownloadMadeEligibleDuringDrain(t *testing.T) {
	proxies := newPingTestProxies(t)
	entries := pingTestEntries(proxies.server("127.0.0.1", "server"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	updates, finished := startTestPing(t, ctx, entries, PingOptions{
		Parallel: 1, PerEndpoint: 1, ExitURL: "http://probe.invalid/exit",
	}, true)
	expectPingTestRequest(t, proxies, "server", "/ping").release()
	// Cancel the optional exit request. The latency result remains successful.
	expectPingTestRequest(t, proxies, "server", "/exit")
	cancel()
	u := awaitPingTest(t, updates, "latency completion during drain")
	checkPingTestProgress(t, u, PhaseLatency, 1, 1)
	if u.SpeedTotal != 1 {
		t.Fatalf("eligible downloads = %d, want 1", u.SpeedTotal)
	}
	u = awaitPingTest(t, updates, "canceled download progress")
	checkCanceledPingDownload(t, u, 1, 1, 1)
	results := awaitPingTest(t, finished, "Ping to return on cancellation")
	if len(results) != 1 || results[0] != u.Result {
		t.Errorf("results = %+v, want the outcome reported in progress (%+v)", results, u.Result)
	}
	select {
	case req := <-proxies.requests:
		t.Errorf("unexpected request after cancellation: %s %s", req.server, req.path)
	default:
	}
}

func checkCanceledPingDownload(t *testing.T, u PingProgress, index, completed, total int) {
	t.Helper()
	if u.Phase != PhaseSpeed || u.EntryDone || u.Result.Entry.Index != index || u.Completed != completed || u.Total != total || u.SpeedTotal != total ||
		u.Result.Err != nil || u.Result.Latency <= 0 || u.Result.Speed != 0 || !errors.Is(u.Result.SpeedErr, context.Canceled) {
		t.Fatalf("progress = %+v, want canceled speed update %d of %d for entry %d", u, completed, total, index)
	}
}

type pingTestRequest struct {
	server, path string
	arrived      time.Time
	release      func()
}

type pingTestProxies struct {
	t          *testing.T
	requests   chan pingTestRequest
	releaseAll chan struct{}

	mu                sync.Mutex
	byIP              map[string]int
	active, downloads int
	peak              pingTestPeaks
}

type pingTestPeaks struct{ total, perIP, downloads int }

func newPingTestProxies(t *testing.T) *pingTestProxies {
	return &pingTestProxies{
		t: t, requests: make(chan pingTestRequest, 32), releaseAll: make(chan struct{}), byIP: make(map[string]int),
	}
}

func (p *pingTestProxies) server(ip, name string) *share.Server {
	p.t.Helper()
	return p.hostnameServer(ip, ip, name)
}

func (p *pingTestProxies) hostnameServer(ip, host, name string) *share.Server {
	p.t.Helper()
	addr := connectProxyAt(p.t, ip, func(w http.ResponseWriter, r *http.Request) {
		release := make(chan struct{})
		req := pingTestRequest{name, r.URL.Path, time.Now(), func() { close(release) }}
		download := req.path == "/down"
		p.mu.Lock()
		p.active++
		p.byIP[ip]++
		p.peak.total = max(p.peak.total, p.active)
		p.peak.perIP = max(p.peak.perIP, p.byIP[ip])
		if download {
			p.downloads++
			p.peak.downloads = max(p.peak.downloads, p.downloads)
		}
		p.mu.Unlock()

		select {
		case p.requests <- req:
			select {
			case <-release:
			case <-p.releaseAll:
			case <-p.t.Context().Done():
			}
		case <-p.t.Context().Done():
		}

		p.mu.Lock()
		p.active--
		p.byIP[ip]--
		if download {
			p.downloads--
		}
		p.mu.Unlock()
		if download {
			fmt.Fprint(w, "download body")
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		p.t.Fatal(err)
	}
	return proxyServer(p.t, net.JoinHostPort(host, port), name)
}

func (p *pingTestProxies) peaks() pingTestPeaks {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func pingTestEntries(servers ...*share.Server) []config.Entry {
	entries := make([]config.Entry, len(servers))
	for i, s := range servers {
		entries[i] = config.Entry{Index: i + 1, Server: s}
	}
	return entries
}

func startTestPing(t *testing.T, ctx context.Context, entries []config.Entry, o PingOptions, download bool) (<-chan PingProgress, <-chan []PingResult) {
	updates := make(chan PingProgress, 32)
	finished := make(chan []PingResult, 1)
	o.URL = "http://probe.invalid/ping"
	o.Timeout = 15 * time.Second
	o.OnProgress = func(u PingProgress) { updates <- u }
	if download {
		o.DownloadURL = "http://probe.invalid/down"
	}
	go func() {
		finished <- Ping(ctx, entries, o)
		close(finished)
	}()
	t.Cleanup(func() { awaitPingTest(t, finished, "Ping cleanup") })
	return updates, finished
}

func awaitPingTest[T any](t *testing.T, events <-chan T, what string) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func expectPingTestRequest(t *testing.T, proxies *pingTestProxies, server, path string) pingTestRequest {
	t.Helper()
	req := awaitPingTest(t, proxies.requests, server+" "+path)
	if req.server != server || req.path != path {
		t.Fatalf("request = %s %s, want %s %s", req.server, req.path, server, path)
	}
	return req
}

func checkPingTestProgress(t *testing.T, u PingProgress, phase PingPhase, index, completed int) {
	t.Helper()
	if u.Phase != phase || u.Result.Entry.Index != index || u.Completed != completed || u.EntryDone != (phase == PhaseLatency) || u.Result.Err != nil {
		t.Fatalf("progress = %+v, want phase %d, entry %d, completed %d", u, phase, index, completed)
	}
	if phase == PhaseSpeed && (u.Result.Speed <= 0 || u.Result.SpeedErr != nil) {
		t.Fatalf("speed progress = %+v, want a successful download", u)
	}
}

func checkPingTestResults(t *testing.T, entries []config.Entry, results []PingResult, speed bool) {
	t.Helper()
	if len(results) != len(entries) {
		t.Fatalf("got %d results, want %d", len(results), len(entries))
	}
	for i, r := range results {
		if r.Entry.Index != entries[i].Index || r.Err != nil || r.Latency <= 0 || r.SpeedErr != nil || speed != (r.Speed > 0) {
			t.Errorf("result %d = %+v, want successful probes for entry %d (download %t)", i, r, entries[i].Index, speed)
		}
	}
}
