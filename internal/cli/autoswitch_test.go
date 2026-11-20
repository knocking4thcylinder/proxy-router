package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// The fastest download wins over the lowest latency; a server whose speed
// test failed still works, so it only loses to reachable servers with a
// measured or unmeasured speed; pools only when no single server works.
func TestPickFastest(t *testing.T) {
	result := func(name string, pool bool, latency time.Duration, speed float64, err error) engine.PingResult {
		s := &share.Server{Name: name}
		if pool {
			s.Pool = &share.Pool{}
		}
		return engine.PingResult{Entry: config.Entry{Server: s}, Latency: latency, Speed: speed, Err: err}
	}
	speedErr := func(name string, latency time.Duration, err error) engine.PingResult {
		return engine.PingResult{Entry: config.Entry{Server: &share.Server{Name: name}}, Latency: latency, SpeedErr: err}
	}
	cases := []struct {
		want    string
		results []engine.PingResult
	}{
		{"fast-download", []engine.PingResult{
			result("low-latency", false, 50*time.Millisecond, 1e5, nil),
			result("fast-download", false, 300*time.Millisecond, 1e6, nil),
		}},
		{"single", []engine.PingResult{
			result("pool", true, 10*time.Millisecond, 1e7, nil),
			result("single", false, 400*time.Millisecond, 1e5, nil),
		}},
		{"pool", []engine.PingResult{
			result("pool", true, 10*time.Millisecond, 1e7, nil),
			result("broken", false, 0, 0, errors.New("stalled")),
		}},
		{"measured", []engine.PingResult{
			result("unmeasured", false, 10*time.Millisecond, 0, nil),
			result("measured", false, 400*time.Millisecond, 1e5, nil),
		}},
		{"measured", []engine.PingResult{
			speedErr("stalled", 10*time.Millisecond, engine.ErrStalled),
			result("measured", false, 400*time.Millisecond, 1e5, nil),
		}},
		{"unmeasured", []engine.PingResult{
			speedErr("stalled", 10*time.Millisecond, engine.ErrStalled),
			result("unmeasured", false, 300*time.Millisecond, 0, nil),
		}},
		{"stalled", []engine.PingResult{
			speedErr("stalled", 100*time.Millisecond, engine.ErrStalled),
			result("dead", false, 0, 0, errors.New("timeout")),
		}},
		{"quicker", []engine.PingResult{
			result("slower", false, 300*time.Millisecond, 0, nil),
			result("quicker", false, 100*time.Millisecond, 0, nil),
		}},
	}
	for _, c := range cases {
		best, ok := pickFastest(c.results)
		if !ok || best.Entry.Server.Name != c.want {
			t.Errorf("picked %v (%v); want %s", best.Entry.Server, ok, c.want)
		}
	}
	if _, ok := pickFastest([]engine.PingResult{result("broken", false, 0, 0, errors.New("x"))}); ok {
		t.Error("picked a broken server")
	}
}

// A switch kept in memory (the TUN service) holds only while the user's
// selection is the one it replaced, and the server still exists.
func TestAutoPickFollowsTheUsersSelection(t *testing.T) {
	st := &config.State{Subscriptions: []*config.Subscription{{Name: "sub", Servers: []*share.Server{{Name: "a"}, {Name: "b"}}}}}
	st.SelectAuto(st.Entries()[0], "")
	pick := &autoPick{base: *st.Selected, to: config.Selection{Group: "sub", Name: "b"}}
	if e, ok := pick.entry(st); !ok || e.Server.Name != "b" {
		t.Fatalf("got %v, %v; want b", e.Server, ok)
	}
	o := runOptions{pick: pick}
	cfg, _ := config.Load(t.TempDir())
	env := &env{cfg: cfg, state: st}
	if target, ok := o.autoTarget(env); !ok || target.Server.Name != "b" {
		t.Errorf("checked %v, %v; want b", target.Server, ok)
	}

	st.Select(st.Entries()[0]) // "use a": no longer automatic
	if _, ok := pick.entry(st); ok {
		t.Error("pick outlived a manual selection")
	}
	if _, ok := o.autoTarget(env); ok {
		t.Error("checking a manually selected server")
	}

	st.SelectAuto(st.Entries()[1], "") // "use --fastest" again
	if _, ok := pick.entry(st); ok {
		t.Error("pick outlived a new use --fastest")
	}

	st.SelectAuto(st.Entries()[0], "")
	pick.base = *st.Selected
	st.Subscriptions[0].Servers = st.Subscriptions[0].Servers[:1] // b is gone
	if _, ok := pick.entry(st); ok {
		t.Error("pick of a removed server")
	}
	var none *autoPick
	if _, ok := none.entry(st); ok {
		t.Error("nil pick")
	}
}

// Auto-switching is off for --server, when disabled, and for pools.
func TestAutoTargetSkips(t *testing.T) {
	st := &config.State{Subscriptions: []*config.Subscription{{Name: "sub", Servers: []*share.Server{
		{Name: "a"}, {Name: "pool", Pool: &share.Pool{}},
	}}}}
	cfg, _ := config.Load(t.TempDir())
	env := &env{cfg: cfg, state: st}
	st.SelectAuto(st.Entries()[0], "")
	if _, ok := (runOptions{server: "a"}).autoTarget(env); ok {
		t.Error("auto-switching a --server run")
	}
	cfg.AutoSwitch.Enabled = false
	if _, ok := (runOptions{}).autoTarget(env); ok {
		t.Error("auto-switching while disabled")
	}
	cfg.AutoSwitch.Enabled = true
	st.SelectAuto(st.Entries()[1], "")
	if _, ok := (runOptions{}).autoTarget(env); ok {
		t.Error("checking a pool")
	}
}

// A speed test that fails while the server still answers requests says
// nothing about the server, so it neither counts as a failure nor starts a
// scan.
func TestSpeedOnlyCheckDoesNotCountAsFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	if _, err := config.LoadState(dir); err != nil {
		t.Fatal(err)
	}
	sw := newSwitcher(engine.WatchOutbound("proxy"))
	target := config.Entry{Server: &share.Server{Name: "a"}}
	sw.check(context.Background(), runOptions{}, checkResult{
		target:    target,
		err:       errors.New("connection reset"),
		speedOnly: true,
	}, 0)
	if sw.failures != 0 || sw.scanning {
		t.Fatalf("speed-only failure counted: failures %d, scanning %v", sw.failures, sw.scanning)
	}
	if !sw.speedOnly {
		t.Fatal("speed-only state not kept")
	}
	sw.check(context.Background(), runOptions{}, checkResult{target: target}, 0)
	if sw.speedOnly {
		t.Fatal("speed-only state not cleared after a full check")
	}
}

// TCP servers are only watched; Hysteria is watched and checked every
// autoFallback intervals; XHTTP over HTTP/3 only on the timer.
func TestSwitcherFollowsWhatItCanWatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	var servers []*share.Server
	for _, link := range []string{
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=tcp&security=tls&sni=a#tcp",
		"hysteria2://pass@1.2.3.4:443/?sni=a#hy2",
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=xhttp&security=tls&sni=a&alpn=h3#h3",
	} {
		s, err := share.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, s)
	}
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Subscriptions = []*config.Subscription{{Name: "sub", Servers: servers}}
	sw := newSwitcher(engine.WatchOutbound("proxy"))
	defer sw.reset()
	cfg, _ := config.Load(dir)
	iv := cfg.AutoSwitch.Interval.D()
	for i, want := range []struct {
		watched bool
		every   time.Duration
		how     string
	}{
		{true, 0, "when its connections show trouble"},
		{true, autoFallback * iv, "when its connections show trouble, and every 5m0s"},
		{false, iv, "every 1m0s (its connections can't be watched)"},
	} {
		st.SelectAuto(st.Entries()[i], "")
		if err := st.Save(); err != nil {
			t.Fatal(err)
		}
		sw.follow(runOptions{}, 0)
		if sw.watched != want.watched || sw.every != want.every || (sw.next != nil) != (want.every > 0) {
			t.Errorf("%s: watched %v, every %s, timer %v; want %v, %s", servers[i].Name, sw.watched, sw.every, sw.next != nil, want.watched, want.every)
		}
		if how := howChecked(cfg, servers[i]); how != want.how {
			t.Errorf("%s: %q; want %q", servers[i].Name, how, want.how)
		}
	}
}

func TestRangeOf(t *testing.T) {
	for _, c := range []struct {
		addr, want string
	}{
		{"1.2.3.4", "1.2.3.0/24"},
		{"10.0.0.1", "10.0.0.0/24"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1::/48"},
		{"example.com", ""},
		{"", ""},
	} {
		e := config.Entry{Server: &share.Server{Address: c.addr}}
		if got := rangeOf(e); got != c.want {
			t.Errorf("rangeOf(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestPickCandidatesPrefersQuietBlocks(t *testing.T) {
	entry := func(name, addr string, latency time.Duration) engine.PingResult {
		return engine.PingResult{
			Entry:   config.Entry{Server: &share.Server{Name: name, Address: addr}},
			Latency: latency,
		}
	}
	blocked := map[string]time.Time{"188.255.236.0/24": time.Now()}
	results := []engine.PingResult{
		entry("fast-blocked", "188.255.236.19", 10*time.Millisecond),
		entry("slow-quiet", "213.239.169.237", 400*time.Millisecond),
		entry("dead", "1.1.1.1", 0), // Err set below
	}
	results[2].Err = errors.New("timeout")

	got := pickCandidates(results, blocked)
	if len(got) != 2 || got[0].Entry.Server.Name != "slow-quiet" || got[1].Entry.Server.Name != "fast-blocked" {
		names := make([]string, len(got))
		for i, r := range got {
			names[i] = r.Entry.Server.Name
		}
		t.Fatalf("picked %v, want [slow-quiet fast-blocked]", names)
	}
	// Nothing quiet answered: a flagged block still beats staying put.
	got = pickCandidates(results[:1], blocked)
	if len(got) != 1 || got[0].Entry.Server.Name != "fast-blocked" {
		t.Fatalf("picked %v, want the flagged one as the only answer", got)
	}
}

func TestApplyRemembersBlocksAndFaded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(name, addr string) config.Entry {
		return config.Entry{Group: "sub", Server: &share.Server{Name: name, Address: addr}}
	}
	st.Subscriptions = []*config.Subscription{{Name: "sub", Servers: []*share.Server{
		entry("old", "188.255.236.18").Server,
		entry("next", "213.239.169.237").Server,
		entry("faded", "66.201.6.46").Server,
	}}}
	st.SelectAuto(st.Entries()[0], "")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	sw := newSwitcher(engine.WatchOutbound("proxy"))
	defer sw.reset()
	best := engine.PingResult{Entry: entry("next", "213.239.169.237"), Latency: time.Second}
	faded := engine.PingResult{Entry: entry("faded", "66.201.6.46"), Latency: 2 * time.Second}
	r := scanResult{from: entry("old", "188.255.236.18"), base: *st.Selected, best: best, ok: true, faded: []engine.PingResult{faded}}

	if pick := sw.apply(r, nil); pick != nil {
		t.Fatalf("pick = %v, want the selection saved to state", pick)
	}
	for _, c := range []struct {
		sel   string
		block string
	}{
		{"old", "188.255.236.0/24"},
		{"faded", "66.201.6.0/24"},
	} {
		if _, ok := sw.failed[config.Selection{Group: "sub", Name: c.sel}]; !ok {
			t.Errorf("%s not remembered as failed", c.sel)
		}
		if _, ok := sw.blocked[c.block]; !ok {
			t.Errorf("block %s not remembered (%s's)", c.block, c.sel)
		}
	}
	if got := sw.avoidRanges(); len(got) != 2 {
		t.Fatalf("avoidRanges = %v, want the two blocks", got)
	}

	// The switch itself saved to state.json, as apply does outside the
	// confined service.
	next, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sel := next.Selected; sel == nil || sel.Name != "next" || !sel.Auto {
		t.Fatalf("selected %+v, want the auto-switch to next", sel)
	}
}

func TestApplyStaysWhenNothingVerified(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	st, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := config.Entry{Server: &share.Server{Name: "old", Address: "188.255.236.18"}}
	st.Subscriptions = []*config.Subscription{{Name: "sub", Servers: []*share.Server{old.Server}}}
	st.SelectAuto(st.Entries()[0], "")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	sw := newSwitcher(engine.WatchOutbound("proxy"))
	defer sw.reset()
	cur := &autoPick{base: *st.Selected, to: config.Selection{Group: "sub", Name: "old"}}
	faded := []engine.PingResult{{Entry: config.Entry{Server: &share.Server{Name: "gone", Address: "66.201.6.46"}}}}
	r := scanResult{from: old, base: *st.Selected, ok: false, tested: 7, faded: faded}

	if pick := sw.apply(r, cur); pick != cur {
		t.Fatalf("pick = %v, want to stay on cur", pick)
	}
	if sw.quietUntil.IsZero() {
		t.Error("nothing verified but trouble isn't calmed")
	}
	if _, ok := sw.blocked["66.201.6.0/24"]; !ok {
		t.Error("a faded answer's block not remembered")
	}
}
