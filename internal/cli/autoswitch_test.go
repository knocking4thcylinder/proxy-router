package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// The fastest download wins over the lowest latency; pools only when no
// single server works.
func TestPickFastest(t *testing.T) {
	result := func(name string, pool bool, latency time.Duration, speed float64, err error) engine.PingResult {
		s := &share.Server{Name: name}
		if pool {
			s.Pool = &share.Pool{}
		}
		return engine.PingResult{Entry: config.Entry{Server: s}, Latency: latency, Speed: speed, Err: err}
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
