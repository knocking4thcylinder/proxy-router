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

// Auto-switching is off for --server, for interval 0, and for pools.
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
	cfg.AutoSwitch.Interval = 0
	if _, ok := (runOptions{}).autoTarget(env); ok {
		t.Error("auto-switching with interval 0")
	}
	cfg.AutoSwitch.Interval = config.Duration(time.Minute)
	st.SelectAuto(st.Entries()[1], "")
	if _, ok := (runOptions{}).autoTarget(env); ok {
		t.Error("checking a pool")
	}
}
