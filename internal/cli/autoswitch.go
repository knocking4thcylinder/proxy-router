package cli

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
)

// Auto-switching: after "use --fastest", a running proxy-router watches
// its connections to the server it uses (engine.Watcher). Nothing is
// tested while they work. When one shows trouble (data stopping
// mid-transfer, as when a censor starts cutting connections to the server,
// a reset, or the server unreachable), ping.download_url is downloaded
// through the server. When that fails auto_switch.failures times in a row,
// every other server is tested like "use --fastest" does and the fastest
// working one takes over.
const (
	// autoRetry is how soon a failed check is repeated, to confirm it.
	autoRetry = 10 * time.Second
	// autoCalm is how long trouble is ignored after a check found the
	// server working; it doubles, up to autoCalmMax, while trouble keeps
	// turning out to be nothing.
	autoCalm    = time.Minute
	autoCalmMax = 10 * time.Minute
	// autoQuiet is how long to wait after a scan found nothing better.
	autoQuiet = 5 * time.Minute
	// autoForget is how long a server that stopped working is left out of
	// scans: it's likely still blocked.
	autoForget = 15 * time.Minute
)

// autoPick is where auto-switching moved, kept in memory when it can't be
// saved to state.json (the TUN service never writes there). It holds only
// while the user's selection is still base: picking another server, or
// "use --fastest" again, ends it.
type autoPick struct {
	base config.Selection
	to   config.Selection
}

func (p *autoPick) entry(s *config.State) (config.Entry, bool) {
	if p == nil || s.Selected == nil || *s.Selected != p.base {
		return config.Entry{}, false
	}
	for _, e := range s.Entries() {
		if e.Group == p.to.Group && e.Server.Name == p.to.Name {
			return e, true
		}
	}
	return config.Entry{}, false
}

func selectionOf(e config.Entry) config.Selection {
	return config.Selection{Group: e.Group, Name: e.Server.Name}
}

// autoSwitching reports whether this run replaces its server when it
// stops working.
func (o runOptions) autoSwitching(e *env) bool {
	return o.server == "" && e.state.Selected != nil && e.state.Selected.Auto &&
		e.cfg.AutoSwitch.Enabled && e.cfg.Ping.DownloadURL != ""
}

// autoTarget is the server auto-switching watches: the one in use, unless
// it's a pool, which has its own health check.
func (o runOptions) autoTarget(e *env) (config.Entry, bool) {
	if !o.autoSwitching(e) {
		return config.Entry{}, false
	}
	entry, ok := o.pick.entry(e.state)
	if !ok {
		entry, ok = e.state.Current()
	}
	if !ok || entry.Server.Pool != nil {
		return config.Entry{}, false
	}
	return entry, true
}

// switcher runs the checks and scans for the run loop, which owns it.
type switcher struct {
	w *engine.Watcher
	// watching is the server whose connections are watched, through
	// instance generation gen.
	watching *config.Selection
	gen      int
	stall    time.Duration

	checking bool
	scanning bool
	failures int
	// passes counts checks in a row that found the server working.
	passes     int
	calmUntil  time.Time
	quietUntil time.Time
	// failed holds servers that stopped working, and when.
	failed  map[config.Selection]time.Time
	checked chan checkResult
	scanned chan scanResult
	// retry fires when a failed check is due to be repeated.
	retry   chan struct{}
	retries *time.Timer
}

type checkResult struct {
	// gen is the instance generation the check went through; a reload
	// in between makes it meaningless.
	gen    int
	target config.Entry
	err    error
}

type scanResult struct {
	from   config.Entry
	base   config.Selection
	best   engine.PingResult
	ok     bool
	tested int
}

func newSwitcher(w *engine.Watcher) *switcher {
	return &switcher{
		w:       w,
		failed:  map[config.Selection]time.Time{},
		checked: make(chan checkResult, 1),
		scanned: make(chan scanResult, 1),
		retry:   make(chan struct{}, 1),
	}
}

// follow watches the server auto-switching looks after, if any, through
// instance generation gen. The run loop calls it whenever the instance or
// the selection may have changed.
func (sw *switcher) follow(o runOptions, gen int) {
	if sw.scanning {
		return
	}
	e, err := load()
	if err != nil {
		return
	}
	target, ok := o.autoTarget(e)
	if !ok {
		if sw.watching != nil {
			sw.w.Stop()
			sw.watching = nil
		}
		sw.reset()
		return
	}
	sel, stall := selectionOf(target), e.cfg.AutoSwitch.Stall.D()
	if sw.watching != nil && *sw.watching == sel && sw.gen == gen && sw.stall == stall {
		return
	}
	if sw.watching == nil || *sw.watching != sel {
		sw.reset()
	}
	sw.w.Start(stall)
	sw.watching, sw.gen, sw.stall = &sel, gen, stall
}

// reset forgets the checks of a server that's no longer watched.
func (sw *switcher) reset() {
	sw.failures, sw.passes, sw.calmUntil = 0, 0, time.Time{}
	if sw.retries != nil {
		sw.retries.Stop()
		sw.retries = nil
	}
}

// trouble starts a check of the server when a connection to it ran into t.
func (sw *switcher) trouble(ctx context.Context, o runOptions, inst *core.Instance, gen int, t engine.Trouble) {
	now := time.Now()
	if sw.checking || sw.scanning || sw.retries != nil || now.Before(sw.calmUntil) || now.Before(sw.quietUntil) {
		return
	}
	sw.start(ctx, o, inst, gen, t.String())
}

// start checks the server in use through inst, the running instance
// (generation gen), because of why ("": to confirm a failed check).
func (sw *switcher) start(ctx context.Context, o runOptions, inst *core.Instance, gen int, why string) {
	if sw.checking || sw.scanning || inst == nil {
		return
	}
	e, err := load()
	if err != nil {
		return
	}
	target, ok := o.autoTarget(e)
	if !ok {
		return
	}
	if why == "" {
		fmt.Printf("%s auto-switch: checking %s again\n", now(), clean(target.String()))
	} else {
		fmt.Printf("%s auto-switch: %s through %s; checking it\n", now(), why, clean(target.String()))
	}
	sw.checking = true
	limit := e.cfg.AutoSwitch.Timeout.D()
	stall := min(2*e.cfg.Ping.Timeout.D(), limit)
	url := e.cfg.Ping.DownloadURL
	go func() {
		_, err := engine.CheckOutbound(ctx, inst, "proxy", url, stall, limit)
		sw.checked <- checkResult{gen: gen, target: target, err: err}
	}()
}

// again repeats a failed check after autoRetry.
func (sw *switcher) again(ctx context.Context, o runOptions, inst *core.Instance, gen int) {
	sw.retries = nil
	sw.start(ctx, o, inst, gen, "")
}

// check takes a check's result and starts a scan if it's time to switch.
func (sw *switcher) check(ctx context.Context, o runOptions, r checkResult, gen int) {
	sw.checking = false
	if r.gen != gen {
		return
	}
	e, err := load()
	if err != nil {
		return
	}
	if r.err == nil {
		calm := min(autoCalm<<min(sw.passes, 4), autoCalmMax)
		sw.passes++
		sw.calmUntil = time.Now().Add(calm)
		if sw.failures > 0 {
			fmt.Printf("%s auto-switch: %s works again\n", now(), clean(r.target.String()))
		} else {
			fmt.Printf("%s auto-switch: %s works; ignoring trouble for %s\n", now(), clean(r.target.String()), calm)
		}
		sw.failures = 0
		return
	}
	sw.failures++
	sw.passes = 0
	need := e.cfg.AutoSwitch.Failures
	fmt.Printf("%s auto-switch: check through %s failed (%d/%d): %s\n",
		now(), clean(r.target.String()), min(sw.failures, need), need, shortErr(r.err))
	if sw.failures < need {
		sw.retries = time.AfterFunc(autoRetry, func() {
			select {
			case sw.retry <- struct{}{}:
			default:
			}
		})
		return
	}
	if time.Now().Before(sw.quietUntil) {
		return
	}
	sw.scanning = true
	// Nothing to watch while the scan's test instances take over Xray's
	// process-wide state.
	sw.w.Stop()
	sw.watching = nil
	go func() { sw.scanned <- scan(ctx, e, o, r.target, sw.avoid()) }()
}

// avoid lists servers that failed recently.
func (sw *switcher) avoid() []config.Selection {
	var out []config.Selection
	for s, at := range sw.failed {
		if time.Since(at) < autoForget {
			out = append(out, s)
		} else {
			delete(sw.failed, s)
		}
	}
	return out
}

// scan tests the servers auto-switching may move to and picks the fastest.
// It runs Xray instances in this process, which take over Xray's globals
// from the running one, so the caller must restart that afterwards.
func scan(ctx context.Context, e *env, o runOptions, from config.Entry, avoid []config.Selection) scanResult {
	sel := *e.state.Selected
	r := scanResult{from: from, base: sel}
	entries, err := e.state.GroupEntries(sel.AutoGroup)
	if err != nil {
		entries = e.state.Entries()
	}
	entries = slices.DeleteFunc(entries, func(en config.Entry) bool {
		s := selectionOf(en)
		return s == selectionOf(from) || slices.Contains(avoid, s)
	})
	r.tested = len(entries)
	if len(entries) == 0 {
		return r
	}
	opts, err := e.ownOptions(o)
	if err != nil {
		fmt.Printf("%s auto-switch: %v\n", now(), err)
		return r
	}
	opts.URL, opts.Timeout = e.cfg.Ping.URL, e.cfg.Ping.Timeout.D()
	opts.Parallel, opts.PerEndpoint = 16, e.cfg.Ping.PerEndpoint
	opts.DownloadURL = e.cfg.Ping.DownloadURL
	fmt.Printf("%s auto-switch: testing %d other servers...\n", now(), len(entries))
	r.best, r.ok = pickFastest(engine.Ping(ctx, entries, opts))
	return r
}

// apply moves to what a scan found: saved to state.json, or, where that
// can't be written, returned as the pick to keep (cur if nothing changes).
func (sw *switcher) apply(r scanResult, cur *autoPick) *autoPick {
	sw.scanning, sw.failures = false, 0
	sw.failed[selectionOf(r.from)] = time.Now()
	if !r.ok {
		sw.quietUntil = time.Now().Add(autoQuiet)
		fmt.Printf("%s auto-switch: none of %d other servers works; staying on %s, ignoring trouble for %s\n",
			now(), r.tested, clean(r.from.String()), autoQuiet)
		return cur
	}
	e, err := load()
	if err != nil {
		fmt.Printf("%s auto-switch: %v\n", now(), err)
		return cur
	}
	if e.state.Selected == nil || *e.state.Selected != r.base {
		// The user picked a server while the scan ran.
		return cur
	}
	to := r.best.Entry
	fmt.Printf("%s auto-switch: %s stopped working; switching to %s (%s)\n",
		now(), clean(r.from.String()), clean(to.String()), pingSummary(r.best))
	if !config.Confined() {
		e.state.SelectAuto(to, r.base.AutoGroup)
		err := e.state.Save()
		if err == nil {
			return nil
		}
		fmt.Printf("%s auto-switch: save state: %v\n", now(), err)
	}
	return &autoPick{base: r.base, to: selectionOf(to)}
}

func now() string { return time.Now().Format(time.TimeOnly) }
