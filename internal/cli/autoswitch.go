package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// Auto-switching: after "use --fastest", a running proxy-router watches
// its connections to the server it uses (engine.Watcher). Nothing is
// tested while they work. When one shows trouble (data stopping
// mid-transfer, as when a censor starts cutting connections to the server,
// a reset, the server turning the account away, or the server unreachable),
// ping.download_url is downloaded through the server. Servers whose
// connections can't be watched (XHTTP over HTTP/3, mKCP, WireGuard) are
// checked that way every auto_switch.interval instead, and Hysteria, only
// partly watched, every autoFallback intervals as well. When the check fails
// auto_switch.failures times in a row, every other server is tested like
// "use --fastest" does and the fastest working one takes over.
const (
	// autoRetry is how soon a failed check is repeated, to confirm it.
	autoRetry = 10 * time.Second
	// autoCalm is how long trouble is ignored after a check found the
	// server working; it doubles, up to autoCalmMax, while trouble keeps
	// turning out to be nothing.
	autoCalm    = time.Minute
	autoCalmMax = 10 * time.Minute
	// autoFallback times auto_switch.interval is how often a partly
	// watched server (Hysteria) is checked anyway.
	autoFallback = 5
	// autoQuiet is how long to wait after a scan found nothing better.
	autoQuiet = 5 * time.Minute
	// autoForget is how long a server that stopped working is left out of
	// scans: it's likely still blocked.
	autoForget = 15 * time.Minute
	// scanVerify is how many of a scan's best answers are re-checked, one
	// request each, before switching: blocks land on servers minutes
	// after they answer a scan, and a switch to a freshly dead server
	// costs another full cycle.
	scanVerify = 3
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

// checkEvery is how often auto-switching checks s on a timer (0: never),
// and whether its connections are watched.
func checkEvery(cfg *config.Config, s *share.Server) (time.Duration, bool) {
	iv := cfg.AutoSwitch.Interval.D()
	switch engine.WatchCoverage(s) {
	case engine.Watched:
		return 0, true
	case engine.PartlyWatched:
		return autoFallback * iv, true
	}
	return iv, false
}

// howChecked says when auto-switching checks s.
func howChecked(cfg *config.Config, s *share.Server) string {
	switch every, watched := checkEvery(cfg, s); {
	case every == 0:
		return "when its connections show trouble"
	case watched:
		return fmt.Sprintf("when its connections show trouble, and every %s", every)
	default:
		return fmt.Sprintf("every %s (its connections can't be watched)", every)
	}
}

// switcher runs the checks and scans for the run loop, which owns it.
type switcher struct {
	w *engine.Watcher
	// looking is the server auto-switching looks after, through instance
	// generation gen. Its connections are watched, and/or it's checked
	// every so often (0: never).
	looking *config.Selection
	gen     int
	stall   time.Duration
	watched bool
	every   time.Duration

	checking bool
	scanning bool
	failures int
	// passes counts checks in a row that found the server working.
	passes    int
	calmUntil time.Time
	// speedOnly: the download failed but a plain request worked.
	speedOnly  bool
	quietUntil time.Time
	// failed holds servers that stopped working, and when.
	failed  map[config.Selection]time.Time
	blocked map[string]time.Time // address blocks (see rangeOf) that did
	checked chan checkResult
	scanned chan scanResult
	// due fires when the next check is due: to repeat a failed one
	// (confirming), or the next timed one.
	due        chan struct{}
	next       *time.Timer
	confirming bool
	// troubled: the check running was prompted by trouble.
	troubled bool
}

type checkResult struct {
	// gen is the instance generation the check went through; a reload
	// in between makes it meaningless.
	gen    int
	target config.Entry
	err    error
	// speedOnly means the download failed but the ping URL answered: the
	// server is alive, the speed test site just didn't work through it.
	speedOnly bool
}

type scanResult struct {
	from   config.Entry
	base   config.Selection
	best   engine.PingResult
	ok     bool
	tested int
	// faded answered the scan but not the re-check before switching:
	// their blocks are remembered, like the old server's.
	faded []engine.PingResult
}

// pickCandidates lists the servers that answered in the order a switch
// should try them: singles first (a working single beats a pool, even one
// in a range that failed recently - the pool fallback policy), and within
// each class, ones in blocks that stopped working recently move behind the
// rest: their next failure is the scan's away, not minutes after it. A
// range failure never changes the class order, only the order inside it.
func pickCandidates(results []engine.PingResult, blocked map[string]time.Time) []engine.PingResult {
	class := func(rs []engine.PingResult) []engine.PingResult {
		var fresh, stale []engine.PingResult
		for _, r := range rs {
			if at, bad := blocked[rangeOf(r.Entry)]; bad && time.Since(at) < autoForget {
				stale = append(stale, r)
			} else {
				fresh = append(fresh, r)
			}
		}
		order := func(rs []engine.PingResult) {
			slices.SortStableFunc(rs, func(a, b engine.PingResult) int {
				switch {
				case better(a, b):
					return -1
				case better(b, a):
					return 1
				}
				return 0
			})
		}
		order(fresh)
		order(stale)
		return append(fresh, stale...)
	}
	var singles, pools []engine.PingResult
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if r.Entry.Server.Pool != nil {
			pools = append(pools, r)
		} else {
			singles = append(singles, r)
		}
	}
	return append(class(singles), class(pools)...)
}

func newSwitcher(w *engine.Watcher) *switcher {
	return &switcher{
		w:       w,
		failed:  map[config.Selection]time.Time{},
		blocked: map[string]time.Time{},
		checked: make(chan checkResult, 1),
		scanned: make(chan scanResult, 1),
		due:     make(chan struct{}, 1),
	}
}

// follow looks after the server auto-switching is for, if any, through
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
		if sw.looking != nil {
			sw.w.Stop()
			sw.looking = nil
		}
		sw.reset()
		return
	}
	sel, stall := selectionOf(target), e.cfg.AutoSwitch.Stall.D()
	every, watched := checkEvery(e.cfg, target.Server)
	same := sw.looking != nil && *sw.looking == sel && sw.watched == watched && sw.every == every
	if same && sw.gen == gen && sw.stall == stall {
		return
	}
	if !same {
		sw.reset()
	}
	sw.looking, sw.gen, sw.stall, sw.watched, sw.every = &sel, gen, stall, watched, every
	if watched {
		sw.w.Start(stall)
	} else {
		sw.w.Stop()
	}
	sw.schedule()
}

// reset forgets the checks of a server that's no longer looked after.
func (sw *switcher) reset() {
	sw.failures, sw.passes, sw.calmUntil = 0, 0, time.Time{}
	sw.speedOnly = false
	if sw.next != nil {
		sw.next.Stop()
		sw.next = nil
	}
	sw.confirming = false
}

// after makes the next check due in d.
func (sw *switcher) after(d time.Duration) {
	if sw.next != nil {
		sw.next.Stop()
	}
	sw.confirming = false
	sw.next = time.AfterFunc(d, func() {
		select {
		case sw.due <- struct{}{}:
		default:
		}
	})
}

// schedule makes the next timed check due, unless one is already, or
// running.
func (sw *switcher) schedule() {
	if sw.every > 0 && sw.looking != nil && sw.next == nil && !sw.checking && !sw.scanning {
		sw.after(max(sw.every, time.Until(sw.quietUntil)))
	}
}

// trouble starts a check of the server when a connection to it ran into t.
func (sw *switcher) trouble(ctx context.Context, o runOptions, inst *core.Instance, gen int, t engine.Trouble) {
	now := time.Now()
	if sw.checking || sw.scanning || sw.confirming || now.Before(sw.calmUntil) || now.Before(sw.quietUntil) {
		return
	}
	sw.start(ctx, o, inst, gen, t.String())
}

// start checks the server in use through inst, the running instance
// (generation gen), because of why ("": it was due).
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
	switch {
	case why != "":
		fmt.Printf("%s auto-switch: %s through %s; checking it\n", now(), why, clean(target.String()))
	case sw.failures > 0:
		fmt.Printf("%s auto-switch: checking %s again\n", now(), clean(target.String()))
	}
	sw.checking, sw.troubled = true, why != ""
	limit := e.cfg.AutoSwitch.Timeout.D()
	stall := min(2*e.cfg.Ping.Timeout.D(), limit)
	url := e.cfg.Ping.DownloadURL
	go func() {
		_, err := engine.CheckOutbound(ctx, inst, "proxy", url, stall, limit)
		speedOnly := false
		if err != nil && !errors.Is(err, engine.ErrStalled) && !errors.Is(err, engine.ErrTooSlow) {
			// A connection-level failure to the speed site can be the
			// site (blocked, reset), not the server. A small request
			// through the same outbound decides.
			timeout := e.cfg.Ping.Timeout.D()
			if _, pingErr := engine.CheckOutbound(ctx, inst, "proxy", e.cfg.Ping.URL, timeout, timeout); pingErr == nil {
				speedOnly = true
			}
		}
		sw.checked <- checkResult{gen: gen, target: target, err: err, speedOnly: speedOnly}
	}()
}

// again runs the check that's due.
func (sw *switcher) again(ctx context.Context, o runOptions, inst *core.Instance, gen int) {
	sw.next, sw.confirming = nil, false
	sw.start(ctx, o, inst, gen, "")
	sw.schedule()
}

// check takes a check's result and starts a scan if it's time to switch.
func (sw *switcher) check(ctx context.Context, o runOptions, r checkResult, gen int) {
	sw.checking = false
	// Timed checks go on whatever this one found, unless a scan starts.
	defer sw.schedule()
	if r.gen != gen {
		return
	}
	e, err := load()
	if err != nil {
		return
	}
	wasSpeedOnly := sw.speedOnly
	sw.speedOnly = false
	if r.speedOnly {
		if !wasSpeedOnly {
			fmt.Printf("%s auto-switch: %s still answers requests (speed test failed: %s)\n",
				now(), clean(r.target.String()), shortErr(r.err))
		}
		sw.speedOnly = true
		sw.failures = 0
		return
	}
	if r.err == nil {
		switch {
		case sw.failures > 0:
			fmt.Printf("%s auto-switch: %s works again\n", now(), clean(r.target.String()))
		case wasSpeedOnly:
			fmt.Printf("%s auto-switch: %s passes the speed test again\n", now(), clean(r.target.String()))
		case sw.troubled:
			// Trouble that keeps turning out to be nothing is listened to
			// less and less.
			calm := min(autoCalm<<min(sw.passes, 4), autoCalmMax)
			sw.passes++
			sw.calmUntil = time.Now().Add(calm)
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
		sw.after(autoRetry)
		sw.confirming = true
		return
	}
	if time.Now().Before(sw.quietUntil) {
		return
	}
	sw.scanning = true
	// The server that just failed two checks is confirmed: remember it
	// and its range now, not in apply. Otherwise the scan's top answers
	// can be its co-blocked neighbours - they answer, then die at the
	// re-check - and the verification burns its attempts on them while a
	// healthy range waits behind.
	sw.markFailed(r.target)
	// Nothing to look after while the scan's test instances take over
	// Xray's process-wide state.
	sw.w.Stop()
	sw.looking = nil
	sw.reset()
	go func() { sw.scanned <- scan(ctx, e, o, r.target, sw.avoid(), sw.avoidRanges()) }()
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

// avoidRanges snapshots the address blocks that stopped working recently.
// Censors block blocks, not servers: the next server in a range that just
// failed is the next one to fail, so scans only fall back into one when
// nothing else answered.
func (sw *switcher) avoidRanges() map[string]time.Time {
	out := map[string]time.Time{}
	for r, at := range sw.blocked {
		if time.Since(at) < autoForget {
			out[r] = at
		} else {
			delete(sw.blocked, r)
		}
	}
	return out
}

// markFailed remembers a server that stopped working, and the address
// block it lives in.
func (sw *switcher) markFailed(e config.Entry) {
	sw.failed[selectionOf(e)] = time.Now()
	if r := rangeOf(e); r != "" {
		sw.blocked[r] = time.Now()
	}
}

// rangeOf is the address block a server lives in: /24 for IPv4, /48 for
// IPv6, "" for a name (no block to blame or avoid). IPv4-mapped IPv6
// spellings are normalized first, so ::ffff:1.2.3.4 and 1.2.3.4 map to
// the same block and unrelated /24s stay distinct.
func rangeOf(e config.Entry) string {
	a, err := netip.ParseAddr(e.Server.Address)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// scan tests the servers auto-switching may move to, re-checks its best
// answers, and picks the fastest that still answers. It runs Xray
// instances in this process, which take over Xray's globals from the
// running one, so the caller must restart that afterwards.
func scan(ctx context.Context, e *env, o runOptions, from config.Entry, avoid []config.Selection, blocked map[string]time.Time) scanResult {
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
	opts.DownloadParallel = e.cfg.Ping.DownloadParallel
	opts.DownloadURL = e.cfg.Ping.DownloadURL
	fmt.Printf("%s auto-switch: testing %d other servers...\n", now(), len(entries))
	candidates := pickCandidates(engine.Ping(ctx, entries, opts), blocked)
	// A scan of hundreds of servers takes minutes, and blocks land on its
	// winners within them. The top answers are re-checked, one bounded
	// request each, before the switch commits.
	verify := opts
	verify.DownloadURL, verify.Parallel, verify.PerEndpoint = "", 1, 1
	r.best, r.ok, r.faded = verifyCandidates(ctx, candidates, verify, scanVerify,
		func(ctx context.Context, e config.Entry, o engine.PingOptions) error {
			res := engine.Ping(ctx, []config.Entry{e}, o)
			if len(res) == 1 && res[0].Err == nil {
				return nil
			}
			return errors.New("no answer")
		})
	return r
}

// verifyCandidates re-checks candidates in order until one passes: each
// re-check is one bounded request, so the work is independent of pool
// size. Pools are not re-checked - engine.Ping would expand a pool to
// every member and time them out one after another, while the scan has
// already measured them all, and in a running instance the pool's own
// balancer re-picks among members by its health check: the freshness the
// re-check gives a single is the balancer's job for a pool.
func verifyCandidates(ctx context.Context, candidates []engine.PingResult, opts engine.PingOptions, max int, ping func(context.Context, config.Entry, engine.PingOptions) error) (best engine.PingResult, ok bool, faded []engine.PingResult) {
	for len(candidates) > 0 && len(faded) < max {
		c := candidates[0]
		candidates = candidates[1:]
		if c.Entry.Server.Pool != nil || ping(ctx, c.Entry, opts) == nil {
			return c, true, faded
		}
		faded = append(faded, c)
	}
	return engine.PingResult{}, false, faded
}

// apply moves to what a scan found: saved to state.json, or, where that
// can't be written, returned as the pick to keep (cur if nothing changes).
func (sw *switcher) apply(r scanResult, cur *autoPick) *autoPick {
	sw.scanning, sw.failures = false, 0
	sw.markFailed(r.from)
	for _, f := range r.faded {
		sw.markFailed(f.Entry)
	}
	if len(r.faded) > 0 {
		fmt.Printf("%s auto-switch: %d answered the scan but not the re-check; their address blocks are avoided for %s\n",
			now(), len(r.faded), autoForget)
	}
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
