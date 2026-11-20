package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

const maxPingParallel = 64

type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}

// Ping measures a full HTTP request through each server, including the proxy
// handshake. Downloads can start as soon as an entry finishes its latency
// probes, using the fastest responding member for a pool. Both phases share
// the overall limit, while the per-endpoint limit bounds concurrent latency
// probes and concurrent downloads per IP separately: a download may overlap
// in-flight latency probes (borrowed or normal), so total per-IP activity
// can exceed per_endpoint. Latency probes may also borrow idle global slots
// (up to min(parallel, 4x per-endpoint)) when every endpoint with queued
// work is at its per-endpoint limit. Downloads never borrow. On
// cancellation, eligible downloads that have not started are reported with
// SpeedErr. Ping silences Xray's global logger, so don't use it next to a
// running proxy.
func Ping(ctx context.Context, entries []config.Entry, o PingOptions) []PingResult {
	// Config warnings (e.g. deprecated ciphers) would repeat for every server.
	xlog.RegisterHandler(discardLog{})
	parallel := min(max(o.Parallel, 1), maxPingParallel)
	downloadParallel := o.DownloadParallel
	if downloadParallel <= 0 {
		downloadParallel = config.DefaultPingDownloadParallel
	}
	endpointLimit := o.PerEndpoint
	if endpointLimit <= 0 {
		endpointLimit = parallel
	}
	// Endpoint limits keep probes polite and within provider rate limits, but
	// a long backlog behind one IP would otherwise leave the global budget
	// idle. Latency probes may borrow up to 4x the limit in that case, so
	// borrowing stays bounded and only uses slots nobody else wants. An
	// endpoint with queued or active downloads stops borrowing, so freed
	// slots go to those downloads instead of more borrowed probes. Speed
	// tests never borrow either: downloads through one IP share bandwidth
	// and would corrupt each other's measurement. A download may overlap
	// in-flight latency probes (borrowed or normal), so the per-endpoint
	// speed gate bounds concurrent downloads, not total activity:
	// ep.active can pass the limit by the size of that overlap until the
	// overlapping probes drain.
	overflowLimit := min(parallel, 4*min(endpointLimit, parallel))
	pending := pingQueue{limit: endpointLimit, overflowLimit: overflowLimit}
	endpoints := make(map[string]*pingEndpoint)
	endpointFor := func(key string) *pingEndpoint {
		if endpoints[key] == nil {
			endpoints[key] = &pingEndpoint{}
		}
		return endpoints[key]
	}

	// Literal endpoints can run right away. Resolve each distinct hostname
	// alongside the probes and move its jobs to the resolved IP's queue.
	var hosts []string
	waitingForIP := make(map[string][]pingJob)
	var total, completed [2]int
	addLatency := func(j pingJob) {
		total[PhaseLatency]++
		addr := j.server.Address
		switch {
		case o.PerEndpoint <= 0:
			pending.add(endpointFor(""), PhaseLatency, j)
		case addr == "" || isIPOrCIDR(addr):
			pending.add(endpointFor(pingEndpointKey(addr)), PhaseLatency, j)
		default:
			if len(waitingForIP[addr]) == 0 {
				hosts = append(hosts, addr)
			}
			waitingForIP[addr] = append(waitingForIP[addr], j)
		}
	}
	results := make([]PingResult, len(entries))
	remaining := make([]int, len(entries))
	speedPending := make([]bool, len(entries))
	for i, e := range entries {
		results[i] = PingResult{Entry: e}
		members := e.Server.Members()
		if members == nil {
			remaining[i] = 1
			addLatency(pingJob{i, e.Server})
			continue
		}
		results[i].Members, remaining[i] = len(members), len(members)
		for _, member := range members {
			addLatency(pingJob{i, member})
		}
	}

	// The scheduler owns result updates, admission and callbacks. Each
	// goroutine gets a slot before it starts and sends exactly one completion.
	probes := make(chan pingCompletion, parallel)
	lookups := make(chan pingLookup, min(parallel, len(hosts)))
	pins := make(map[string]Resolver)
	var active, activeSpeed, activeLookups, nextHost int
	phases := [2]PingPhase{PhaseLatency, PhaseSpeed}
	finishLookup := func(lookup pingLookup) {
		activeLookups--
		key := lookup.host
		if lookup.err == nil && lookup.ip != "" {
			key = pingEndpointKey(lookup.ip)
		}
		if o.Resolve != nil {
			// Reuse the answer for each probe. A failed shared retry lets
			// PinAddresses fall back to Xray's own resolution for this host.
			pins[lookup.host] = func(host string) (string, error) {
				if host == lookup.host {
					return lookup.ip, lookup.err
				}
				return o.Resolve(host)
			}
		}
		pending.add(endpointFor(key), PhaseLatency, waitingForIP[lookup.host]...)
		delete(waitingForIP, lookup.host)
	}
	// Every admitted job owns one global slot and one endpoint slot until its
	// single completion is handled, regardless of which queue admitted it.
	startJob := func(job pingJob, ep *pingEndpoint, phase PingPhase) {
		active++
		if phase == PhaseSpeed {
			activeSpeed++
			speedPending[job.entry] = false
		}
		opts := o
		if pin := pins[job.server.Address]; pin != nil {
			opts.Resolve = pin
		}
		// Space starts on one endpoint: a scan firing at one address in
		// quick succession is itself a pattern worth not sending, and the
		// pacing costs seconds. Per-endpoint pacing needs endpoints that
		// mean an address; without PerEndpoint every job shares one.
		wait := time.Duration(0)
		if o.PerEndpoint > 0 {
			wait = ep.spaced(endpointGap, time.Now())
		}
		go func() {
			if wait > 0 && ctx.Err() == nil {
				time.Sleep(wait)
			}
			p := pingCompletion{job: job, endpoint: ep, phase: phase, err: ctx.Err()}
			if p.err == nil {
				if phase == PhaseLatency {
					p.latency, p.exit, p.err = pingLatency(ctx, job.server, opts)
				} else {
					p.speed, p.err = pingSpeed(ctx, job.server, opts)
				}
			}
			probes <- p
		}()
	}
	startProbe := func(phase PingPhase) bool {
		if phase == PhaseSpeed {
			limit := min(downloadParallel, parallel)
			// Leave room for a ready latency probe even if DNS or endpoint
			// capacity is currently holding back the remaining latency work.
			if parallel > 1 && completed[PhaseLatency] < total[PhaseLatency] {
				limit = min(limit, parallel-1)
			}
			if activeSpeed >= limit {
				return false
			}
		}
		job, ep := pending.take(phase)
		if ep == nil {
			return false
		}
		// With multiple workers, alternate so downloads can overlap latency.
		// A single worker always gives ready latency the first slot.
		if parallel > 1 && phase == phases[0] {
			phases[0], phases[1] = phases[1], phases[0]
		}
		startJob(job, ep, phase)
		return true
	}
	// Only called after both normal queues came up empty, so the slot would
	// otherwise sit idle. Latency only: see overflowLimit for why downloads
	// must not borrow. The phase-alternation swap from startProbe is
	// intentionally skipped: a ready admissible speed job was already offered
	// the slot and did not take it, so a borrow cannot jump the speed queue.
	startOverflowProbe := func() bool {
		job, ep := pending.takeOverflow()
		if ep == nil {
			return false
		}
		startJob(job, ep, PhaseLatency)
		return true
	}

	type member struct {
		server   *share.Server
		endpoint *pingEndpoint
	}
	best := make([]member, len(entries))
	report := func(i int, phase PingPhase, entryDone bool) {
		completed[phase]++
		if o.OnProgress != nil {
			o.OnProgress(PingProgress{
				Result: results[i], Completed: completed[phase], Total: total[phase],
				SpeedTotal: total[PhaseSpeed], EntryDone: entryDone, Phase: phase,
			})
		}
	}
	finishProbe := func(p pingCompletion) {
		active--
		pending.release(p.endpoint, p.phase)
		i := p.job.entry
		r := &results[i]
		entryDone := false
		if p.phase == PhaseSpeed {
			activeSpeed--
			r.Speed, r.SpeedErr = p.speed, p.err
		} else {
			if p.err == nil {
				r.Alive++
				if best[i].server == nil || p.latency < r.Latency {
					r.Latency, r.Exit, r.Err = p.latency, p.exit, nil
					best[i] = member{p.job.server, p.endpoint}
				}
			} else if best[i].server == nil {
				r.Err = p.err
			}
			remaining[i]--
			entryDone = remaining[i] == 0
			if entryDone && o.DownloadURL != "" && best[i].server != nil {
				total[PhaseSpeed]++
				speedPending[i] = true
				if ctx.Err() == nil {
					pending.add(best[i].endpoint, PhaseSpeed, pingJob{i, best[i].server})
				}
			}
		}
		report(i, p.phase, entryDone)
	}

	for ctx.Err() == nil {
		// Admit probes for any host whose lookup has already completed.
		// A worker can still run a download while other answers are pending.
	drainLookups:
		for activeLookups > 0 {
			select {
			case lookup := <-lookups:
				finishLookup(lookup)
			default:
				break drainLookups
			}
		}
		for activeLookups < parallel && nextHost < len(hosts) && ctx.Err() == nil {
			host := hosts[nextHost]
			nextHost++
			activeLookups++
			go func() { lookups <- lookupPingEndpoint(ctx, host, o.Resolve) }()
		}
		for active < parallel && ctx.Err() == nil {
			if !startProbe(phases[0]) && !startProbe(phases[1]) {
				// Normal rotation left the global slot idle because every
				// endpoint with queued work sits at its own limit. Let a
				// backlogged latency queue borrow the slot.
				if !startOverflowProbe() {
					break
				}
			}
		}
		if active == 0 && activeLookups == 0 {
			break
		}
		select {
		case <-ctx.Done():
		case p := <-probes:
			finishProbe(p)
		case lookup := <-lookups:
			finishLookup(lookup)
		}
	}

	// Cancellation stops admission. Drain started probes so their instances
	// close. A custom Resolver has no context, so outstanding lookups can
	// finish on their own and send into the bounded buffer after Ping returns.
	for active > 0 {
		finishProbe(<-probes)
	}
	if err := ctx.Err(); err != nil {
		for i, left := range remaining {
			if left > 0 && best[i].server == nil {
				results[i].Err = err
			}
			if speedPending[i] {
				results[i].SpeedErr = err
				report(i, PhaseSpeed, false)
			}
		}
	}
	return results
}

type pingJob struct {
	entry  int
	server *share.Server
}

type pingCompletion struct {
	job      pingJob
	endpoint *pingEndpoint
	phase    PingPhase
	latency  time.Duration
	exit     string
	speed    float64
	err      error
}

type pingLookup struct {
	host, ip string
	err      error
}

func lookupPingEndpoint(ctx context.Context, host string, resolve Resolver) pingLookup {
	answer := pingLookup{host: host, err: ctx.Err()}
	if answer.err != nil {
		return answer
	}
	if resolve != nil {
		// Same lookups as pinning, keeping server names off plain DNS.
		answer.ip, answer.err = resolve(host)
		if (answer.err != nil || answer.ip == "") && ctx.Err() == nil {
			// A probe used to try pinning again after endpoint lookup failed.
			// Retry once per hostname before assigning the endpoint slot.
			answer.ip, answer.err = resolve(host)
		}
		if answer.err == nil && answer.ip == "" {
			answer.err = errors.New("no addresses")
		}
	} else {
		var ips []string
		ips, answer.err = net.DefaultResolver.LookupHost(ctx, host)
		if len(ips) > 0 {
			answer.ip = ips[0]
		}
	}
	return answer
}

func pingEndpointKey(addr string) string {
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.Unmap().String()
	}
	return addr
}

type pingEndpoint struct {
	active, activeSpeed int
	jobs                [2][]pingJob
	queued              [2]bool
	overflowing         bool
	lastStart           time.Time
}

// endpointGap is the least time Ping puts between two starts on one
// endpoint. Censors watch for bursts; the pacing costs a scan seconds.
var endpointGap = 200 * time.Millisecond

// spaced records a test starting at now, after waiting out the returned
// delay, and returns how long it must wait to keep gap since the previous
// start. The scheduler loop is single-threaded; no lock is needed.
func (ep *pingEndpoint) spaced(gap time.Duration, now time.Time) time.Duration {
	wait := gap - now.Sub(ep.lastStart)
	if wait < 0 {
		wait = 0
	}
	ep.lastStart = now.Add(wait)
	return wait
}

// pingQueue rotates through endpoints with available slots, so a large
// backlog for one IP doesn't occupy probe slots or need to be scanned.
// Endpoints over their limit wait in a second rotation for a borrowed slot;
// borrowing rotates too, so one backlog can't monopolize the idle capacity.
type pingQueue struct {
	limit, overflowLimit int
	ready                [2][]*pingEndpoint
	overflow             []*pingEndpoint
}

func (q *pingQueue) add(ep *pingEndpoint, phase PingPhase, jobs ...pingJob) {
	ep.jobs[phase] = append(ep.jobs[phase], jobs...)
	q.markReady(ep, phase)
}

func (q *pingQueue) markReady(ep *pingEndpoint, phase PingPhase) {
	if !ep.queued[phase] && q.canTake(ep, phase) {
		ep.queued[phase] = true
		q.ready[phase] = append(q.ready[phase], ep)
	}
	// A speed take can also push a busy endpoint over its limit while
	// latency work waits, so check overflow for every state change.
	if !ep.overflowing && q.canOverflow(ep) {
		ep.overflowing = true
		q.overflow = append(q.overflow, ep)
	}
}

func (q *pingQueue) canTake(ep *pingEndpoint, phase PingPhase) bool {
	if len(ep.jobs[phase]) == 0 {
		return false
	}
	if phase == PhaseSpeed {
		// A download overlaps in-flight latency probes (borrowed or
		// normal), so ep.active can pass the limit, but only concurrent
		// downloads contend for the endpoint's bandwidth: the speed gate
		// bounds activeSpeed within the same ceiling the no-overlap code
		// allowed. Gating on ep.active instead would starve a queued
		// download until the whole overlapping backlog drains.
		if ep.activeSpeed >= q.limit {
			return false
		}
	} else if ep.active >= q.limit {
		return false
	}
	// With one endpoint slot, let the scheduler alternate phases. With more
	// slots, reserve one for latency whenever latency work is queued.
	return phase == PhaseLatency || q.limit == 1 || len(ep.jobs[PhaseLatency]) == 0 || ep.activeSpeed < q.limit-1
}

// canOverflow reports whether an endpoint that already reached its limit has
// latency work for a borrowed global slot, within the capped burst. Endpoints
// with queued or active downloads never borrow: their freed slots must go to
// those downloads, which the relaxed speed gate then admits promptly.
func (q *pingQueue) canOverflow(ep *pingEndpoint) bool {
	if len(ep.jobs[PhaseSpeed]) > 0 || ep.activeSpeed > 0 {
		return false
	}
	return len(ep.jobs[PhaseLatency]) > 0 && ep.active >= q.limit && ep.active < q.overflowLimit
}

func (q *pingQueue) take(phase PingPhase) (pingJob, *pingEndpoint) {
	for len(q.ready[phase]) > 0 {
		ready := q.ready[phase]
		ep := ready[0]
		ready[0] = nil
		if len(ready) == 1 {
			q.ready[phase] = ready[:0]
		} else {
			q.ready[phase] = ready[1:]
		}
		ep.queued[phase] = false
		// Since the endpoint queued, other jobs may have arrived or started.
		if !q.canTake(ep, phase) {
			// A latency backlog that lost its normal slot may have become
			// eligible to borrow one instead.
			q.markReady(ep, phase)
			continue
		}
		jobs := ep.jobs[phase]
		j := jobs[0]
		jobs[0] = pingJob{}
		ep.jobs[phase] = jobs[1:]
		ep.active++
		if phase == PhaseSpeed {
			ep.activeSpeed++
		}
		q.markReady(ep, phase)
		return j, ep
	}
	return pingJob{}, nil
}

// takeOverflow borrows a slot for one latency job from an endpoint at its
// limit. The scheduler only calls it when a normal take would leave the
// global budget idle.
func (q *pingQueue) takeOverflow() (pingJob, *pingEndpoint) {
	for len(q.overflow) > 0 {
		ready := q.overflow
		ep := ready[0]
		ready[0] = nil
		q.overflow = ready[1:]
		ep.overflowing = false
		// The endpoint may have dropped below its limit or lost its jobs
		// since it queued here.
		if !q.canOverflow(ep) {
			continue
		}
		jobs := ep.jobs[PhaseLatency]
		j := jobs[0]
		jobs[0] = pingJob{}
		ep.jobs[PhaseLatency] = jobs[1:]
		ep.active++
		q.markReady(ep, PhaseLatency)
		return j, ep
	}
	return pingJob{}, nil
}

func (q *pingQueue) release(ep *pingEndpoint, phase PingPhase) {
	ep.active--
	if phase == PhaseSpeed {
		ep.activeSpeed--
	}
	q.markReady(ep, PhaseLatency)
	q.markReady(ep, PhaseSpeed)
}
