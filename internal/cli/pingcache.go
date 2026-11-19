package cli

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

const (
	// pingCacheFile holds measured ping results in the config directory so
	// separate processes ("use --fastest", the panel) reuse them.
	pingCacheFile = "ping-cache.json"
	// pingCacheFresh matches the panel's in-memory reuse window
	// (panelRescan, 5 minutes): a record younger than this can be picked
	// without probing again.
	pingCacheFresh = 5 * time.Minute
	// pingCacheOrder is how long a record still orders probes (previously
	// fastest first) once it is too old to reuse directly.
	pingCacheOrder = 24 * time.Hour
)

// pingKey identifies an entry across the panel's results and the cache.
func pingKey(group, name string) string { return group + "\x00" + name }

// pingCacheRecord is one server's last measurement. Server is a fingerprint
// of the measured server, so a replaced server under the same name reads as
// stale instead of handing its successor an old result.
type pingCacheRecord struct {
	Server   string        `json:"server"`
	Speed    float64       `json:"speed,omitempty"` // bytes per second
	SpeedErr string        `json:"speed_err,omitempty"`
	Latency  time.Duration `json:"latency"` // nanoseconds
	Err      string        `json:"err,omitempty"`
	At       time.Time     `json:"at"`
}

// pingCache is ping-cache.json.
type pingCache struct {
	Version int                        `json:"version"`
	At      time.Time                  `json:"at"`      // last write
	Records map[string]pingCacheRecord `json:"records"` // by pingKey
}

// serverFingerprint identifies the server behind a name: Outbound, Chain and
// Pool are exactly what currentScanWinner compares, so a replaced server
// yields a different fingerprint while a reloaded one keeps its records.
// share.Server's pointers and warnings never enter it, so the fingerprint
// survives the JSON round-trip through state.json and ping-cache.json.
func serverFingerprint(s *share.Server) string {
	if s == nil {
		return ""
	}
	id, err := json.Marshal(struct {
		Outbound json.RawMessage   `json:"outbound"`
		Chain    []json.RawMessage `json:"chain,omitempty"`
		Pool     *share.Pool       `json:"pool,omitempty"`
	}{s.Outbound, s.Chain, s.Pool})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:])
}

// loadPingCache reads the cache tolerantly: a missing or corrupt file, or an
// unknown format version, is an empty cache and never an error.
func loadPingCache(dir string) pingCache {
	data, err := os.ReadFile(filepath.Join(dir, pingCacheFile))
	if err != nil {
		return pingCache{Version: 1}
	}
	var c pingCache
	if json.Unmarshal(data, &c) != nil || c.Version != 1 {
		return pingCache{Version: 1}
	}
	return c
}

// savePingCache merges records into ping-cache.json, preserving untouched
// ones, and writes it atomically. A CLI scan and the panel's scan completion
// can write concurrently from two processes: the merge is read-modify-write,
// so the later write drops the earlier one's new records. That only costs
// those records a re-probe, so there is no cross-process lock.
func savePingCache(dir string, records map[string]pingCacheRecord) {
	if dir == "" || len(records) == 0 {
		return
	}
	c := loadPingCache(dir)
	if c.Records == nil {
		c.Records = make(map[string]pingCacheRecord, len(records))
	}
	for k, r := range records {
		c.Records[k] = r
	}
	c.Version, c.At = 1, time.Now()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	_ = config.WriteFileAtomic(filepath.Join(dir, pingCacheFile), data, 0o600)
}

// cacheableResult says whether r is definitive enough to cache: in speed
// mode the download must have really finished (a canceled one says nothing
// about the server), and a failed latency probe is a definitive negative.
func cacheableResult(r engine.PingResult, speedTest bool) bool {
	if r.Err != nil {
		return true
	}
	if speedTest {
		return finalSpeed(r)
	}
	return r.Latency > 0
}

// finalSpeed says a speed update is a real measurement, not the cancellation
// of a download that never ran.
func finalSpeed(r engine.PingResult) bool {
	return r.Speed > 0 || r.SpeedErr != nil && !errors.Is(r.SpeedErr, context.Canceled)
}

// pingCacheErr restores a cached error: the stall and too-slow sentinels keep
// their identity (summaries match on errors.Is), anything else only needs
// its message.
func pingCacheErr(s string) error {
	switch s {
	case "":
		return nil
	case engine.ErrStalled.Error():
		return engine.ErrStalled
	case engine.ErrTooSlow.Error():
		return engine.ErrTooSlow
	}
	return errors.New(s)
}

// cacheRecord turns a definitive result into a cache record, stamped at.
func cacheRecord(r engine.PingResult, at time.Time) pingCacheRecord {
	rec := pingCacheRecord{
		Server:  serverFingerprint(r.Entry.Server),
		Speed:   r.Speed,
		Latency: r.Latency,
		At:      at,
	}
	if r.Err != nil {
		rec.Err = r.Err.Error()
	}
	if r.SpeedErr != nil {
		switch {
		case errors.Is(r.SpeedErr, engine.ErrStalled):
			rec.SpeedErr = engine.ErrStalled.Error()
		case errors.Is(r.SpeedErr, engine.ErrTooSlow):
			rec.SpeedErr = engine.ErrTooSlow.Error()
		default:
			rec.SpeedErr = r.SpeedErr.Error()
		}
	}
	return rec
}

// cacheResult rebuilds a result for the current entry from a record. The
// caller has already checked the fingerprint, so the identity holds.
func cacheResult(en config.Entry, rec pingCacheRecord) engine.PingResult {
	return engine.PingResult{
		Entry:    en,
		Latency:  rec.Latency,
		Err:      pingCacheErr(rec.Err),
		Speed:    rec.Speed,
		SpeedErr: pingCacheErr(rec.SpeedErr),
	}
}

// fastestPlan is one "use --fastest" run shaped by the cache: fresh entries
// are reused without probing, the rest are probed, previously fastest first.
type fastestPlan struct {
	seed  []engine.PingResult // fresh usable cached samples on current entries
	probe []config.Entry      // stale or unknown entries, fastest-cached first
	total int                 // every entry in the group, for notes
}

// planFastest partitions entries against the cache: a fresh usable record
// (same server, measured within the reuse window) competes without probing,
// while stale-but-recent records order the probing by their last measured
// speed, so the budget reaches untested servers first and repeated runs
// converge to full coverage. Unknown or replaced entries keep config order
// behind the cached ones.
func planFastest(entries []config.Entry, cache pingCache, now time.Time) fastestPlan {
	type cached struct {
		en    config.Entry
		speed float64
	}
	var fresh []engine.PingResult
	var stale []cached
	var unknown []config.Entry
	for _, en := range entries {
		rec, ok := cache.Records[pingKey(en.Group, en.Server.Name)]
		if ok && rec.Server == serverFingerprint(en.Server) {
			switch age := now.Sub(rec.At); {
			case age < pingCacheFresh:
				fresh = append(fresh, cacheResult(en, rec))
				continue
			case age < pingCacheOrder:
				stale = append(stale, cached{en, rec.Speed})
				continue
			}
		}
		unknown = append(unknown, en)
	}
	slices.SortStableFunc(stale, func(a, b cached) int { return cmp.Compare(b.speed, a.speed) })
	plan := fastestPlan{seed: fresh, total: len(entries)}
	for _, c := range stale {
		plan.probe = append(plan.probe, c.en)
	}
	plan.probe = append(plan.probe, unknown...)
	return plan
}

// scanSamples accumulates progress snapshots into definitive per-entry
// results for the cache. Snapshots are cumulative, so the newest wins.
type scanSamples map[int]*scanSample

type scanSample struct {
	r           engine.PingResult
	latencyDone bool
	speedDone   bool
	at          time.Time
}

func (s scanSamples) add(p engine.PingProgress) {
	sample := s[p.Result.Entry.Index]
	if sample == nil {
		sample = &scanSample{}
		s[p.Result.Entry.Index] = sample
	}
	sample.r = p.Result
	switch {
	case p.Phase == engine.PhaseLatency && p.EntryDone:
		sample.latencyDone, sample.at = true, time.Now()
	case p.Phase == engine.PhaseSpeed && finalSpeed(p.Result):
		sample.speedDone, sample.at = true, time.Now()
	}
}

// records filters the samples down to what the cache keeps: only entries
// whose probes finished, first occurrence of a duplicate name wins (matching
// how State.Current resolves it).
func (s scanSamples) records(speedTest bool) map[string]pingCacheRecord {
	records := make(map[string]pingCacheRecord, len(s))
	for _, sample := range s {
		// An unreachable entry never downloads; its failure is final.
		if !sample.latencyDone || speedTest && sample.r.Err == nil && !sample.speedDone {
			continue
		}
		if !cacheableResult(sample.r, speedTest) {
			continue
		}
		k := pingKey(sample.r.Entry.Group, sample.r.Entry.Server.Name)
		if _, ok := records[k]; !ok {
			records[k] = cacheRecord(sample.r, sample.at)
		}
	}
	return records
}

// saveScanCache records a finished (exhaustive) scan in the ping cache.
func saveScanCache(dir string, results []engine.PingResult, speedTest bool, at time.Time) {
	records := make(map[string]pingCacheRecord, len(results))
	for _, r := range results {
		if !cacheableResult(r, speedTest) {
			continue
		}
		k := pingKey(r.Entry.Group, r.Entry.Server.Name)
		if _, ok := records[k]; !ok {
			records[k] = cacheRecord(r, at)
		}
	}
	savePingCache(dir, records)
}
