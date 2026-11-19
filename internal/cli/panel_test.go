//go:build cgo && (linux || darwin)

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestPanelFastestJoinsScanAndRevalidatesState(t *testing.T) {
	p, e := panelFastestFixture(t, true)
	synctest.Test(t, func(t *testing.T) {
		scan := p.fullScan
		p.testDone = make(chan struct{})
		scan.started = time.Now()
		entries := e.state.Entries()
		for i, en := range entries {
			p.testProgress(e.cfg, scan, engine.PingProgress{
				Phase: engine.PhaseSpeed, Result: engine.PingResult{Entry: en, Speed: float64(2 - i)},
			})
		}
		done := startPanelFastest(p)
		synctest.Wait()
		time.Sleep(fastestScanBudget - time.Millisecond)
		synctest.Wait()
		requirePanelFastestWaiting(t, done)

		// A subscription update can replace an endpoint under the same
		// name and persist unrelated state while the action is waiting.
		state, err := config.LoadState(p.t.dir)
		if err != nil {
			t.Fatal(err)
		}
		state.Manual[0].Port++
		state.HWID = "new-device-id"
		if err := state.Save(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
		got := awaitPanelFastest(t, done)
		if got.err != nil || got.name != "second" {
			t.Fatalf("selection at the deadline = %+v, want second", got)
		}
		if p.fullScan != scan || p.testDone == nil {
			t.Fatal("the full scan should still be filling the list")
		}
		state, err = config.LoadState(p.t.dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := (config.Selection{Group: config.ManualGroup, Name: "second", Auto: true}); state.Selected == nil || *state.Selected != want {
			t.Fatalf("saved selection = %+v, want %+v", state.Selected, want)
		}
		if state.HWID != "new-device-id" || state.Manual[0].Port != entries[0].Server.Port+1 {
			t.Fatalf("saving the selection discarded concurrent state changes: %+v", state)
		}
	})
}

func TestPanelFastestWaitsForUsableSampleOrExhaustion(t *testing.T) {
	tests := []struct {
		name      string
		speedTest bool
		exhaust   bool
		expired   bool
	}{
		{name: "late speed", speedTest: true, expired: true},
		{name: "latency only", expired: true},
		{name: "early exhaustion", speedTest: true, exhaust: true},
		{name: "late exhaustion", speedTest: true, exhaust: true, expired: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, e := panelFastestFixture(t, tt.speedTest)
			synctest.Test(t, func(t *testing.T) {
				scan := p.fullScan
				p.testDone = make(chan struct{})
				scan.started = time.Now()
				if tt.expired {
					scan.started = scan.started.Add(-fastestScanBudget)
				}
				en := e.state.Entries()[0]
				if tt.speedTest {
					r := engine.PingResult{Entry: en, Latency: time.Millisecond}
					p.testProgress(e.cfg, scan, engine.PingProgress{Result: r, EntryDone: true})
					r.SpeedErr = engine.ErrStalled
					p.testProgress(e.cfg, scan, engine.PingProgress{Phase: engine.PhaseSpeed, Result: r})
				}
				done := startPanelFastest(p)
				synctest.Wait()
				requirePanelFastestWaiting(t, done)

				switch {
				case tt.exhaust:
					p.finishTest(scan)
				case tt.speedTest:
					p.testProgress(e.cfg, scan, engine.PingProgress{
						Phase: engine.PhaseSpeed, Result: engine.PingResult{Entry: en, Speed: 5},
					})
				default:
					p.testProgress(e.cfg, scan, engine.PingProgress{
						EntryDone: true, Result: engine.PingResult{Entry: en, Latency: time.Millisecond},
					})
				}
				if got := awaitPanelFastest(t, done); got.err != nil || got.name != "first" {
					t.Fatalf("selection = %+v, want first", got)
				}
			})
		})
	}
}

func TestPanelFastestUsesRecentFullScanAndDefinitiveRechecks(t *testing.T) {
	p, e := panelFastestFixture(t, true)
	synctest.Test(t, func(t *testing.T) {
		scan := p.fullScan
		p.testDone = make(chan struct{})
		scan.started = time.Now()
		entries := e.state.Entries()
		for i, en := range entries {
			p.testProgress(e.cfg, scan, engine.PingProgress{
				Phase: engine.PhaseSpeed, Result: engine.PingResult{Entry: en, Speed: float64(2 - i)},
			})
		}
		p.finishTest(scan)
		finished := scan.finished

		p.testDone = make(chan struct{})
		result := engine.PingResult{Entry: entries[0], Latency: time.Millisecond}
		p.testProgress(e.cfg, nil, engine.PingProgress{Result: result, EntryDone: true})
		if got := awaitPanelFastest(t, startPanelFastest(p)); got.err != nil || got.name != "first" {
			t.Fatalf("selection during an unfinished recheck = %+v, want first", got)
		}
		result.SpeedErr = engine.ErrStalled
		p.testProgress(e.cfg, nil, engine.PingProgress{Phase: engine.PhaseSpeed, Result: result})
		if got := awaitPanelFastest(t, startPanelFastest(p)); got.err != nil || got.name != "second" {
			t.Fatalf("selection after a failed download = %+v, want second", got)
		}
		for _, en := range entries {
			p.testProgress(e.cfg, nil, engine.PingProgress{
				EntryDone: true, Result: engine.PingResult{Entry: en, Err: errors.New("latency failed")},
			})
		}
		if got := awaitPanelFastest(t, startPanelFastest(p)); got.err == nil || got.err.Error() != "no server responded" {
			t.Fatalf("selection after both servers failed = %+v, want an error", got)
		}
		p.finishTest(nil)
		if scan.finished != finished || scan.usable(e.cfg, finished.Add(panelRescan)) {
			t.Fatal("partial rechecks extended the full scan's freshness")
		}
	})
}

func TestPanelSeedsFullScanFromPingCache(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace bool
	}{
		{"instant pick", false},
		{"replaced server stays uncovered", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := panelFastestFixture(t, true)
			p.fullScan = nil
			entries := e.state.Entries()
			// A finished CLI scan left its measurements behind.
			second := pingCacheRecord{Server: serverFingerprint(entries[1].Server), Speed: 1e6, Latency: time.Millisecond, At: time.Now()}
			if tc.replace {
				second.Server = "another server"
			}
			savePingCache(p.t.dir, map[string]pingCacheRecord{
				pingKey(entries[0].Group, entries[0].Server.Name): {Server: serverFingerprint(entries[0].Server), Speed: 2e6, Latency: time.Millisecond, At: time.Now()},
				pingKey(entries[1].Group, entries[1].Server.Name): second,
			})

			if got := awaitPanelFastest(t, startPanelFastest(p)); got.err != nil || got.name != "first" {
				t.Fatalf("selection = %+v, want first straight from the cache", got)
			}
			if p.testDone != nil {
				t.Fatal("the seeded scan should serve the pick without starting a test")
			}
			// pick() still reports a replaced server as uncovered.
			if _, _, covered := p.fullScan.pick(entries); covered == tc.replace {
				t.Fatalf("covered = %v, want %v", covered, !tc.replace)
			}
			if !p.fullScan.usable(e.cfg, time.Now()) {
				t.Fatal("the seeded scan should be usable")
			}
		})
	}
}

func TestPanelWritesPingCacheOnScanCompletion(t *testing.T) {
	p, e := panelFastestFixture(t, true)
	scan := p.fullScan
	p.testDone = make(chan struct{})
	for i, en := range e.state.Entries() {
		p.testProgress(e.cfg, scan, engine.PingProgress{
			Phase: engine.PhaseSpeed, Result: engine.PingResult{Entry: en, Latency: time.Millisecond, Speed: float64(2 - i)},
		})
	}
	p.finishTest(scan)

	cache := loadPingCache(p.t.dir)
	if len(cache.Records) != 2 {
		t.Fatalf("cached %d records, want 2: %+v", len(cache.Records), cache.Records)
	}
	for _, en := range e.state.Entries() {
		rec, ok := cache.Records[pingKey(en.Group, en.Server.Name)]
		if !ok || rec.Server != serverFingerprint(en.Server) || rec.Speed == 0 {
			t.Fatalf("record for %s = %+v, want this scan's measurement", en.Server.Name, rec)
		}
	}
}

func panelFastestFixture(t *testing.T, speedTest bool) (*panel, *env) {
	t.Helper()
	t.Setenv("XRAY_LOCATION_ASSET", "")
	dir := t.TempDir()
	if !speedTest {
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("ping:\n  download_url: ''\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := loadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.state.Manual = []*share.Server{
		{Name: "first", Address: "127.0.0.1", Port: 8080},
		{Name: "second", Address: "127.0.0.1", Port: 8081},
	}
	if err := e.state.Save(); err != nil {
		t.Fatal(err)
	}
	e.state, err = config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &panel{
		t:        &tray{dir: dir},
		fullScan: &panelScan{cfg: e.cfg, results: make(map[string]engine.PingResult)},
		results:  make(map[string]engine.PingResult),
	}
	return p, e
}

type panelFastestOutcome struct {
	name string
	err  error
}

func startPanelFastest(p *panel) <-chan panelFastestOutcome {
	done := make(chan panelFastestOutcome, 1)
	go func() {
		best, err := p.useFastest()
		outcome := panelFastestOutcome{err: err}
		if best.Entry.Server != nil {
			outcome.name = best.Entry.Server.Name
		}
		done <- outcome
	}()
	return done
}

func requirePanelFastestWaiting(t *testing.T, done <-chan panelFastestOutcome) {
	t.Helper()
	select {
	case got := <-done:
		t.Fatalf("action returned before it could select from the scan: %+v", got)
	default:
	}
}

func awaitPanelFastest(t *testing.T, done <-chan panelFastestOutcome) panelFastestOutcome {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(time.Second):
		t.Fatal("action did not return after a usable result became available")
		return panelFastestOutcome{}
	}
}

func TestScanNoteShowsOverlappingProgress(t *testing.T) {
	at := time.Now().Add(-2 * time.Minute)
	tests := []struct {
		name                               string
		testing                            bool
		done, total, speedDone, speedTotal int
		want                               string
	}{
		{"idle", false, 0, 0, 0, 0, "tested 2 min ago · ↻"},
		{"latency only", true, 3, 10, 0, 0, "testing 3/10…"},
		{"overlap", true, 3, 10, 1, 2, "3/10 · speeds 1/2…"},
		{"speed total grew", true, 4, 10, 2, 5, "4/10 · speeds 2/5…"},
		{"latency done", true, 10, 10, 2, 4, "speeds 2/4…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanNote(tt.testing, tt.done, tt.total, tt.speedDone, tt.speedTotal, at)
			if got != tt.want {
				t.Fatalf("scanNote() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFreezeCountriesKeepsOrderAndSplit(t *testing.T) {
	ok := []panelCountry{
		{trayCountry: trayCountry{flag: "🇨🇭", name: "Switzerland"}, working: 2},
		{trayCountry: trayCountry{flag: "🇫🇮", name: "Finland"}, working: 1},
	}
	dead := []panelCountry{
		{trayCountry: trayCountry{flag: "🇩🇪", name: "Germany"}},
	}
	order := countryOrder(ok, dead)

	// Mid-scan: Switzerland's servers all time out and Germany recovers,
	// so a fresh sort puts Germany first and Switzerland on the dead
	// side. The rows must stay where the user saw them.
	midOK := []panelCountry{dead[0], ok[1]}
	midOK[0].working = 1
	midDead := []panelCountry{ok[0]}
	midDead[0].working = 0
	frozenOK, frozenDead := freezeCountries(order, midOK, midDead)
	if len(frozenOK) != 2 || frozenOK[0].name != "Switzerland" || frozenOK[1].name != "Finland" {
		t.Fatalf("working rows moved: %+v", frozenOK)
	}
	if len(frozenDead) != 1 || frozenDead[0].name != "Germany" {
		t.Fatalf("dead rows moved: %+v", frozenDead)
	}
}

func TestToggleActionAfterFocusLoss(t *testing.T) {
	now := time.Now()
	p := &panel{}
	if got := p.toggleAction(now); got != panelToggleShow {
		t.Fatalf("closed panel: got %v, want show", got)
	}

	p.open = true
	if got := p.toggleAction(now); got != panelToggleHide {
		t.Fatalf("open panel: got %v, want hide", got)
	}

	// The tray click that took focus away is already handled by dismiss;
	// its toggle must not reopen the panel.
	p.open = false
	p.autoHideAt = now.Add(-panelToggleGrace / 2)
	if got := p.toggleAction(now); got != panelToggleIgnore {
		t.Fatalf("toggle right after focus loss: got %v, want ignore", got)
	}

	p.autoHideAt = now.Add(-panelToggleGrace - time.Millisecond)
	if got := p.toggleAction(now); got != panelToggleShow {
		t.Fatalf("toggle after the grace period: got %v, want show", got)
	}

	// An open panel wins over the grace window: the click closes it.
	p.open = true
	p.autoHideAt = now.Add(-panelToggleGrace / 2)
	if got := p.toggleAction(now); got != panelToggleHide {
		t.Fatalf("open panel within grace: got %v, want hide", got)
	}
}

func TestFreezeCountriesAppendsNewRows(t *testing.T) {
	ok := []panelCountry{{trayCountry: trayCountry{flag: "🇨🇭", name: "Switzerland"}, working: 1}}
	order := countryOrder(ok, nil)

	added := []panelCountry{
		{trayCountry: trayCountry{flag: "🇫🇮", name: "Finland"}, working: 1},
		ok[0],
	}
	frozenOK, _ := freezeCountries(order, added, nil)
	if len(frozenOK) != 2 || frozenOK[0].name != "Switzerland" || frozenOK[1].name != "Finland" {
		t.Fatalf("new row isn't last: %+v", frozenOK)
	}
}

func TestReadSwitchesReadsTailAndCaches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-router.log")
	var log strings.Builder
	log.WriteString("2026-01-01 00:00:00 auto-switch: #1 old/old stopped working; switching to #2 old/old (1 ms)\n")
	// Push the older line out of the tail that readSwitches reads.
	for i := 0; i < 300<<10/8; i++ {
		log.WriteString("padding\n")
	}
	log.WriteString("2026-02-02 12:34:56 auto-switch: #3 g/from stopped working; switching to #4 g/to (7 ms)\n")
	if err := os.WriteFile(path, []byte(log.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readSwitches(path, 2)
	if len(got) != 1 || got[0].from != "from" || got[0].to != "to" {
		t.Fatalf("tail read = %+v, want the recent switch only", got)
	}
	// An unchanged file reuses the cached result.
	if again := readSwitches(path, 2); len(again) != 1 || again[0] != got[0] {
		t.Fatalf("cached read = %+v, want %+v", again, got)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("2026-02-02 12:35:56 auto-switch: #4 g/to stopped working; switching to #5 g/new (8 ms)\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got = readSwitches(path, 2)
	if len(got) != 2 || got[0].from != "to" || got[0].to != "new" {
		t.Fatalf("after append = %+v, want newest first", got)
	}
}
