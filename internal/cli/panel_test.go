//go:build cgo && (linux || darwin)

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
