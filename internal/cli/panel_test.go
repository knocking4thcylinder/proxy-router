//go:build panel && (linux || (darwin && cgo))

package cli

import "testing"

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
