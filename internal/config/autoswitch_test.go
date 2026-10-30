package config

import (
	"testing"
	"time"
)

// Auto-switching is on by default. Files from when every server was checked
// on a timer still load; their "interval: 0" still turns it off.
func TestAutoSwitchConfig(t *testing.T) {
	cases := []struct {
		yaml    string
		enabled bool
		stall   time.Duration
	}{
		{"", true, 10 * time.Second},
		{"auto_switch:\n  stall: 5s\n", true, 5 * time.Second},
		{"auto_switch:\n  enabled: false\n", false, 10 * time.Second},
		{"auto_switch:\n  interval: 1m\n  failures: 2\n  timeout: 15s\n", true, 10 * time.Second},
		{"auto_switch:\n  interval: 0\n", false, 10 * time.Second},
	}
	for _, c := range cases {
		cfg, err := loadYAML(t, c.yaml)
		if err != nil {
			t.Errorf("%q: %v", c.yaml, err)
			continue
		}
		if a := cfg.AutoSwitch; a.Enabled != c.enabled || a.Stall.D() != c.stall {
			t.Errorf("%q: enabled %v, stall %s; want %v, %s", c.yaml, a.Enabled, a.Stall.D(), c.enabled, c.stall)
		}
	}
	for _, bad := range []string{"auto_switch:\n  stall: 1s\n", "auto_switch:\n  interval: 5s\n"} {
		if _, err := loadYAML(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
