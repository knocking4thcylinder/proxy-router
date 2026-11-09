package config

import (
	"testing"
	"time"
)

func TestAutoUpdateConfig(t *testing.T) {
	cases := []struct {
		yaml     string
		enabled  bool
		interval time.Duration
	}{
		{"", true, 24 * time.Hour},
		{"auto_update:\n  interval: 6h\n", true, 6 * time.Hour},
		{"auto_update:\n  enabled: false\n", false, 24 * time.Hour},
		{"auto_update:\n  enabled: false\n  interval: 0\n", false, 0},
		{"auto_update:\n  interval: 0\n", false, 0},
	}
	for _, c := range cases {
		cfg, err := loadYAML(t, c.yaml)
		if err != nil {
			t.Errorf("%q: %v", c.yaml, err)
			continue
		}
		if a := cfg.AutoUpdate; a.Enabled != c.enabled || a.Interval.D() != c.interval {
			t.Errorf("%q: enabled %v, interval %s; want %v, %s", c.yaml, a.Enabled, a.Interval.D(), c.enabled, c.interval)
		}
	}
	for _, bad := range []string{
		"auto_update:\n  interval: 5m\n",
		"auto_update:\n  interval: nope\n",
	} {
		if _, err := loadYAML(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
