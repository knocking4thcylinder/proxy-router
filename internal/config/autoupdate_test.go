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
		channel  string
	}{
		{"", true, 24 * time.Hour, "auto"},
		{"auto_update:\n  interval: 6h\n", true, 6 * time.Hour, "auto"},
		{"auto_update:\n  enabled: false\n", false, 24 * time.Hour, "auto"},
		{"auto_update:\n  channel: nightly\n", true, 24 * time.Hour, "nightly"},
		{"auto_update:\n  channel: stable\n", true, 24 * time.Hour, "stable"},
		{"auto_update:\n  channel: auto\n", true, 24 * time.Hour, "auto"},
		{"auto_update:\n  enabled: false\n  interval: 0\n", false, 0, "auto"},
		{"auto_update:\n  interval: 0\n", false, 0, "auto"},
	}
	for _, c := range cases {
		cfg, err := loadYAML(t, c.yaml)
		if err != nil {
			t.Errorf("%q: %v", c.yaml, err)
			continue
		}
		if a := cfg.AutoUpdate; a.Enabled != c.enabled || a.Interval.D() != c.interval || a.Channel != c.channel {
			t.Errorf("%q: enabled %v, interval %s, channel %q; want %v, %s, %q",
				c.yaml, a.Enabled, a.Interval.D(), a.Channel, c.enabled, c.interval, c.channel)
		}
	}
	for _, bad := range []string{
		"auto_update:\n  interval: 5m\n",
		"auto_update:\n  interval: nope\n",
		"auto_update:\n  channel: beta\n",
	} {
		if _, err := loadYAML(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
