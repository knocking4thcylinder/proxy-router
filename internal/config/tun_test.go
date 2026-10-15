package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadYAML(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(dir)
}

func TestTUNDefaults(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !c.TUN.KillSwitch || c.TUN.IPv6 {
		t.Fatalf("tun = %+v", c.TUN)
	}
	// Leaving it out of an existing config.yaml keeps it on.
	if c, err = loadYAML(t, "tun:\n  enabled: true\n"); err != nil || !c.TUN.KillSwitch {
		t.Fatalf("tun = %+v, %v", c.TUN, err)
	}
	if c, err = loadYAML(t, "tun:\n  kill_switch: false\n"); err != nil || c.TUN.KillSwitch {
		t.Fatalf("tun = %+v, %v", c.TUN, err)
	}
}

func TestTUNName(t *testing.T) {
	if _, err := loadYAML(t, "tun:\n  name: utun42\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`'x" accept'`, `"tun0; flush ruleset"`, "averyveryverylongname"} {
		if _, err := loadYAML(t, "tun:\n  name: "+bad+"\n"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
