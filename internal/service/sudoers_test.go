package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSudoersRuleLints checks the rule with visudo, including the space in
// the macOS binary path and the commands the tray allows on both systems.
func TestSudoersRuleLints(t *testing.T) {
	for _, c := range []struct {
		name, bin, dir string
	}{
		{"macOS", "/Library/Application Support/proxy-router/proxy-router", "/Users/alice/.config/proxy-router"},
		{"Linux", "/var/lib/proxy-router/proxy-router", "/home/alice/.config/proxy-router"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rule, err := sudoersRule("alice", c.bin, [][]string{
				{"--dir", c.dir, "--uid", "1000", "start", "--tun"},
				{"--dir", c.dir, "--uid", "1000", "stop", "--system"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := exec.LookPath("visudo"); err != nil {
				t.Skip("no visudo")
			}
			path := filepath.Join(t.TempDir(), "proxy-router")
			if err := os.WriteFile(path, []byte(rule), 0o440); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("visudo", "-c", "-q", "-f", path).CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s\n%s", err, out, rule)
			}
		})
	}
}

func TestSudoersRuleRejects(t *testing.T) {
	for _, c := range []struct {
		user, bin string
		args      []string
	}{
		{"alice", "/bin/proxy-router", []string{"--dir", "/Users/alice/My Config"}},
		{"alice", "/bin/proxy-router", []string{"--dir", "/x,/y"}},
		{"alice", "/bin/proxy-router", []string{"--dir", "/x*"}},
		{"alice", "/bin/proxy-router", []string{"stop\nroot ALL=(ALL) NOPASSWD: ALL"}},
		{"%admin", "/bin/proxy-router", []string{"stop"}},
		{"alice", "/bin/proxy:router", []string{"stop"}},
	} {
		if rule, err := sudoersRule(c.user, c.bin, [][]string{c.args}); err == nil {
			t.Errorf("%q %q %q: no error\n%s", c.user, c.bin, c.args, rule)
		}
	}
}
