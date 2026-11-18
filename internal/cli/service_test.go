package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A malformed config stops start before it consults the service manager.
// An elevated start must leave the rest of the user's directory untouched.
func TestRootStartReadsConfigWithoutCreatingFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or a user namespace")
	}
	const configEnv = "PROXY_ROUTER_TEST_START_CONFIG_DIR"
	if dir := os.Getenv(configEnv); dir != "" {
		flagDir = dir
		err := startService(startOptions{tun: true}, false)
		if err == nil || !strings.Contains(err.Error(), "config.yaml:") {
			t.Fatalf("expected a config parse error, got %v", err)
		}
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("[\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Confinement lasts for the process, just as it does in the CLI.
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootStartReadsConfigWithoutCreatingFiles$")
	cmd.Env = append(os.Environ(), configEnv+"="+dir, "SUDO_UID=", "PKEXEC_UID=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "routing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected routing.yaml to remain absent, got %v", err)
	}
}

// TestStartArgs: the root half of a TUN start gets the mode spelled out
// and nothing that only the user's half uses.
func TestStartArgs(t *testing.T) {
	for _, c := range []struct {
		o       startOptions
		restart bool
		want    string
	}{
		{startOptions{}, false, "start --tun"},
		{startOptions{noTUN: true}, false, "start --tun"}, // only called for TUN mode
		{startOptions{force: true, verbose: 2}, true, "restart --tun --force -vv"},
		{startOptions{rules: "/tmp/my rules.yaml", server: "Germany", noUpdate: true, systemProxy: true}, false, "start --tun --rules /tmp/my rules.yaml --server Germany --system-proxy --no-update"},
	} {
		if got := strings.Join(c.o.args(c.restart), " "); got != c.want {
			t.Errorf("%+v restart=%v: %q, want %q", c.o, c.restart, got, c.want)
		}
	}
}
