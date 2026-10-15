package cli

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestSudoAuthenticationFallback(t *testing.T) {
	for _, tc := range []struct {
		name, script, stderr string
		fallback, fails      bool
	}{
		{"success", "exit 0", "", false, false},
		{"authentication required", "echo 'sudo: a password is required' >&2; exit 1", "", true, false},
		{"command failed", "echo 'startup failed' >&2; exit 1", "startup failed\n", false, true},
		{"other sudo error", "echo 'sudo: command not allowed' >&2; exit 1", "sudo: command not allowed\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", tc.script)
			var output bytes.Buffer
			cmd.Stderr = &output
			called := false
			err := runSudoWithFallback(cmd, func() *exec.Cmd {
				called = true
				return exec.Command("sh", "-c", "exit 0")
			})
			if called != tc.fallback || (err != nil) != tc.fails || output.String() != tc.stderr {
				t.Fatalf("fallback=%v err=%v stderr=%q", called, err, output.String())
			}
		})
	}
}

func TestSudoDialogFailure(t *testing.T) {
	cmd := exec.Command("sh", "-c", "echo 'sudo: a password is required' >&2; exit 1")
	err := runSudoWithFallback(cmd, func() *exec.Cmd {
		return exec.Command("sh", "-c", "exit 7")
	})
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 7 {
		t.Fatalf("dialog failure lost: %v", err)
	}
}

func TestSudoAction(t *testing.T) {
	bin, dir := "/Library/Application Support/proxy-router/proxy-router", "/Users/u/.config/proxy-router"
	argv := func(action ...string) []string {
		return append([]string{bin, "--dir", dir, "--uid", "501"}, action...)
	}
	for _, ok := range [][]string{argv("start", "--tun"), argv("stop", "--system")} {
		if !sudoAction(ok) {
			t.Errorf("%q isn't allowed", ok)
		}
	}
	for _, bad := range [][]string{
		argv("start", "--tun", "--force"), argv("restart", "--tun"), argv("uninstall", "--system"),
		argv("stop"), argv("start"), argv(), {bin, "--uid", "501", "--dir", dir, "stop", "--system"},
	} {
		if sudoAction(bad) {
			t.Errorf("%q is allowed", bad)
		}
	}
}
