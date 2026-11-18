//go:build cgo

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

func TestMacOSTUNDialogCompiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires AppleScript")
	}
	argv := []string{"/Users/alice/proxy-router", "--dir", "/Users/alice/.config/proxy-router", "--uid", "501", "start", "--tun"}
	cmd := exec.Command("/usr/bin/osacompile", "-o", filepath.Join(t.TempDir(), "dialog.scpt"), "-e", elevated(argv).Args[2])
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile authorization dialog: %v\n%s", err, out)
	}
}

func TestMacOSTUNRuleSetup(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "proxy-router's binary")
	helper := `#!/bin/sh
case "$5" in
start|restart)
    printf '%s\n' "$5"
    exit "$ACTION_STATUS" ;;
stop)
    printf 'stop\n' ;;
tray)
    printf 'rule setup failed\n' >&2
    exit 7 ;;
esac
`
	if err := os.WriteFile(bin, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, action, flag, actionStatus, wantOutput string
		wantExit                                     int
	}{
		{"initial connect", "start", "--tun", "0", "start\nrule setup failed\n", 0},
		{"failed connect", "start", "--tun", "5", "start\n", 5},
		{"restart", "restart", "--tun", "0", "restart\nrule setup failed\n", 0},
		{"stop before migration", "stop", "--system", "0", "stop\n", 0},
		{"proxy mode", "start", "--no-tun", "0", "start\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := []string{bin, "--dir", "/Users/alice/.config/proxy-router", "--uid", "501", tc.action, tc.flag}
			cmd := exec.Command("/bin/sh", "-c", elevatedShell(argv))
			cmd.Env = append(os.Environ(), "ACTION_STATUS="+tc.actionStatus)
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Run(); cmd.ProcessState.ExitCode() != tc.wantExit || out.String() != tc.wantOutput {
				t.Fatalf("run: %v, output %q, want exit %d and %q", err, out.String(), tc.wantExit, tc.wantOutput)
			}
		})
	}
	installed := service.BinaryPath(service.Target{Scope: service.System})
	argv := []string{installed, "--dir", "/Users/alice/.config/proxy-router", "--uid", "501", "stop", "--system"}
	if got := elevatedShell(argv); got == shellWords(argv) {
		t.Fatal("stopping the installed TUN service should also repair its authorization rule")
	}
}
