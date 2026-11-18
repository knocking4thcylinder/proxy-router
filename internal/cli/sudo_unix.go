//go:build darwin || linux

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// passwordlessSudo returns a sudo command running argv when the sudoers
// listing permits it, else nil. Listing can succeed even when execution
// requires authentication; runSudoWithFallback handles that. The rule only
// covers the TUN service's root-owned copy of proxy-router with one of
// sudoActions; "sudo -n -l" asks whether it allows argv without running
// anything. It's the same rule on macOS and Linux.
func passwordlessSudo(argv []string) *exec.Cmd {
	if !sudoAction(argv) || argv[0] != service.BinaryPath(service.Target{Scope: service.System}) {
		return nil
	}
	// Some distributions restrict access to the sudoers directory. In
	// that case sudo can check the rule even when we can't stat it.
	if _, err := os.Stat(service.SudoersPath); err != nil && !os.IsPermission(err) {
		return nil
	}
	if exec.Command("sudo", append([]string{"-n", "-l"}, argv...)...).Run() != nil {
		return nil
	}
	return exec.Command("sudo", append([]string{"-n"}, argv...)...)
}

// allowSudo handles the macOS password dialog's "tray --allow-sudo".
func allowSudo() error {
	if os.Geteuid() != 0 {
		return errors.New("writing the sudoers rule has to run as root")
	}
	if flagDir == "" {
		return errors.New("writing the sudoers rule needs --dir")
	}
	// Root only works with a directory its user alone can change.
	if _, err := configDir(); err != nil {
		return err
	}
	u, err := config.TargetUser()
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("writing the sudoers rule needs --uid")
	}
	dir, err := filepath.Abs(flagDir)
	if err != nil {
		return err
	}
	return service.AllowSudo(u, sudoArgLists(dir, u.Uid))
}
