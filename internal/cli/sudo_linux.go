//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// sudoersThenSudo writes the sudoers rule with this build in one password
// dialog, then returns the passwordless sudo command for argv. It handles
// a TUN service installed by an older build, whose copy of proxy-router
// can't write the rule itself: after this, connecting and disconnecting
// don't ask again. nil means it doesn't apply -- not a sudo action, no
// installed service, no sudo or pkexec, or this is the binary that would
// run anyway (elevated adds --write-sudoers to it instead).
func sudoersThenSudo(argv []string) (*exec.Cmd, error) {
	if !sudoAction(argv) {
		return nil, nil
	}
	installed := service.BinaryPath(service.Target{Scope: service.System})
	if argv[0] != installed {
		return nil, nil
	}
	if _, err := os.Stat(installed); err != nil {
		return nil, nil
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		return nil, nil
	}
	if _, err := exec.LookPath("pkexec"); err != nil {
		return nil, nil
	}
	// A config folder sudoers can't express (spaces, wildcard characters)
	// gets no rule; don't ask for a password that won't help.
	if !service.SudoersPossible(sudoArgLists(argv[2], argv[4])) {
		return nil, nil
	}
	self, err := selfExecutable()
	if err != nil || self == installed {
		return nil, nil
	}
	// sudoAction checked that argv starts with --dir dir --uid uid.
	cmd := exec.Command("pkexec", self, "--dir", argv[2], "--uid", argv[4], "tray", "--allow-sudo")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("write the sudoers rule: %w", err)
	}
	if c := passwordlessSudo(argv); c != nil {
		return c, nil
	}
	return nil, errors.New("wrote the sudoers rule, but sudo still doesn't allow the TUN service's copy")
}
