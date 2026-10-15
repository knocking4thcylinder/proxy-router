//go:build !darwin

package cli

import (
	"errors"
	"os/exec"
)

// passwordlessSudo is nil: only macOS gets the sudoers rule (Linux has
// polkit; see packaging/linux).
func passwordlessSudo([]string) *exec.Cmd { return nil }

func allowSudo() error { return errors.New("--allow-sudo is only used on macOS") }
