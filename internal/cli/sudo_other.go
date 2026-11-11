//go:build !darwin && !linux

package cli

import (
	"errors"
	"os/exec"
)

// passwordlessSudo is nil: only macOS and Linux get the sudoers rule.
func passwordlessSudo([]string) *exec.Cmd { return nil }

func sudoersThenSudo([]string) (*exec.Cmd, error) { return nil, nil }

func allowSudo() error { return errors.New("--allow-sudo is only used on macOS and Linux") }
