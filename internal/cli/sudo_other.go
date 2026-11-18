//go:build !darwin && !linux

package cli

import (
	"os/exec"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// passwordlessSudo is nil: only macOS and Linux get the sudoers rule.
func passwordlessSudo([]string) *exec.Cmd { return nil }

func allowInstalledSudo(service.Target, string) {}
