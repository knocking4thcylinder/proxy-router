//go:build darwin

package cli

import "os/exec"

// sudoersThenSudo is Linux only: on macOS elevated writes the rule in the
// same AppleScript that runs the action (see tray_darwin.go).
func sudoersThenSudo([]string) (*exec.Cmd, error) { return nil, nil }
