//go:build darwin

package cli

import "github.com/knocking4thcylinder/proxy-router/internal/service"

// The macOS password dialog provisions the rule (see tray_darwin.go).
func allowInstalledSudo(service.Target, string) {}
