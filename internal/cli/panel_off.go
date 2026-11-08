//go:build !(cgo && (linux || darwin))

package cli

import "github.com/spf13/cobra"

// panelCmd is only in builds without cgo: the window needs cgo and
// OpenGL, which CGO_ENABLED=0 builds do without.
func panelCmd() *cobra.Command { return nil }

// panelAvailable says whether this build has the control window.
func panelAvailable() bool { return false }
