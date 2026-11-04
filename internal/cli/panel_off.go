//go:build !(panel && (linux || (darwin && cgo)))

package cli

import "github.com/spf13/cobra"

// panelCmd is only in builds with the panel tag: the window needs cgo and
// OpenGL, which the plain build does without.
func panelCmd() *cobra.Command { return nil }

// panelAvailable says whether this build has the control window.
func panelAvailable() bool { return false }
