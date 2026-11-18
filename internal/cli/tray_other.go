//go:build !linux && !(darwin && cgo)

package cli

import (
	"errors"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

func trayCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tray",
		Short: "Show a tray icon (menu bar icon on macOS) to control proxy-router",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "darwin" {
				return errors.New("this build has no menu bar icon: it was built without cgo (install Xcode's command line tools and rebuild)")
			}
			return errors.New("the tray icon is only available on Linux and macOS")
		},
	}
}

// elevated would run argv as root after a password dialog; there's none
// in this build.
func elevated(argv []string) *exec.Cmd { return nil }
