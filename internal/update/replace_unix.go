//go:build !windows

package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/knocking4thcylinder/proxy-router/internal/secpath"
)

// replaceBinary writes src over target atomically: a temporary file in the
// same directory, then a rename. A running proxy-router keeps executing
// the old, now unlinked file until it restarts.
func replaceBinary(target, src string) error {
	real, err := resolveBinary(target)
	if err != nil {
		return err
	}
	// Root must not be tricked into writing a user-controlled executable.
	// Replacing the system service's own root-owned copy passes; a sudo
	// `proxy-router update` of the user's binary doesn't.
	if os.Geteuid() == 0 {
		if _, err := secpath.CheckFile(real, 0); err != nil {
			return fmt.Errorf("refusing to replace %s as root: %w (run \"proxy-router update\" as your user)", real, err)
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(real), "."+filepath.Base(real)+".new-")
	if err != nil {
		return fmt.Errorf("replace %s: %w", real, err)
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, real); err != nil {
		return fmt.Errorf("replace %s: %w", real, err)
	}
	name = ""
	return nil
}
