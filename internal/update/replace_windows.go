//go:build windows

package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// replaceBinary replaces target with src. A running .exe can be renamed
// but not overwritten, so the old one is moved aside first.
func replaceBinary(target, src string) error {
	real, err := resolveBinary(target)
	if err != nil {
		return err
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
	if err := tmp.Close(); err != nil {
		return err
	}

	// A .old left by an earlier update may still be running (Windows
	// won't delete it until that process exits), so pick a free name
	// instead of failing on it.
	old := real + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		old = fmt.Sprintf("%s.old-%d", real, os.Getpid())
	}
	if err := os.Rename(real, old); err != nil {
		return fmt.Errorf("replace %s: %w", real, err)
	}
	if err := os.Rename(name, real); err != nil {
		// Put the old binary back so this doesn't leave nothing to run.
		if rerr := os.Rename(old, real); rerr != nil {
			return fmt.Errorf("replace %s: %w (and couldn't restore the old one: %v)", real, err, rerr)
		}
		return fmt.Errorf("replace %s: %w", real, err)
	}
	name = ""
	// The old process may still be running from this file; Windows lets it
	// be deleted once it exits. A leftover is harmless.
	_ = os.Remove(old)
	return nil
}
