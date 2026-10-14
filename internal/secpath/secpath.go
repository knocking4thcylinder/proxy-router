// Package secpath checks that a path can't be swapped out from under a
// process running as root by some other user.
package secpath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Check resolves symlinks in path and checks that the result is owned by
// uid or root, and that neither it nor any directory above it can be
// changed by anyone but uid and root: each is owned by one of them and
// isn't writable by group or others (directories above may be, with the
// sticky bit, like /tmp). Returns the resolved path, which is what the
// caller should use from then on.
func Check(path string, uid int) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if real, err = filepath.Abs(real); err != nil {
		return "", err
	}
	for p, leaf := real, true; ; p, leaf = filepath.Dir(p), false {
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		owner, ok := ownerOf(fi)
		if !ok {
			return "", fmt.Errorf("%s: can't tell who owns it", p)
		}
		if owner != uid && owner != 0 {
			return "", fmt.Errorf("%s is owned by uid %d, not %s", p, owner, who(uid))
		}
		if fi.Mode().Perm()&0o022 != 0 && (leaf || fi.Mode()&fs.ModeSticky == 0) {
			return "", fmt.Errorf("%s can be changed by other users (mode %o); chmod go-w it", p, fi.Mode().Perm())
		}
		if parent := filepath.Dir(p); parent == p {
			return real, nil
		}
	}
}

// CheckFile is Check for a regular file.
func CheckFile(path string, uid int) (string, error) {
	real, err := Check(path, uid)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(real); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", errors.New(real + " isn't a regular file")
	}
	return real, nil
}

func who(uid int) string {
	if uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid %d or root", uid)
}
