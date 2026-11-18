package secpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckExecutable returns the resolved path of a regular executable owned by
// uid or root. It checks each directory and symlink before following it, so
// both the original path and the resolved path are protected from replacement
// by other users. Use the returned path when executing or opening the file.
func CheckExecutable(path string, uid int) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%q is not an absolute executable path", path)
	}
	volume := filepath.VolumeName(path)
	return checkExecutable(strings.TrimPrefix(path, volume), volume+string(filepath.Separator), uid)
}

func checkExecutable(path, root string, uid int) (string, error) {
	fi, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if err := checkOwner(root, fi, uid); err != nil {
		return "", err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s is not a trusted filesystem root", root)
	}

	sep := string(filepath.Separator)
	dir, pending := root, path
	for links := 0; pending != ""; {
		part, rest, more := strings.Cut(pending, sep)
		pending = rest
		switch part {
		case "", ".":
			continue
		case "..":
			if dir != root {
				dir = filepath.Dir(dir)
			}
			continue
		}
		p := filepath.Join(dir, part)
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if err := checkOwner(p, fi, uid); err != nil {
			return "", err
		}
		mode := fi.Mode()
		if mode&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", fmt.Errorf("%s: too many symlinks", path)
			}
			pending, err = os.Readlink(p)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(pending) {
				dir = root
			}
			if more {
				pending += sep + rest
			}
			continue
		}
		if mode.Perm()&0o022 != 0 {
			return "", fmt.Errorf("%s can be changed by other users", p)
		}
		if more && mode.IsDir() {
			dir = p
			continue
		}
		if !more && mode.IsRegular() && mode.Perm()&0o111 != 0 {
			return p, nil
		}
		return "", fmt.Errorf("%s is not a trusted executable path", p)
	}
	return "", fmt.Errorf("%s is not an executable", path)
}
