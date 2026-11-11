package update

import (
	"fmt"
	"os"
	"path/filepath"
)

// resolveBinary returns the real path of an executable to replace: the
// symlink target, made absolute, and checked to be a regular file.
func resolveBinary(target string) (string, error) {
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	if real, err = filepath.Abs(real); err != nil {
		return "", err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s isn't a regular file", real)
	}
	return real, nil
}
