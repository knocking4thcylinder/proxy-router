package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func readConfined(dir, name string, uid int, max int64) ([]byte, error) {
	return nil, errors.New("confined reads aren't supported on Windows")
}

// writeAtomic writes r to path through a temp file in the same directory.
func writeAtomic(path string, r io.Reader, perm os.FileMode, owner *ids) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, r)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	return n, os.Rename(tmp.Name(), path)
}
