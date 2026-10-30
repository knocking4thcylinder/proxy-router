//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareStatusDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	// This is what launchd's 0077 umask leaves behind.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !prepareStatusDir(dir, os.Getuid()) {
		t.Fatal("could not prepare the status directory")
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("status directory must be traversable by the tray: %v, %v", fi, err)
	}
	if !prepareStatusDir(dir, os.Getuid()) {
		t.Fatal("preparing the directory again failed")
	}
}

func TestPrepareStatusDirRejectsUnsafePaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if prepareStatusDir(dir, os.Getuid()+1) {
		t.Fatal("accepted a different owner")
	}
	link := dir + "-link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if prepareStatusDir(link, os.Getuid()) {
		t.Fatal("followed a symlink")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if prepareStatusDir(dir, os.Getuid()) {
		t.Fatal("accepted a directory writable by others")
	}
}
