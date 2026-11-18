package service

import (
	"errors"
	"io/fs"
	"testing"
)

func TestMacOSSystemBinaryPath(t *testing.T) {
	// A fresh machine has no installed service, so a missing binary is
	// fine. An unsafe existing ancestor would block passwordless elevation.
	path, err := RootBinary()
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if want := BinaryPath(Target{Scope: System}); err != nil || path != want {
		t.Fatalf("RootBinary() = %q, %v, want %q", path, err, want)
	}
}
