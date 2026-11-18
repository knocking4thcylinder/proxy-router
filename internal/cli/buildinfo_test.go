//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryVersion(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("version reporting for user executables is tested without root")
	}
	dir := t.TempDir()
	write := func(name, out string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho '"+out+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}

	path := write("proxy-router", "proxy-router version v9.9.9")
	if v, ok := binaryVersion(path); !ok || v != "v9.9.9" {
		t.Errorf("binaryVersion = %q, %v; want v9.9.9, true", v, ok)
	}
	// A dev build has no release version to compare.
	dev := write("dev", "proxy-router version dev-abc123")
	if v, ok := binaryVersion(dev); ok {
		t.Errorf("binaryVersion(dev) = %q, %v; want no version", v, ok)
	}
	if newerBinary(dev) {
		t.Error("a dev build was reported as a newer release")
	}
	if !newerBinary(path) {
		t.Error("v9.9.9 wasn't reported as newer than this test build")
	}
}

func TestVersionProbePath(t *testing.T) {
	path := "proxy-router"
	if got, err := versionProbePath(path, 1000); err != nil || got != path {
		t.Fatalf("user probe path = %q, %v; want %q", got, err, path)
	}
	if got, err := versionProbePath(path, 0); err == nil || got != "" {
		t.Fatalf("root accepted a relative probe path: %q, %v", got, err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if got, err := versionProbePath(missing, 0); err == nil || got != "" {
		t.Fatalf("root accepted an unverified absolute probe path: %q, %v", got, err)
	}
}
