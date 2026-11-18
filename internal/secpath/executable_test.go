//go:build !windows

package secpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckExecutable(t *testing.T) {
	// Treat the fixture as the filesystem root so ownership checks don't
	// depend on directories outside the test (such as a container's /tmp).
	root := t.TempDir()
	for _, dir := range []string{"bin", "links", "writable"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "writable"), 0o775); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "bin", "proxy-router")
	if err := os.WriteFile(want, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mutable := filepath.Join(root, "mutable")
	if err := os.WriteFile(mutable, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mutable, 0o777); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"alias":          "/bin",
		"links/relative": "../alias/proxy-router",
		"writable/link":  "/bin/proxy-router",
		"unsafe-target":  "/writable/link",
		"loop":           "loop",
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/bin/proxy-router", "/alias/proxy-router", "/links/relative"} {
		if got, err := checkExecutable(path, root, os.Geteuid()); err != nil || got != want {
			t.Errorf("checkExecutable(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
	for _, path := range []string{"/data", "/bin", "/mutable", "/writable/link", "/unsafe-target", "/loop"} {
		if got, err := checkExecutable(path, root, os.Geteuid()); err == nil || got != "" {
			t.Errorf("checkExecutable(%q) accepted %q", path, got)
		}
	}
}
