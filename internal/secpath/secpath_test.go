//go:build !windows

package secpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	// TempDir sits under /tmp (sticky) or a per-user directory; both
	// pass as directories above.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	// In containers the filesystem root or an intermediate directory can
	// be owned by an unrelated uid (e.g. "nobody"), which Check rightly
	// rejects. The ownership rules can't be exercised there, so skip
	// instead of asserting about an environment the test doesn't control.
	if !ownedBy(dir, me) {
		t.Skipf("ancestors of %s aren't owned by uid %d or root; skipping", dir, me)
	}
	if _, err := Check(dir, me); err != nil {
		t.Fatalf("own directory: %v", err)
	}

	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckFile(file, me); err != nil {
		t.Fatalf("own file: %v", err)
	}
	if _, err := CheckFile(dir, me); err == nil {
		t.Fatal("CheckFile accepted a directory")
	}

	// Symlinks are resolved and the target is what's checked.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if got, err := Check(link, me); err != nil || got != mustReal(t, file) {
		t.Fatalf("symlink: %q, %v", got, err)
	}

	for _, mode := range []os.FileMode{0o664, 0o646} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(file, me); err == nil || !strings.Contains(err.Error(), "other users") {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}

	// A writable directory above makes everything below it unsafe, and
	// the sticky bit doesn't excuse the path itself.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(sub, me); err == nil {
		t.Fatal("accepted a path under a world-writable directory")
	}
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(sub, me); err != nil {
		t.Fatalf("sticky directory above: %v", err)
	}
	if _, err := Check(dir, me); err == nil {
		t.Fatal("accepted a world-writable path")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Owned by someone else.
	if me != 0 {
		if _, err := Check(file, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
			t.Fatalf("other owner: %v", err)
		}
	}
	if _, err := Check(filepath.Join(dir, "missing"), me); err == nil {
		t.Fatal("accepted a missing path")
	}
}

func mustReal(t *testing.T, p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ownedBy walks p up to the filesystem root and reports whether every
// component is owned by uid or root. It mirrors the ownership half of
// Check, so the test can tell whether the environment lets it run.
func ownedBy(p string, uid int) bool {
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return false
		}
		owner, ok := ownerOf(fi)
		if !ok || (owner != uid && owner != 0) {
			return false
		}
		if parent := filepath.Dir(p); parent == p {
			return true
		} else {
			p = parent
		}
	}
}
