//go:build !windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// confineForTest confines to dir as the current user, undoing it after.
func confineForTest(t *testing.T, dir string) {
	t.Helper()
	Confine(dir, os.Getuid(), filepath.Join(t.TempDir(), "assets"))
	t.Cleanup(func() { confined = confinement{} })
}

func write(t *testing.T, path, data string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "proxy-router")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadConfined(t *testing.T) {
	dir := privateDir(t)
	uid := os.Getuid()
	outside := filepath.Join(t.TempDir(), "secret")
	write(t, outside, "secret", 0o600)
	write(t, filepath.Join(dir, "config.yaml"), "log_level: info\n", 0o600)
	write(t, filepath.Join(dir, "rules", "r.yaml"), "default: direct\n", 0o600)
	write(t, filepath.Join(dir, "open.yaml"), "x", 0o600)
	if err := os.Chmod(filepath.Join(dir, "open.yaml"), 0o666); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "big"), strings.Repeat("x", 100), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	if data, err := readConfined(dir, "config.yaml", uid, 1<<20); err != nil || string(data) != "log_level: info\n" {
		t.Fatalf("config.yaml: %q, %v", data, err)
	}
	if _, err := readConfined(dir, "rules/r.yaml", uid, 1<<20); err != nil {
		t.Fatalf("subdirectory: %v", err)
	}
	if _, err := readConfined(dir, "missing", uid, 1<<20); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v, want ErrNotExist", err)
	}
	for name, want := range map[string]string{
		"link.yaml":      "symlink",
		"linkdir/secret": "linkdir", // ENOTDIR or ELOOP
		"fifo":           "regular file",
		"open.yaml":      "writable by other users",
		"big":            "larger than",
		"../secret":      "inside",
		"/etc/passwd":    "inside",
		"rules/../../x":  "inside",
	} {
		_, err := readConfined(dir, name, uid, 50)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, want)
		}
	}
	if _, err := readConfined(dir, "config.yaml", uid+1, 1<<20); err == nil || !strings.Contains(err.Error(), "belongs to uid") {
		t.Errorf("other owner: %v", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfined(dir, "config.yaml", uid, 1<<20); err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Errorf("group-writable directory: %v", err)
	}
}

func TestConfinedLoad(t *testing.T) {
	dir := privateDir(t)
	confineForTest(t, dir)

	// Missing files: defaults and an empty state, like before.
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.AssetDir() != confined.assetDir {
		t.Errorf("AssetDir = %s, want the root-owned %s", c.AssetDir(), confined.assetDir)
	}
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Save: %v, want ErrReadOnly", err)
	}
	if err := WriteFileAtomic(filepath.Join(dir, "status.json"), []byte("{}"), 0o600); err == nil {
		t.Error("WriteFileAtomic wrote into the confined directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state.json was written: %v", err)
	}

	for _, rules := range []string{"/etc/passwd", "~/routing.yaml", "../routing.yaml"} {
		write(t, filepath.Join(dir, "config.yaml"), "rules: "+rules+"\n", 0o600)
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "only reads rules files inside") {
			t.Errorf("rules: %s: %v", rules, err)
		}
	}
	write(t, filepath.Join(dir, "config.yaml"), "rules: sub/routing.yaml\n", 0o600)
	write(t, filepath.Join(dir, "sub", "routing.yaml"), "default: direct\n", 0o600)
	c, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(c.RulesPath()); err != nil {
		t.Errorf("rules in a subdirectory: %v", err)
	}
	if _, err := LoadRules("/etc/passwd"); err == nil {
		t.Error("LoadRules read a file outside the directory")
	}

	// Values from the file don't end up in error messages.
	write(t, filepath.Join(dir, "config.yaml"), "log_level: [hunter2]\n", 0o600)
	if _, err := Load(dir); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error echoes the value: %v", err)
	}

	// A symlinked state.json isn't followed.
	outside := filepath.Join(t.TempDir(), "state.json")
	write(t, outside, `{"hwid":"x"}`, 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil {
		t.Error("LoadState followed a symlink")
	}
}

func TestReadUserFileConfined(t *testing.T) {
	dir := privateDir(t)
	write(t, filepath.Join(dir, "status.json"), "{}", 0o600)
	if _, err := ReadUserFile(dir, "status.json"); err != nil && os.Geteuid() != 0 {
		t.Fatal(err)
	}
	confineForTest(t, dir)
	if _, err := ReadUserFile(dir, "status.json"); err == nil {
		t.Error("the TUN service read status.json from the user's directory")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := privateDir(t)
	outside := filepath.Join(t.TempDir(), "target")
	write(t, outside, "original", 0o644)
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(outside); string(data) != "original" {
		t.Errorf("wrote through the symlink: %q", data)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("state.json: %v, want a regular 0600 file", fi.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}

	// New directories are private.
	nested := filepath.Join(t.TempDir(), "new", "status.json")
	if err := WriteFileAtomic(nested, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Dir(nested)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("new directory: %v, %v; want 0700", fi.Mode(), err)
	}
}
