package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestTargetUIDFrom(t *testing.T) {
	for _, c := range []struct {
		flag, pkexec, sudo string
		want               string
		bad                bool
	}{
		{},
		{flag: "1000", want: "1000"}, // the service unit, or osascript
		{flag: "1000", pkexec: "1000", want: "1000"},
		{flag: "1000", sudo: "1000", want: "1000"},
		{flag: "1000", pkexec: "1001", bad: true}, // --uid can't pick another user
		{flag: "1000", sudo: "1001", bad: true},
		{flag: "0", sudo: "1000", bad: true},
		{sudo: "1000", want: "1000"}, // plain "sudo proxy-router ..."
		{pkexec: "1000", want: "1000"},
		{pkexec: "1000", sudo: "1001", bad: true},
		{flag: "1000\n", bad: true},
		{flag: "-1", bad: true},
		{flag: "../1000", bad: true},
		{sudo: "x", bad: true},
		{flag: "01000", want: "1000"},
	} {
		env := map[string]string{"PKEXEC_UID": c.pkexec, "SUDO_UID": c.sudo}
		got, err := targetUIDFrom(c.flag, func(k string) string { return env[k] })
		if c.bad != (err != nil) || got != c.want {
			t.Errorf("%+v: got %q, %v", c, got, err)
		}
	}
}

func TestTargetUserNotRoot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	defer SetTargetUID("")
	t.Setenv("SUDO_UID", "0") // ignored when not root
	for uid, bad := range map[string]bool{"": false, strconv.Itoa(os.Getuid()): false, strconv.Itoa(os.Getuid() + 1): true} {
		SetTargetUID(uid)
		u, err := TargetUser()
		if u != nil || bad != (err != nil) {
			t.Errorf("--uid %q: %v, %v", uid, u, err)
		}
	}
}

func TestCheckDirNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("not root only")
	}
	// Not root: nothing to check, even for a world-writable directory.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckDir(dir); err != nil || got != dir {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestCheckDirRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	defer SetTargetUID("")
	SetTargetUID("")
	t.Setenv("SUDO_UID", "")
	t.Setenv("PKEXEC_UID", "")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDir(filepath.Join(dir, "a", "b")); err != nil {
		t.Fatalf("missing directory under a safe one: %v", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDir(dir); err == nil {
		t.Fatal("accepted a group-writable directory")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDir(dir); err == nil {
		t.Fatal("accepted another user's directory")
	}
}
