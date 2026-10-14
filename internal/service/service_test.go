package service

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDefinitionLints checks the generated plist / unit with the platform's
// own validator, including arguments that need quoting.
func TestDefinitionLints(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no service support")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []Scope{User, System} {
		s := Spec{
			Target: Target{Scope: scope, User: u},
			Binary: "/tmp/dir with space/proxy-router",
			Args:   []string{"--dir", "/home/a b/.config/proxy-router", "run", "--service", "--tun", `we"ird$%&<>`},
		}
		def := Definition(s)
		dir := t.TempDir()
		var cmd *exec.Cmd
		if runtime.GOOS == "darwin" {
			path := filepath.Join(dir, Label+".plist")
			if err := os.WriteFile(path, def, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd = exec.Command("plutil", "-lint", path)
		} else {
			path := filepath.Join(dir, Unit)
			if err := os.WriteFile(path, def, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := exec.LookPath("systemd-analyze"); err != nil {
				t.Skip("no systemd-analyze")
			}
			// verify needs the binary to exist.
			bin := filepath.Join(dir, "bin dir", "proxy-router")
			_ = os.MkdirAll(filepath.Dir(bin), 0o755)
			_ = os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
			s.Binary = bin
			if err := os.WriteFile(path, Definition(s), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd = exec.Command("systemd-analyze", "verify", "--man=no", path)
			if scope == User {
				cmd.Args = append(cmd.Args[:2], append([]string{"--user"}, cmd.Args[2:]...)...)
			}
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s\n%s", scope, err, out, def)
		}
		if strings.TrimSpace(string(out)) != "" && runtime.GOOS == "linux" {
			t.Fatalf("%s: %s\n%s", scope, out, def)
		}
	}
}

func TestSpecCheck(t *testing.T) {
	ok := Spec{Binary: "/var/lib/proxy-router/proxy-router", Args: []string{"--dir", "/home/a b/.config/pr $%\"'\\", "run"}}
	if err := ok.Check(); err != nil {
		t.Fatalf("rejected %q: %v", ok.Args, err)
	}
	for _, bad := range []string{
		"/home/u\n[Service]\nExecStartPre=/bin/sh -c id",
		"/home/u\r",
		"/home/u\x00",
		"/home/u\t",
		"/home/u\x1b[2J",
		"/home/u\x7f",
		"/home/u\u0085",
		"/home/u\xff",
	} {
		s := Spec{Binary: ok.Binary, Args: []string{"--dir", bad, "run"}}
		if err := s.Check(); err == nil {
			t.Errorf("accepted arg %q", bad)
		}
		s = Spec{Binary: bad, Args: ok.Args}
		if err := s.Check(); err == nil {
			t.Errorf("accepted binary %q", bad)
		}
	}
}

// TestWriteAtomicReplacesSymlink: a symlink at the destination is
// replaced, not written through.
func TestWriteAtomicReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "unit")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(dst, strings.NewReader("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("wrote through the symlink: %q", b)
	}
	if fi, err := os.Lstat(dst); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("destination isn't a regular file: %v %v", fi, err)
	}
}

func TestUserFilesNotAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	u := &user.User{Uid: "12345", Gid: "12345", Username: "nobody-test", HomeDir: t.TempDir()}
	tg := Target{Scope: User, User: u}
	if _, err := InstallBinary(tg); err == nil {
		t.Error("InstallBinary wrote a user's files as root")
	}
	if err := writeDefinition(tg, DefinitionPath(tg), nil); err == nil {
		t.Error("writeDefinition wrote a user's files as root")
	}
	if err := Remove(tg); err == nil {
		t.Error("Remove deleted a user's files as root")
	}
}

func TestRootLookPath(t *testing.T) {
	// A program planted in $PATH is never picked.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, name := range []string{"sh", "systemctl", "launchctl", "no-such-program"} {
		p := rootLookPath(name)
		if !strings.HasPrefix(p, "/usr/") && !strings.HasPrefix(p, "/sbin/") && !strings.HasPrefix(p, "/bin/") {
			t.Errorf("%s: %s is outside %s", name, p, rootPath)
		}
	}
	if p := rootLookPath("sh"); !exists(p) {
		t.Errorf("sh: %s doesn't exist", p)
	}
}
