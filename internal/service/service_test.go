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
