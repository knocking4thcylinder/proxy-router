// Package service installs proxy-router as a background service that starts
// automatically: launchd on macOS, systemd on Linux.
//
// There are two kinds. TUN mode needs root, so it runs as a system service
// (LaunchDaemon / systemd system unit) started at boot. Proxy-only mode runs
// as the user (LaunchAgent / systemd user unit) and starts at login.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Name identifies the service to launchd (label) and systemd (unit name).
const (
	Label = "io.github.knocking4thcylinder.proxy-router"
	Unit  = "proxy-router.service"
)

// ErrUnsupported is returned on systems without a supported service manager.
var ErrUnsupported = errors.New("background service isn't supported on this system; use \"proxy-router run\"")

// Scope says who runs the service.
type Scope string

const (
	User   Scope = "user"   // the logged-in user; starts at login
	System Scope = "system" // root; starts at boot
)

// Target is one service definition: a scope, and for user services, whose.
type Target struct {
	Scope Scope
	// User owns a user-scope service; may differ from the current user when
	// running as root under sudo.
	User *user.User
}

func (t Target) String() string {
	if t.Scope == System {
		return "system service"
	}
	return "user service"
}

// Status describes an installed service.
type Status struct {
	Installed bool // the definition file exists
	Enabled   bool // starts automatically (at boot or login)
	Running   bool
	PID       int
}

// Spec is what Install writes.
type Spec struct {
	Target
	Binary string   // path to run
	Args   []string // arguments after the binary
}

// InstallBinary copies the running executable to the service's own
// location, so rebuilding or moving the build output doesn't touch the
// running service, and a root service never runs a user-writable file.
// Returns the destination path.
func InstallBinary(t Target) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	if src, err = filepath.EvalSymlinks(src); err != nil {
		return "", err
	}
	dst := BinaryPath(t)
	if same, _ := sameContents(src, dst); same {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	// Write a new file and rename it over the old one: the running service
	// keeps executing its (now unlinked) copy until it restarts.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".proxy-router.*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	if t.Scope == User {
		chownTo(t.User, filepath.Dir(dst), dst)
	}
	return dst, nil
}

// UpToDate reports whether s is installed exactly as given, with the
// running executable's build.
func UpToDate(s Spec) bool {
	data, err := os.ReadFile(DefinitionPath(s.Target))
	return err == nil && bytes.Equal(data, Definition(s)) && !Outdated(s.Target)
}

// Outdated reports whether the installed binary differs from the running
// executable.
func Outdated(t Target) bool {
	src, err := os.Executable()
	if err != nil {
		return false
	}
	same, err := sameContents(src, BinaryPath(t))
	return err == nil && !same
}

func sameContents(a, b string) (bool, error) {
	fa, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	fb, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(fa, fb), nil
}

// writeOwned writes a definition file, owned by the target's user for user
// services (we may be root under sudo).
func writeOwned(t Target, path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	if t.Scope == User {
		chownTo(t.User, filepath.Dir(path), path)
	}
	return nil
}

func chownTo(u *user.User, paths ...string) {
	if u == nil || os.Geteuid() != 0 {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, p := range paths {
		_ = os.Lchown(p, uid, gid)
	}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			s = err.Error()
		}
		return s, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), s)
	}
	return s, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
