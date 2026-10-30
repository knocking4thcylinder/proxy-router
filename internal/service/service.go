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
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knocking4thcylinder/proxy-router/internal/secpath"
)

// Name identifies the service to launchd (label) and systemd (unit name).
const (
	Label = "io.github.knocking4thcylinder.proxy-router"
	Unit  = "proxy-router.service"
)

// ErrUnsupported is returned on systems without a supported service manager.
var ErrUnsupported = errors.New("background service isn't supported on this system; use \"proxy-router run --foreground\"")

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

// Check rejects specs that can't be written safely: the service files are
// line-oriented, and a newline in an argument (say, in a crafted --dir)
// would add directives to them.
func (s Spec) Check() error {
	for _, a := range append([]string{s.Binary}, s.Args...) {
		if !utf8.ValidString(a) {
			return fmt.Errorf("service argument %q isn't valid UTF-8", a)
		}
		if strings.IndexFunc(a, unicode.IsControl) >= 0 {
			return fmt.Errorf("service argument %q contains control characters", a)
		}
	}
	return nil
}

// errUserFilesAsRoot keeps root from writing in directories the user
// controls, where symlinks could point the writes anywhere.
var errUserFilesAsRoot = errors.New("a user service's files are changed as that user, not as root")

// InstallBinary copies the running executable to the service's own
// location, so rebuilding or moving the build output doesn't touch the
// running service, and a root service never runs a user-writable file.
// Returns the destination path.
func InstallBinary(t Target) (string, error) {
	if t.Scope == User && os.Geteuid() == 0 {
		return "", errUserFilesAsRoot
	}
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
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	// A new file renamed over the old one: the running service keeps
	// executing its (now unlinked) copy until it restarts.
	return dst, writeAtomic(dst, in, 0o755)
}

// RootBinary returns the system service's copy of proxy-router if it's
// safe to run as root: a regular file that only root can change, in
// directories only root can change.
func RootBinary() (string, error) {
	path := BinaryPath(Target{Scope: System})
	if path == "" {
		return "", ErrUnsupported
	}
	return secpath.CheckFile(path, 0)
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

// writeDefinition writes a service definition file. User services' files
// are only written by that user.
func writeDefinition(t Target, path string, data []byte) error {
	if t.Scope == User && os.Geteuid() == 0 {
		return errUserFilesAsRoot
	}
	return writeAtomic(path, bytes.NewReader(data), 0o644)
}

// writeAtomic writes path through a temp file in the same directory and a
// rename, so it replaces a symlink at path rather than writing where it
// points, and readers never see a partial file.
func writeAtomic(path string, r io.Reader, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// rootPath is where commands are looked up when running as root, instead
// of an inherited $PATH.
const rootPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// command is exec.Command, but as root it only runs programs from
// rootPath and passes that PATH on.
func command(name string, args ...string) *exec.Cmd {
	if os.Geteuid() != 0 || filepath.IsAbs(name) {
		return exec.Command(name, args...)
	}
	cmd := exec.Command(rootLookPath(name), args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+rootPath)
	return cmd
}

// rootLookPath finds name in rootPath. A missing program yields a path
// that doesn't exist, so running it fails instead of searching $PATH.
func rootLookPath(name string) string {
	dirs := filepath.SplitList(rootPath)
	for _, dir := range dirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return filepath.Join(dirs[0], name)
}

func run(name string, args ...string) (string, error) {
	out, err := command(name, args...).CombinedOutput()
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
