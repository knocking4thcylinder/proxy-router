package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// DefinitionPath is the systemd unit file.
func DefinitionPath(t Target) string {
	if t.Scope == System {
		return "/etc/systemd/system/" + Unit
	}
	return filepath.Join(t.User.HomeDir, ".config", "systemd", "user", Unit)
}

// BinaryPath is where the service's copy of proxy-router lives. /var/lib
// rather than /usr/local: /usr is read-only on SteamOS and other immutable
// systems.
func BinaryPath(t Target) string {
	if t.Scope == System {
		return "/var/lib/proxy-router/proxy-router"
	}
	return filepath.Join(t.User.HomeDir, ".local", "share", "proxy-router", "proxy-router")
}

// systemctl runs systemctl for the target: the system manager, the user's
// own manager, or (as root under sudo) another user's manager.
func systemctl(t Target, args ...string) (string, error) {
	if t.Scope == User {
		if os.Geteuid() == 0 {
			args = append([]string{"--user", "--machine=" + t.User.Username + "@"}, args...)
		} else {
			args = append([]string{"--user"}, args...)
		}
	}
	return run("systemctl", args...)
}

// quote escapes one ExecStart argument. Install rejects control
// characters (Spec.Check); should one get here anyway it's written as a C
// escape, never raw, so it can't start a new line of the unit.
func quote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return strings.ContainsRune(" \t\"'\\$%;", r) || unicode.IsControl(r)
	}) < 0 {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '$':
			b.WriteString("$$")
		case r == '%':
			b.WriteString("%%")
		case unicode.IsControl(r) && r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Definition is the unit file Install writes for s.
func Definition(s Spec) []byte {
	var cmd []string
	for _, a := range append([]string{s.Binary}, s.Args...) {
		cmd = append(cmd, quote(a))
	}
	wantedBy, after := "default.target", ""
	if s.Scope == System {
		wantedBy = "multi-user.target"
		after = "Wants=network-online.target\nAfter=network-online.target\n"
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=proxy-router
%s
[Service]
ExecStart=%s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=%s
`, after, strings.Join(cmd, " "), wantedBy))
}

// Install writes the unit, enables it at boot/login and (re)starts it.
func Install(s Spec) error {
	if err := s.Check(); err != nil {
		return err
	}
	if err := writeDefinition(s.Target, DefinitionPath(s.Target), Definition(s)); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", Unit}, {"restart", Unit}} {
		if _, err := systemctl(s.Target, args...); err != nil {
			return err
		}
	}
	return nil
}

// Stop stops the service and keeps it from starting at boot/login.
func Stop(t Target) error {
	if !exists(DefinitionPath(t)) {
		return nil
	}
	// systemctl stop waits for the process to exit.
	_, err := systemctl(t, "disable", "--now", Unit)
	return err
}

// Remove stops the service and deletes its files.
func Remove(t Target) error {
	if t.Scope == User && os.Geteuid() == 0 {
		return errUserFilesAsRoot
	}
	if err := Stop(t); err != nil {
		return err
	}
	if err := os.Remove(DefinitionPath(t)); err != nil && !os.IsNotExist(err) {
		return err
	}
	_, _ = systemctl(t, "daemon-reload")
	_ = os.RemoveAll(filepath.Dir(BinaryPath(t)))
	return nil
}

// Query reports the service's state.
func Query(t Target) (Status, error) {
	st := Status{Installed: exists(DefinitionPath(t))}
	if !st.Installed {
		return st, nil
	}
	out, err := systemctl(t, "show", "-p", "ActiveState", "-p", "MainPID", "-p", "UnitFileState", Unit)
	if err != nil {
		return st, err
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "ActiveState":
			st.Running = v == "active" || v == "activating" || v == "reloading"
		case "MainPID":
			st.PID, _ = strconv.Atoi(v)
		case "UnitFileState":
			st.Enabled = v == "enabled"
		}
	}
	return st, nil
}
