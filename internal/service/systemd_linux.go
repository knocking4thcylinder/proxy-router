package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// quote escapes one ExecStart argument.
func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

// Definition is the unit file Install writes for s.
func Definition(s Spec) []byte {
	var cmd []string
	for _, a := range append([]string{s.Binary}, s.Args...) {
		cmd = append(cmd, quote(a))
	}
	wantedBy, after, hardening := "default.target", "", ""
	if s.Scope == System {
		wantedBy = "multi-user.target"
		after = "Wants=network-online.target\nAfter=network-online.target\n"
		hardening = systemHardening
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=proxy-router
%s
[Service]
ExecStart=%s
Restart=on-failure
RestartSec=3
%s
[Install]
WantedBy=%s
`, after, strings.Join(cmd, " "), hardening, wantedBy))
}

// systemHardening confines the root TUN service. It writes only to its
// StateDirectory (/var/lib/proxy-router: binary, geo files) and
// RuntimeDirectory (/run/proxy-router: status.json), logs to the journal
// and reads the user's config read-only. Capabilities: NET_ADMIN for the
// TUN device, routes and SO_MARK, NET_RAW for SO_BINDTODEVICE,
// NET_BIND_SERVICE for low listen ports, and DAC_READ_SEARCH to read the
// user's 0600 files in their 0700 home. No PrivateNetwork or
// PrivateDevices: it has to manage the host's network and /dev/net/tun.
const systemHardening = `StandardOutput=journal
StandardError=journal
StateDirectory=proxy-router
StateDirectoryMode=0755
RuntimeDirectory=proxy-router
RuntimeDirectoryMode=0755
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
`

// Install writes the unit, enables it at boot/login and (re)starts it.
func Install(s Spec) error {
	if err := writeOwned(s.Target, DefinitionPath(s.Target), Definition(s)); err != nil {
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
