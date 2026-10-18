package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/netif"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// runStatus is what a running proxy-router (foreground or service) reports
// in status.json for "proxy-router status".
type runStatus struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Service bool      `json:"service"`
	// State is "waiting" (for network, or for another VPN to disconnect)
	// or "running".
	State   string `json:"state"`
	Waiting string `json:"waiting,omitempty"`
	Mode    string `json:"mode"` // "tun" or "proxy"
	TUN     string `json:"tun,omitempty"`
	Via     string `json:"via,omitempty"`
	Note    string `json:"note,omitempty"`
	Server  string `json:"server,omitempty"`
	Socks   string `json:"socks,omitempty"`
	HTTP    string `json:"http,omitempty"`
}

var processStart = time.Now()

// systemRunDir holds status.json while proxy-router runs as root (the TUN
// service's RuntimeDirectory on Linux), so root never writes to the
// user's directory. "status" and the tray read it as the user.
func systemRunDir() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/proxy-router"
	}
	return "/run/proxy-router"
}

// outsidePath is the TUN service's unix socket handing out sockets that
// leave around the TUN (see tun.ServeOutside).
func outsidePath() string { return filepath.Join(systemRunDir(), "outside.sock") }

// statusPath is where this process reports its status.
func statusPath(dir string) string {
	if os.Geteuid() == 0 {
		return filepath.Join(systemRunDir(), "status.json")
	}
	return filepath.Join(dir, "status.json")
}

// logPath is the user service's log; the TUN service logs to the journal
// (Linux) or service.SystemLog (macOS).
func logPath(dir string) string { return filepath.Join(dir, "proxy-router.log") }

func describeRun(e *env, o runOptions, state, waiting string) runStatus {
	st := runStatus{
		PID: os.Getpid(), Started: processStart, Service: o.service,
		State: state, Waiting: waiting, Mode: "proxy",
		Socks: e.cfg.Listen.Socks, HTTP: e.cfg.Listen.HTTP,
		Server: "(none)",
	}
	if o.server != "" {
		if en, err := e.state.Find(o.server); err == nil {
			st.Server = en.String()
		}
	} else if cur, ok := e.state.Current(); ok {
		st.Server = cur.String()
	}
	if o.tunName != "" {
		st.Mode, st.TUN = "tun", o.tunName
		st.Via, _ = netif.Physical(o.tunName)
	} else if iface, note := e.outboundInterface(); note != "" {
		st.Note = note
	} else {
		st.Via = iface
	}
	return st
}

func writeRunStatus(dir string, st runStatus) {
	data, _ := json.MarshalIndent(st, "", "  ")
	perm := os.FileMode(0o600)
	if os.Geteuid() == 0 {
		// Readable by the user; it says no more than "ip route" does.
		perm = 0o644
		if !systemRunDirOK() {
			return
		}
	}
	_ = config.WriteFileAtomic(statusPath(dir), append(data, '\n'), perm)
}

// removeRunStatus deletes status.json if it's this process's.
func removeRunStatus(dir string) {
	if st, ok := readRunStatus(dir); ok && st.PID == os.Getpid() {
		_ = os.Remove(statusPath(dir))
	}
}

// readRunStatus returns the status of a live proxy-router process: one
// running as root (the TUN service), or else the user's.
func readRunStatus(dir string) (runStatus, bool) {
	if st, ok := parseRunStatus(os.ReadFile(filepath.Join(systemRunDir(), "status.json"))); ok {
		return st, true
	}
	return parseRunStatus(config.ReadUserFile(dir, "status.json"))
}

func parseRunStatus(data []byte, err error) (runStatus, bool) {
	var st runStatus
	if err != nil || json.Unmarshal(data, &st) != nil {
		return st, false
	}
	return st, st.PID == os.Getpid() || service.Alive(st.PID)
}

// waitForUplink checks TUN mode's preconditions: a network connection, and
// no other VPN holding the default route. The service waits them out (both
// are normal right after boot or login); in the foreground they're errors.
// stop is true when interrupted while waiting.
func waitForUplink(ctx context.Context, dir string, o runOptions) (stop bool, err error) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	shown := ""
	for {
		reason := ""
		if d, _ := netif.Detect(); d.Tunnel != "" && !o.force {
			if !o.service {
				return false, fmt.Errorf(`another VPN (%s) owns the default route, e.g. Happ, Hiddify or a WireGuard tunnel.
Two VPNs that both capture all traffic break each other's routing and DNS.
Disconnect it first (closing its window isn't enough; on macOS "scutil --nc list"
shows what's connected), or pass --force to start anyway`, d.Tunnel)
			}
			reason = fmt.Sprintf("another VPN (%s) owns the default route; disconnect it", d.Tunnel)
		} else if _, err := netif.Physical(""); err != nil {
			if !o.service {
				return false, err
			}
			reason = "no network connection"
		}
		if reason == "" {
			return false, nil
		}
		if reason != shown {
			shown = reason
			fmt.Printf("%s waiting: %s\n", time.Now().Format(time.TimeOnly), reason)
			writeRunStatus(dir, runStatus{
				PID: os.Getpid(), Started: processStart, Service: o.service,
				State: "waiting", Waiting: reason, Mode: "tun",
			})
		}
		select {
		case <-ctx.Done():
			return true, nil
		case <-sigs:
			return true, nil
		case <-time.After(3 * time.Second):
		}
	}
}
