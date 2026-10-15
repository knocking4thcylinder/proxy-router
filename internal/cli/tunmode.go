package cli

import (
	"fmt"
	"os"

	"github.com/knocking4thcylinder/proxy-router/internal/tun"
)

// tunOptions is what TUN mode applies for e's config.
func tunOptions(e *env, name string) tun.Options {
	t := e.cfg.TUN
	return tun.NewOptions(name, t.IPv6, t.KillSwitch, e.cfg.SystemRoute)
}

// clearTUN removes what TUN mode leaves in place when the service stops
// (the kill switch) or crashes. It's how "proxy-router stop" always gets
// the network back. Needs root; a TUN run in the foreground keeps its own.
func clearTUN() {
	if os.Geteuid() != 0 {
		return
	}
	if dir, err := configDir(); err == nil {
		if st, ok := readRunStatus(dir); ok && !st.Service && st.Mode == "tun" {
			return
		}
	}
	if err := tun.Cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, "TUN: can't remove the kill switch:", err)
	}
}
