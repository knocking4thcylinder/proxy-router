package tun

import "strings"

// macOS route handling that doesn't need macOS, so it's tested anywhere.

// netstatDest is how `netstat -rn` prints a split route's destination.
var netstatDest = map[string]string{
	"0.0.0.0/1":   "0/1",
	"128.0.0.0/1": "128.0/1",
	"::/1":        "::/1",
	"8000::/1":    "8000::/1",
}

// bsdRouteArgs are the `route` arguments that add r. Reject routes go
// through lo0, so they never match sockets bound to the physical
// interface.
func bsdRouteArgs(r route, name string) []string {
	if r.reject {
		gw := "127.0.0.1"
		if r.family == "inet6" {
			gw = "::1"
		}
		return []string{"-q", "-n", "add", "-" + r.family, "-net", r.prefix, gw, "-reject"}
	}
	return []string{"-q", "-n", "add", "-" + r.family, "-net", r.prefix, "-interface", name}
}

func bsdDeleteArgs(r route) []string {
	return []string{"-q", "-n", "delete", "-" + r.family, "-net", r.prefix}
}

// splitRoutes finds r's destination in `netstat -rn` output and reports
// whether it's there and whether it's ours: on the TUN (name), or a reject
// route on lo0 (macOS can't tag routes, so any such route is taken to be
// ours; nothing else installs them for half the address space). With an
// empty name only reject routes count as ours.
func splitRoute(netstat string, r route, name string) (present, ours bool, desc string) {
	dest := netstatDest[r.prefix]
	for _, line := range strings.Split(netstat, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != dest {
			continue
		}
		gateway, flags, iface := f[1], f[2], f[3]
		ours = (name != "" && iface == name) || (iface == "lo0" && strings.ContainsAny(flags, "RB"))
		return true, ours, dest + " via " + gateway + " (" + iface + ")"
	}
	return false, false, ""
}
