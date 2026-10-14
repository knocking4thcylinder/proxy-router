// Package netif detects when another VPN's tunnel owns the default route,
// so proxy-router can send its own connections around it.
//
// A VPN can own it with a default route of its own, or with split routes
// (0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1) that beat the default route
// without replacing it. Both count, for IPv4 and IPv6.
package netif

import (
	"fmt"
	"strings"
)

// Route is a default route candidate.
type Route struct {
	Iface   string
	Gateway bool // has a real next-hop gateway (not a point-to-point link)
	// Addr is the next hop as printed by netstat (BSD only).
	Addr string
	// Scoped routes (macOS "I" flag) only apply to sockets bound to Iface.
	Scoped bool
}

// Detection is the result of inspecting default routes.
type Detection struct {
	// Tunnel is the VPN interface holding the default route, if any.
	Tunnel string
	// Physical is the interface to bind to so traffic bypasses Tunnel.
	Physical string
}

// isTunnel reports interface names used by VPN/TUN software.
func isTunnel(name string) bool {
	for _, p := range []string{"utun", "tun", "prtun", "tap", "wg", "ipsec", "ppp", "gif", "stf"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// isVirtual reports interfaces that are never a useful uplink.
func isVirtual(name string) bool {
	for _, p := range []string{"lo", "bridge", "awdl", "llw", "anpi", "ap", "docker", "veth", "virbr", "vmnet"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// pick decides from default routes ordered by priority (active first).
func pick(routes []Route) Detection {
	if len(routes) == 0 || !isTunnel(routes[0].Iface) {
		return Detection{}
	}
	return Detection{Tunnel: routes[0].Iface, Physical: physical(routes, "")}
}

// physical returns the first real uplink among routes, skipping exclude.
func physical(routes []Route, exclude string) string {
	for _, r := range routes {
		if r.Gateway && r.Iface != exclude && !isTunnel(r.Iface) && !isVirtual(r.Iface) {
			return r.Iface
		}
	}
	return ""
}

// Physical returns the real uplink (e.g. en0) whether or not a VPN is in
// front of it. TUN mode binds to it so its own traffic can't loop.
func Physical(exclude string) (string, error) {
	routes, err := defaultRoutes()
	if err != nil {
		return "", err
	}
	if r, ok := uplink(routes, exclude); ok {
		return r.Iface, nil
	}
	if p := physical(routes, exclude); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("no physical network interface with a default route")
}

// uplink returns the physical interface holding the system-wide (unscoped)
// default route, and that route's gateway.
func uplink(routes []Route, exclude string) (Route, bool) {
	for _, r := range routes {
		if !r.Scoped && r.Gateway && r.Iface != exclude && !isTunnel(r.Iface) && !isVirtual(r.Iface) {
			return r, true
		}
	}
	return Route{}, false
}

// parseNetstat reads default routes from BSD `netstat -rn` output.
func parseNetstat(out string) []Route {
	var routes, split []Route
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		gateway, flags, iface := f[1], f[2], f[3]
		switch f[0] {
		case "default":
			routes = append(routes, Route{
				Iface:   iface,
				Gateway: strings.Contains(flags, "G") && !strings.HasPrefix(gateway, "link#"),
				Addr:    gateway,
				Scoped:  strings.Contains(flags, "I"),
			})
		case "0/1", "128.0/1", "::/1", "8000::/1":
			// VPNs that use split routes (WireGuard, OpenVPN, our own TUN)
			// override the default route without replacing it.
			if isTunnel(iface) {
				split = append(split, Route{Iface: iface})
			}
		}
	}
	if len(split) > 0 {
		routes = append(split[:1], routes...)
	}
	return routes
}

// Detect inspects the system's default routes.
func Detect() (Detection, error) {
	routes, err := defaultRoutes()
	if err != nil {
		return Detection{}, err
	}
	d := pick(routes)
	if d.Tunnel == "" {
		// A VPN that only takes IPv6 over still captures traffic.
		if r6, _ := familyRoutes("inet6"); len(r6) > 0 && isTunnel(r6[0].Iface) {
			d = Detection{Tunnel: r6[0].Iface, Physical: physical(routes, "")}
		}
	}
	return d, nil
}

// defaultRoutes lists IPv4 default route candidates, active first.
func defaultRoutes() ([]Route, error) {
	return familyRoutes("inet")
}

// Uplink returns the physical interface with the system-wide default route
// for family ("inet" or "inet6") and its gateway, skipping exclude.
func Uplink(family, exclude string) (iface, gateway string, err error) {
	routes, err := familyRoutes(family)
	if err != nil {
		return "", "", err
	}
	r, ok := uplink(routes, exclude)
	if !ok {
		return "", "", fmt.Errorf("no %s default route", family)
	}
	return r.Iface, r.Addr, nil
}
