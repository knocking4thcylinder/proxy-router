package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func FreeName() (string, error) { return "prtun0", nil }

// SocketMark is the SO_MARK proxy-router's own sockets carry in TUN mode,
// so the kill switch can let them out of the physical interface.
func SocketMark() int { return Mark }

// routeProto tags the routes Up adds ("proto 112"), so they're told apart
// from other VPNs' and only they are ever replaced or deleted. Reject routes
// outlive the process, so a later run (or Cleanup) recognizes them by it.
const routeProto = "112"

// linkAddr is the TUN's IPv4 address. Xray leaves it without one on Linux,
// and systemd-resolved doesn't send DNS to links without a routable address.
const linkAddr = "198.18.0.1/32"

func ipFamily(family string) string {
	if family == "inet6" {
		return "-6"
	}
	return "-4"
}

func addRouteArgs(r route, name string) []string {
	if r.reject {
		return []string{ipFamily(r.family), "route", "replace", "unreachable", r.prefix, "proto", routeProto}
	}
	return []string{ipFamily(r.family), "route", "replace", r.prefix, "dev", name, "proto", routeProto}
}

// delRouteArgs deletes r if it's ours. Without a name it matches any of
// our routes for the prefix, of either kind.
func delRouteArgs(r route, name string) []string {
	switch {
	case name == "":
		return []string{ipFamily(r.family), "route", "del", r.prefix, "proto", routeProto}
	case r.reject:
		return []string{ipFamily(r.family), "route", "del", "unreachable", r.prefix, "proto", routeProto}
	}
	return []string{ipFamily(r.family), "route", "del", r.prefix, "dev", name, "proto", routeProto}
}

// foreignRoutes describes the routes in `ip -j route show exact <prefix>`
// output that aren't ours.
func foreignRoutes(out string) ([]string, error) {
	var rs []struct {
		Type     string `json:"type"`
		Dst      string `json:"dst"`
		Dev      string `json:"dev"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(out), &rs); err != nil {
		return nil, fmt.Errorf("can't read the routing table: %w", err)
	}
	var foreign []string
	for _, r := range rs {
		if r.Protocol == routeProto {
			continue
		}
		desc := r.Dst
		if r.Type != "" {
			desc = r.Type + " " + desc
		}
		if r.Dev != "" {
			desc += " dev " + r.Dev
		}
		foreign = append(foreign, desc)
	}
	return foreign, nil
}

// checkRoutes refuses to touch split routes someone else owns: replacing
// them would break that VPN, and deleting them later would too.
func checkRoutes(rs []route) error {
	var conflicts []string
	for _, r := range rs {
		out, err := output("ip", "-j", ipFamily(r.family), "route", "show", "exact", r.prefix)
		if err != nil {
			if r.family == "inet6" {
				continue // no IPv6 in this kernel
			}
			return err
		}
		f, err := foreignRoutes(out)
		if err != nil {
			return err
		}
		conflicts = append(conflicts, f...)
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("another VPN's routes are in the way (%s); disconnect it first: proxy-router doesn't replace routes it doesn't own", strings.Join(conflicts, ", "))
	}
	return nil
}

// Up points the split routes at the interface (IPv6 at a reject route
// unless o.IPv6), turns on the kill switch, and points system DNS into the
// TUN. It's safe to run again with changed options. On error, Down undoes
// what was done.
func Up(o Options) error {
	if err := ValidName(o.Name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", o.Name, "up"); err != nil {
		return err
	}
	if err := run("ip", "-4", "addr", "replace", linkAddr, "dev", o.Name); err != nil {
		return err
	}
	// Kill switch first, so nothing leaks while the rest is set up.
	if o.KillSwitch {
		if err := installKillSwitch(o); err != nil {
			return err
		}
	} else if err := clearKillSwitch(); err != nil {
		warn("can't remove the kill switch: %v", err)
	}
	rs := routes(o.IPv6)
	if err := checkRoutes(rs); err != nil {
		return err
	}
	for _, r := range rs {
		if err := run("ip", addRouteArgs(r, o.Name)...); err != nil {
			if r.family == "inet6" && !hasIPv6(o.Name) {
				warn("IPv6 is unavailable, so there's none to capture (%v)", err)
				continue
			}
			return err
		}
	}
	setDNS(o)
	return nil
}

// Down removes the routes and DNS settings, and the kill switch unless
// keepKillSwitch: the service keeps it while it restarts.
func Down(o Options, keepKillSwitch bool) {
	if resolved() {
		_ = run("resolvectl", "revert", o.Name)
	}
	for _, r := range routes(o.IPv6) {
		_ = run("ip", delRouteArgs(r, o.Name)...)
	}
	if !keepKillSwitch {
		if err := clearKillSwitch(); err != nil {
			warn("can't remove the kill switch: %v", err)
		}
	}
}

// Cleanup removes everything Up leaves behind after the process is gone:
// the kill switch and the IPv6 reject routes. (Routes into the TUN and its
// DNS settings disappear with the interface.)
func Cleanup() error {
	for _, r := range routes(true) {
		_ = run("ip", delRouteArgs(r, "")...)
	}
	return clearKillSwitch()
}

// Sync puts the TUN's DNS settings back if systemd-resolved lost them (it
// forgets them when restarted). Binding sockets needs no extra routes on
// Linux.
func Sync(o Options) error {
	if !resolved() {
		return nil
	}
	if out, err := output("resolvectl", "domain", o.Name); err == nil && !strings.Contains(out, "~.") {
		setDNS(o)
	}
	return nil
}

func installKillSwitch(o Options) error {
	if tool("nft") == "" {
		return errors.New("tun.kill_switch needs nftables (the nft command); install it, or set tun.kill_switch: false in config.yaml")
	}
	_, err := runTool(nftRuleset(o), "nft", "-f", "-")
	return err
}

func clearKillSwitch() error {
	if tool("nft") == "" {
		return nil // so there can't be one
	}
	_, err := runTool(nftClear(), "nft", "-f", "-")
	return err
}

// resolved reports whether systemd-resolved is running.
var resolved = func() bool {
	_, err := os.Stat("/run/systemd/resolve/io.systemd.Resolve")
	return err == nil && tool("resolvectl") != ""
}

// resolvConf is read to warn about DNS leaks; tests replace it.
var resolvConf = func() string {
	data, _ := os.ReadFile("/etc/resolv.conf")
	return string(data)
}

// resolvedArgs make the TUN systemd-resolved's DNS route for every name.
// Links with a more specific routing domain (Tailscale's tailnet on
// tailscale0, a LAN search domain) keep theirs.
func resolvedArgs(name string) [][]string {
	return [][]string{
		{"dns", name, DNSServer},
		{"domain", name, "~."},
		{"default-route", name, "yes"},
		// Only plain DNS is answered in the TUN.
		{"dnsovertls", name, "no"},
		{"llmnr", name, "no"},
		{"mdns", name, "no"},
	}
}

// setDNS points systemd-resolved into the TUN. Without it, DNS to a local
// resolver (the router, from a static /etc/resolv.conf) takes the LAN
// route around the TUN; the kill switch catches that, so it's only a
// warning when the kill switch is off.
func setDNS(o Options) {
	configured := false
	if resolved() {
		configured = true
		for i, args := range resolvedArgs(o.Name) {
			if err := run("resolvectl", args...); err != nil {
				if i < 2 {
					warn("can't point systemd-resolved at the TUN: %v", err)
					configured = false
					break
				}
				// Older systemd lacks some settings; it works without.
			}
		}
	}
	if o.KillSwitch {
		return
	}
	if leaky := leakyResolvers(resolvConf(), configured); len(leaky) > 0 {
		warn("DNS queries to %s don't go through the TUN and leak; turn on tun.kill_switch to redirect them", strings.Join(leaky, ", "))
	}
}

// leakyResolvers lists the nameservers in resolv.conf that DNS would reach
// without going through the TUN: local ones, which the split routes don't
// cover. systemd-resolved's stub is fine once it's pointed at the TUN.
func leakyResolvers(resolvConf string, resolvedConfigured bool) []string {
	var out []string
	for _, line := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.Unmap()
		stub := a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54")
		if (stub && resolvedConfigured) || !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()) {
			continue
		}
		out = append(out, a.String())
	}
	return out
}
