package tun

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/knocking4thcylinder/proxy-router/internal/netif"
)

// FreeName returns an unused utunN name (macOS only accepts that form).
func FreeName() (string, error) {
	for n := 99; n < 256; n++ {
		name := fmt.Sprintf("utun%d", n)
		if _, err := net.InterfaceByName(name); err != nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free utun interface number")
}

// SocketMark is 0: macOS has no socket marks, the kill switch goes by user.
func SocketMark() int { return 0 }

func netstat(family string) string {
	out, _ := output("netstat", "-rn", "-f", family)
	return out
}

// checkRoutes refuses to touch split routes someone else owns: replacing
// them would break that VPN, and deleting them later would too.
func checkRoutes(rs []route, name string) error {
	var conflicts []string
	tables := map[string]string{}
	for _, r := range rs {
		if _, ok := tables[r.family]; !ok {
			tables[r.family] = netstat(r.family)
		}
		if present, ours, desc := splitRoute(tables[r.family], r, name); present && !ours {
			conflicts = append(conflicts, desc)
		}
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
	// Kill switch first, so nothing leaks while the rest is set up.
	if o.KillSwitch {
		if err := installKillSwitch(o); err != nil {
			return err
		}
	} else if err := clearKillSwitch(); err != nil {
		warn("can't remove the kill switch: %v", err)
	}
	if err := syncScoped(o.Name); err != nil {
		return err
	}
	rs := routes(o.IPv6)
	if err := checkRoutes(rs, o.Name); err != nil {
		return err
	}
	for _, r := range rs {
		// Ours from before: a crashed run's reject route, or the other
		// kind after tun.ipv6 changed. "add" fails while it's there.
		if present, ours, _ := splitRoute(netstat(r.family), r, o.Name); present && ours {
			_ = run("route", bsdDeleteArgs(r)...)
		}
		if err := run("route", bsdRouteArgs(r, o.Name)...); err != nil {
			if r.family == "inet6" && !hasIPv6(o.Name) {
				warn("IPv6 is unavailable, so there's none to capture (%v)", err)
				continue
			}
			return err
		}
	}
	if err := syncDNS(); err != nil {
		warn("can't point DNS at the TUN: %v", err)
	}
	return nil
}

// Down removes the routes and DNS settings, and the kill switch unless
// keepKillSwitch: the service keeps it while it restarts.
func Down(o Options, keepKillSwitch bool) {
	restoreDNS()
	for _, r := range routes(o.IPv6) {
		if present, ours, _ := splitRoute(netstat(r.family), r, o.Name); present && ours {
			_ = run("route", bsdDeleteArgs(r)...)
		}
	}
	mu.Lock()
	for family, s := range added {
		s.remove(family)
		delete(added, family)
	}
	mu.Unlock()
	if !keepKillSwitch {
		if err := clearKillSwitch(); err != nil {
			warn("can't remove the kill switch: %v", err)
		}
	}
}

// Cleanup removes everything Up leaves behind after the process is gone:
// the kill switch, the DNS override and the IPv6 reject routes. (Routes
// into the TUN disappear with the interface.)
func Cleanup() error {
	restoreDNS()
	for _, r := range routes(false) {
		if present, ours, _ := splitRoute(netstat(r.family), r, ""); present && ours {
			_ = run("route", bsdDeleteArgs(r)...)
		}
	}
	return clearKillSwitch()
}

// scopedDefault is a default route that only applies to sockets bound to
// iface.
//
// proxy-router binds its own sockets to the physical interface
// (IP_BOUND_IF) so they bypass the TUN, but macOS only honours that binding
// through a route scoped to the interface. It creates those for secondary
// interfaces only: the primary one (usually en0) has just the system-wide
// default route, which the TUN's split routes override, and bound sockets
// get "network is unreachable". So Up adds the scoped route itself.
type scopedDefault struct{ iface, gateway string }

func (s scopedDefault) args(op, family string) []string {
	return []string{"-q", "-n", op, "-" + family, "default", s.gateway, "-ifscope", s.iface}
}

func (s scopedDefault) remove(family string) {
	_ = run("route", s.args("delete", family)...)
}

var (
	mu    sync.Mutex
	added = map[string]scopedDefault{} // family -> route Up added
)

// Sync follows network changes (Wi-Fi <-> Ethernet, new gateway, DHCP
// rewriting DNS): it keeps a scoped default route on the physical
// interface and DNS pointed into the TUN. Run it whenever the network may
// have changed, and now and then.
func Sync(o Options) error {
	if err := syncScoped(o.Name); err != nil {
		return err
	}
	return syncDNS()
}

// syncScoped adds the scoped default routes, for IPv6 too: its split routes
// are always there, into the TUN or rejected.
func syncScoped(name string) error {
	mu.Lock()
	defer mu.Unlock()
	for _, family := range []string{"inet", "inet6"} {
		iface, gw, err := netif.Uplink(family, name)
		if err != nil {
			if family == "inet6" {
				continue // no IPv6 uplink: nothing to bypass
			}
			return err
		}
		want := scopedDefault{iface, gw}
		if added[family] == want {
			continue
		}
		if old, ok := added[family]; ok {
			old.remove(family)
			delete(added, family)
		}
		err = run("route", want.args("add", family)...)
		switch {
		case err == nil:
			added[family] = want
		case strings.Contains(err.Error(), "File exists"):
			// macOS (or a crashed run) already has one; leave it alone.
		default:
			return fmt.Errorf("can't add a default route scoped to %s: %w", iface, err)
		}
	}
	return nil
}

func scutil(script string) (string, error) {
	return runTool(script, "scutil")
}

func primaryService() string {
	out, _ := scutil("show State:/Network/Global/IPv4\n")
	d, _ := parseScutil(out)
	if p := d["PrimaryService"]; len(p) == 1 && serviceID.MatchString(p[0]) {
		return p[0]
	}
	return ""
}

func readBackup() (dnsBackup, bool) {
	out, _ := scutil("show " + dnsBackupKey + "\n")
	return parseBackup(out)
}

// syncDNS points the primary service's DNS at DNSServer, following changes
// of the primary service, and saves what it replaces.
func syncDNS() error {
	primary := primaryService()
	b, saved := readBackup()
	if saved && b.Service != primary {
		if _, err := scutil(restoreDNSScript(b)); err != nil {
			return err
		}
	}
	if primary == "" {
		return nil
	}
	out, _ := scutil("show " + setupDNSKey(primary) + "\n")
	cur, hadKey := parseScutil(out)
	if slices.Equal(cur["ServerAddresses"], []string{DNSServer}) {
		return nil
	}
	// Save what's there now: it's newer than an older backup if the
	// settings were re-applied (the user changed them).
	if _, err := scutil(backupScript(dnsBackup{Service: primary, HadKey: hadKey, Servers: cur["ServerAddresses"]})); err != nil {
		return err
	}
	_, err := scutil(applyDNSScript(primary))
	return err
}

func restoreDNS() {
	if b, ok := readBackup(); ok {
		if _, err := scutil(restoreDNSScript(b)); err != nil {
			warn("can't restore DNS settings: %v", err)
		}
	}
}

func installKillSwitch(o Options) error {
	// pf is off by default; enabling it with only macOS's own rules
	// changes nothing, so it's left on afterwards.
	if out, err := output("pfctl", "-s", "info"); err == nil && !strings.Contains(out, "Status: Enabled") {
		if err := run("pfctl", "-E"); err != nil {
			return err
		}
	}
	_, err := runTool(pfRules(o), "pfctl", "-a", pfAnchor, "-f", "-")
	return err
}

func clearKillSwitch() error {
	return run("pfctl", "-a", pfAnchor, "-F", "all")
}
