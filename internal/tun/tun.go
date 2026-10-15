// Package tun routes the system's traffic into Xray's TUN interface.
//
// Only the two halves of the address space (0.0.0.0/1 and 128.0.0.0/1, and
// ::/1 and 8000::/1) are pointed at the TUN. They beat the default route
// without replacing it, and anything more specific (the LAN, Tailscale's
// peers and 100.64.0.0/10) keeps going where it went before.
// proxy-router's own sockets are bound to the physical interface, so they
// don't loop back into the TUN.
//
// IPv6 is always taken over: into the TUN with Options.IPv6, otherwise into
// a reject route, so apps fail fast and fall back to IPv4 instead of
// leaking around the proxy.
//
// System DNS is pointed into the TUN (systemd-resolved on Linux, the
// primary service's DNS on macOS), where Xray answers it.
//
// The kill switch is a firewall policy (nftables on Linux, a pf anchor on
// macOS) that drops traffic leaving outside the TUN, except proxy-router's
// own, the LAN and system_route destinations. It outlives the process on
// purpose, so crashes and restarts don't leak; Cleanup ("proxy-router
// stop") removes it.
package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/netif"
)

// DNSServer is the resolver address system DNS is pointed at. It's routed
// into the TUN, where Xray answers anything sent to port 53 (the tun_dns
// rule); nothing listens there on the internet (198.18.0.0/15 is reserved
// for benchmarking), so a query that somehow escaped would go nowhere.
const DNSServer = "198.18.0.53"

// Mark is the socket mark (SO_MARK) on proxy-router's own connections on
// Linux, which the kill switch lets out of the physical interface. See
// SocketMark.
const Mark = 0x7072

// Options is what Up applies.
type Options struct {
	// Name is the TUN interface.
	Name string
	// IPv6 sends IPv6 through the TUN; otherwise it's rejected.
	IPv6 bool
	// KillSwitch blocks traffic outside the TUN, see the package comment.
	KillSwitch bool
	// Exempt lists system_route destinations the kill switch lets through.
	Exempt []netip.Prefix
}

// NewOptions builds Options from config values. systemRoute entries that
// aren't addresses (domain:, geoip:) are skipped: the kill switch can only
// match addresses, and those names resolve to the ranges listed next to
// them.
func NewOptions(name string, ipv6, killSwitch bool, systemRoute []string) Options {
	o := Options{Name: name, IPv6: ipv6, KillSwitch: killSwitch}
	for _, e := range systemRoute {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			o.Exempt = append(o.Exempt, p.Masked())
		} else if a, err := netip.ParseAddr(e); err == nil {
			o.Exempt = append(o.Exempt, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return o
}

// Equal reports whether o and p would apply the same thing.
func (o Options) Equal(p Options) bool {
	return o.Name == p.Name && o.IPv6 == p.IPv6 && o.KillSwitch == p.KillSwitch && slices.Equal(o.Exempt, p.Exempt)
}

// exempt splits Exempt by family.
func (o Options) exempt() (v4, v6 []string) {
	for _, p := range o.Exempt {
		if p.Addr().Unmap().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	return v4, v6
}

// lan is what the kill switch lets out of the physical interface besides
// proxy-router's own traffic: local networks, link-local and multicast
// (DHCP, NDP, mDNS), and broadcast. Port 53/853 is blocked even there.
var (
	lan4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"}
	lan6 = []string{"fe80::/10", "fc00::/7", "ff00::/8"}
)

// validName is what interface names may look like. Names end up in
// firewall rules, so anything else is refused.
var validName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// ValidName reports whether name can be used as the TUN interface.
func ValidName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("%q is not a valid interface name (up to 15 letters, digits, '.', '-', '_')", name)
	}
	return nil
}

// route is one of the split routes Up installs.
type route struct {
	family string // "inet" or "inet6"
	prefix string
	// reject makes the route fail connections at once instead of carrying
	// them into the TUN.
	reject bool
}

func routes(ipv6 bool) []route {
	return []route{
		{"inet", "0.0.0.0/1", false},
		{"inet", "128.0.0.0/1", false},
		{"inet6", "::/1", !ipv6},
		{"inet6", "8000::/1", !ipv6},
	}
}

// RequireRoot fails with a helpful message when not running as root.
func RequireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("TUN mode needs root to create the interface and routes; run: sudo %s", strings.Join(os.Args, " "))
	}
	return nil
}

// WaitForInterface waits until Xray has created the interface.
func WaitForInterface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %s did not appear", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// WaitGone waits until a closed interface is really gone, so a new one
// with the same name can be created ("device or resource busy" otherwise).
func WaitGone(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(name); err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %s is still there after %v", name, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// runTool runs a system tool with input on stdin and returns its output. Tests
// replace it to see the commands without running them.
var runTool = func(stdin, name string, args ...string) (string, error) {
	cmd := netif.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func run(name string, args ...string) error {
	_, err := runTool("", name, args...)
	return err
}

func output(name string, args ...string) (string, error) {
	return runTool("", name, args...)
}

// warn reports a problem that doesn't stop TUN mode.
var warn = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "TUN: "+format+"\n", args...)
}

// hasIPv6 reports whether there's an IPv6 default route to leak through.
var hasIPv6 = func(exclude string) bool {
	_, _, err := netif.Uplink("inet6", exclude)
	return err == nil
}

// tool is netif.Tool; tests replace it.
var tool = netif.Tool
