package tun

import (
	"fmt"
	"net"
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

func routes(ipv6 bool) [][2]string {
	r := [][2]string{{"-inet", "0.0.0.0/1"}, {"-inet", "128.0.0.0/1"}}
	if ipv6 {
		r = append(r, [2]string{"-inet6", "::/1"}, [2]string{"-inet6", "8000::/1"})
	}
	return r
}

// Up points the split default routes at the interface.
func Up(name string, ipv6 bool) error {
	if err := Sync(name, ipv6); err != nil {
		return err
	}
	for _, r := range routes(ipv6) {
		// A stale route from a crashed run would make "add" fail.
		_ = run("route", "-q", "-n", "delete", r[0], "-net", r[1])
		if err := run("route", "-q", "-n", "add", r[0], "-net", r[1], "-interface", name); err != nil {
			Down(name, ipv6)
			return err
		}
	}
	return nil
}

// Down removes the routes.
func Down(name string, ipv6 bool) {
	for _, r := range routes(ipv6) {
		_ = run("route", "-q", "-n", "delete", r[0], "-net", r[1])
	}
	mu.Lock()
	defer mu.Unlock()
	for family, s := range added {
		s.remove(family)
		delete(added, family)
	}
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

// Sync makes sure the physical interface has a scoped default route,
// following network changes (Wi-Fi <-> Ethernet, new gateway). Run it
// whenever the network may have changed.
func Sync(name string, ipv6 bool) error {
	families := []string{"inet"}
	if ipv6 {
		families = append(families, "inet6")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, family := range families {
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
