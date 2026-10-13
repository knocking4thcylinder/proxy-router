package tun

import (
	"fmt"
	"net"
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
	for _, r := range routes(ipv6) {
		// A stale route from a crashed run would make "add" fail.
		_ = run("route", "-q", "-n", "delete", r[0], "-net", r[1], "-interface", name)
		if err := run("route", "-q", "-n", "add", r[0], "-net", r[1], "-interface", name); err != nil {
			Down(name, ipv6)
			return err
		}
	}
	return nil
}

// Down removes the routes. They also vanish when the interface does.
func Down(name string, ipv6 bool) {
	for _, r := range routes(ipv6) {
		_ = run("route", "-q", "-n", "delete", r[0], "-net", r[1], "-interface", name)
	}
}
