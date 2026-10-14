package netif

import (
	"fmt"
	"os/exec"
)

// defaultRoutes parses `netstat -rn -f inet`; the kernel lists the active
// default route first.
func defaultRoutes() ([]Route, error) {
	return netstat("inet")
}

func netstat(family string) ([]Route, error) {
	out, err := exec.Command("netstat", "-rn", "-f", family).Output()
	if err != nil {
		return nil, err
	}
	return parseNetstat(string(out)), nil
}

// Uplink returns the physical interface with the system-wide default route
// for family ("inet" or "inet6") and its gateway, skipping exclude.
func Uplink(family, exclude string) (iface, gateway string, err error) {
	routes, err := netstat(family)
	if err != nil {
		return "", "", err
	}
	r, ok := uplink(routes, exclude)
	if !ok {
		return "", "", fmt.Errorf("no %s default route", family)
	}
	return r.Iface, r.Addr, nil
}
