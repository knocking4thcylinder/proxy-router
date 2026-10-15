package netif

import (
	"encoding/hex"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Route flags from <linux/route.h>.
const (
	rtfGateway = 0x0002
	rtfReject  = 0x0200
)

// familyRoutes reads /proc/net/route or /proc/net/ipv6_route, ordered by
// metric (lowest first), with other VPNs' split routes ahead of them.
func familyRoutes(family string) ([]Route, error) {
	path, parse := "/proc/net/route", parseProcRoute
	if family == "inet6" {
		path, parse = "/proc/net/ipv6_route", parseProcIPv6Route
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) && family == "inet6" {
		return nil, nil // IPv6 is disabled in this kernel
	}
	if err != nil {
		return nil, err
	}
	return parse(string(data)), nil
}

type procEntry struct {
	Route
	metric int
	split  bool
}

// sortRoutes orders default routes by metric and puts split routes on
// tunnel interfaces first: they beat the default route whatever its metric.
func sortRoutes(entries []procEntry) []Route {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].split != entries[j].split {
			return entries[i].split
		}
		return entries[i].metric < entries[j].metric
	})
	routes := make([]Route, len(entries))
	for i, e := range entries {
		routes[i] = e.Route
	}
	return routes
}

// parseProcRoute reads /proc/net/route. Addresses are little-endian hex:
// 128.0.0.0 is "00000080".
func parseProcRoute(data string) []Route {
	var entries []procEntry
	for _, line := range strings.Split(data, "\n")[1:] {
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) < 8 {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		if flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		e := procEntry{Route: Route{Iface: f[0], Gateway: f[2] != "00000000", Addr: procIPv4(f[2])}, metric: metric}
		switch {
		case f[1] == "00000000" && f[7] == "00000000":
		case (f[1] == "00000000" || f[1] == "00000080") && f[7] == "00000080":
			if !isTunnel(f[0]) {
				continue
			}
			e.split = true
		default:
			continue
		}
		entries = append(entries, e)
	}
	return sortRoutes(entries)
}

func procIPv4(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 || s == "00000000" {
		return ""
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}).String()
}

// parseProcIPv6Route reads /proc/net/ipv6_route: destination, prefix
// length, source, source prefix length, next hop, metric, refcount, use,
// flags, interface; numbers in hex.
func parseProcIPv6Route(data string) []Route {
	const zero = "00000000000000000000000000000000"
	var entries []procEntry
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[9] == "lo" {
			continue
		}
		flags, _ := strconv.ParseUint(f[8], 16, 32)
		if flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 32)
		e := procEntry{Route: Route{Iface: f[9], Gateway: flags&rtfGateway != 0}, metric: int(metric)}
		if b, err := hex.DecodeString(f[4]); err == nil && len(b) == 16 && f[4] != zero {
			e.Addr = netip.AddrFrom16([16]byte(b)).String()
		}
		switch {
		case f[0] == zero && f[1] == "00":
		case (f[0] == zero || f[0] == "8"+zero[1:]) && f[1] == "01":
			if !isTunnel(f[9]) {
				continue
			}
			e.split = true
		default:
			continue
		}
		entries = append(entries, e)
	}
	return sortRoutes(entries)
}
