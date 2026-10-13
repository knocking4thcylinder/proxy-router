package netif

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// defaultRoutes reads /proc/net/route, ordered by metric (lowest first).
func defaultRoutes() ([]Route, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	type entry struct {
		Route
		metric int
	}
	var entries []entry
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		entries = append(entries, entry{Route{Iface: f[0], Gateway: f[2] != "00000000"}, metric})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].metric < entries[j].metric })
	routes := make([]Route, len(entries))
	for i, e := range entries {
		routes[i] = e.Route
	}
	return routes, nil
}
