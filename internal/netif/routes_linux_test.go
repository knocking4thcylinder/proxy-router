package netif

import "testing"

const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enp42s0	00000000	011FA8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	0101A8C0	0003	0	0	20600	00000000	0	0	0
wlan0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
`

func TestProcRouteByMetric(t *testing.T) {
	routes := parseProcRoute(procRoute)
	if len(routes) != 2 || routes[0].Iface != "enp42s0" || routes[0].Addr != "192.168.31.1" || !routes[0].Gateway {
		t.Fatalf("got %+v", routes)
	}
	if d := pick(routes); d != (Detection{}) {
		t.Fatalf("no VPN: got %+v", d)
	}
}

func TestProcRouteSplitVPN(t *testing.T) {
	// OpenVPN's def1 / wg-quick style split routes beat the default route.
	routes := parseProcRoute(procRoute + `tun0	00000000	0100080A	0003	0	0	0	00000080	0	0	0
tun0	00000080	0100080A	0003	0	0	0	00000080	0	0	0
`)
	d := pick(routes)
	if d.Tunnel != "tun0" || d.Physical != "enp42s0" {
		t.Fatalf("got %+v", d)
	}
	// Split routes on a LAN interface (or anything else) aren't a VPN.
	routes = parseProcRoute(procRoute + "wlan0	00000000	00000000	0001	0	0	0	00000080	0	0	0\n")
	if d := pick(routes); d.Tunnel != "" {
		t.Fatalf("got %+v", d)
	}
}

func TestProcRouteSkipsReject(t *testing.T) {
	routes := parseProcRoute(procRoute + "lo	00000000	00000000	0201	0	0	0	00000000	0	0	0\n")
	if len(routes) != 2 {
		t.Fatalf("got %+v", routes)
	}
}

const procIPv6Route = `fd7a115ca1e000000000000000000000 30 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 0000000d 00000000 00000001 tailscale0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003    wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000064 00000001 00000000 00450003  enp42s0
00000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000201       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`

func TestProcIPv6Route(t *testing.T) {
	routes := parseProcIPv6Route(procIPv6Route)
	if len(routes) != 2 || routes[0].Iface != "enp42s0" || routes[0].Addr != "fe80::2" || !routes[0].Gateway {
		t.Fatalf("got %+v", routes)
	}
	r, ok := uplink(routes, "")
	if !ok || r.Iface != "enp42s0" {
		t.Fatalf("got %+v", r)
	}
}

func TestProcIPv6RouteSplitVPN(t *testing.T) {
	routes := parseProcIPv6Route(procIPv6Route + `00000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001      wg0
80000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001      wg0
`)
	if len(routes) != 4 || routes[0].Iface != "wg0" || routes[2].Iface != "enp42s0" {
		t.Fatalf("got %+v", routes)
	}
}
