package netif

import "testing"

func TestPickBehindForeignTunnel(t *testing.T) {
	// Real `netstat -rn -f inet` output with Happ's TUN active.
	out := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#88            UCSg               utun39
default            192.168.31.1       UGScIg                en0
default            link#78            UCSIg           bridge100      !
1.1.1.1            link#88            UHWIig             utun39
`
	d := pick(parseNetstat(out))
	if d.Tunnel != "utun39" || d.Physical != "en0" {
		t.Fatalf("got %+v", d)
	}
}

func TestPickNoTunnel(t *testing.T) {
	out := "default            192.168.1.1        UGScg                 en0\n"
	if d := pick(parseNetstat(out)); d != (Detection{}) {
		t.Fatalf("got %+v", d)
	}
}

func TestPickSplitRouteVPN(t *testing.T) {
	out := `default            192.168.1.1        UGScg                 en0
0/1                utun7              USc                 utun7
128.0/1            utun7              USc                 utun7
`
	d := pick(parseNetstat(out))
	if d.Tunnel != "utun7" || d.Physical != "en0" {
		t.Fatalf("got %+v", d)
	}
}

func TestUplinkSkipsScopedRoutes(t *testing.T) {
	out := `default            192.168.31.1       UGScIg                en1
default            192.168.1.1        UGScg                 en0
0/1                utun99             UScg               utun99
default            fe80::1%en0        UGcg                  en0
`
	r, ok := uplink(parseNetstat(out), "utun99")
	if !ok || r.Iface != "en0" || r.Addr != "192.168.1.1" {
		t.Fatalf("got %+v %v", r, ok)
	}
}

func TestPickIPv6SplitRoutes(t *testing.T) {
	out := `default                                 fe80::1%en0                     UGcg                  en0
::/1                                    utun7                           USc                 utun7
8000::/1                                utun7                           USc                 utun7
`
	if d := pick(parseNetstat(out)); d.Tunnel != "utun7" {
		t.Fatalf("got %+v", d)
	}
}

func TestToolUsesSystemDirs(t *testing.T) {
	dir := t.TempDir()
	saved := systemDirs
	systemDirs = []string{dir}
	defer func() { systemDirs = saved }()
	t.Setenv("PATH", "/usr/bin:/bin")
	if p := Tool("sh"); p != "" {
		t.Fatalf("found %s outside the system directories", p)
	}
	if c := Command("sh"); c.Path != dir+"/sh" {
		t.Fatalf("path = %s", c.Path)
	}
}
