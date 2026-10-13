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
