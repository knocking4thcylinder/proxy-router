package tun

import (
	"strings"
	"testing"
)

const netstat4 = `Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
0/1                utun99             USc                utun99
128.0/1            utun7              USc                 utun7
`

const netstat6 = `Destination                             Gateway                         Flags               Netif Expire
default                                 fe80::1%en0                     UGcg                  en0
::/1                                    ::1                             UGRSc                 lo0
`

func TestSplitRouteOwnership(t *testing.T) {
	rs := routes(false)
	if present, ours, _ := splitRoute(netstat4, rs[0], "utun99"); !present || !ours {
		t.Error("0/1 on our TUN isn't ours")
	}
	if present, ours, desc := splitRoute(netstat4, rs[1], "utun99"); !present || ours || !strings.Contains(desc, "utun7") {
		t.Errorf("another VPN's 128.0/1 is ours: %s", desc)
	}
	if present, ours, _ := splitRoute(netstat6, rs[2], ""); !present || !ours {
		t.Error("a reject route left by a crashed run isn't ours")
	}
	if present, _, _ := splitRoute(netstat6, rs[3], "utun99"); present {
		t.Error("8000::/1 isn't there")
	}
}

func TestBSDRouteArgs(t *testing.T) {
	rs := routes(false)
	if got := strings.Join(bsdRouteArgs(rs[0], "utun99"), " "); got != "-q -n add -inet -net 0.0.0.0/1 -interface utun99" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(bsdRouteArgs(rs[2], "utun99"), " "); got != "-q -n add -inet6 -net ::/1 ::1 -reject" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(bsdRouteArgs(routes(true)[3], "utun99"), " "); got != "-q -n add -inet6 -net 8000::/1 -interface utun99" {
		t.Errorf("got %s", got)
	}
}
