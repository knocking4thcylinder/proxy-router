package tun

import (
	"strings"
	"testing"
)

// before fails unless a comes before b in s.
func before(t *testing.T, s, a, b string) {
	t.Helper()
	i, j := strings.Index(s, a), strings.Index(s, b)
	if i < 0 || j < 0 || i > j {
		t.Fatalf("want %q before %q in:\n%s", a, b, s)
	}
}

func TestNftRuleset(t *testing.T) {
	o := NewOptions("prtun0", false, true, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "domain:ts.net"})
	rs := nftRuleset(o)
	// Replaced atomically, created first so the delete can't fail.
	if !strings.HasPrefix(rs, "table inet proxy_router\ndelete table inet proxy_router\ntable inet proxy_router {\n") {
		t.Fatalf("ruleset:\n%s", rs)
	}
	for _, want := range []string{
		`oifname "prtun0" accept`,
		"meta mark 0x7072 accept",
		"ip daddr { 100.64.0.0/10 } accept",
		"ip6 daddr { fd7a:115c:a1e0::/48 } accept",
		"udp sport 68 udp dport 67 accept",
		"dnat ip to 198.18.0.53",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Tailscale's MagicDNS (100.100.100.100:53) is let through before DNS
	// is blocked; the router's DNS isn't, though the router is.
	before(t, rs, "ip daddr { 100.64.0.0/10 } accept", "th dport { 53, 853 } reject")
	before(t, rs, "th dport { 53, 853 } reject", "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
	// DNS redirected into the TUN is let through: the output chain sees
	// the interface it was routed to before the redirect.
	before(t, rs, "ip daddr 198.18.0.53 ct status dnat accept", "th dport { 53, 853 } reject")
	before(t, rs, "ip6 daddr { fe80::/10", "\t\treject with icmpx type admin-prohibited\n\t}")
	// DNS to system_route addresses isn't redirected either.
	before(t, rs, "chain dns", "ip daddr { 100.64.0.0/10 } return")

	// No exemptions: no empty sets, which nft rejects.
	rs = nftRuleset(NewOptions("prtun0", false, true, []string{"domain:ts.net"}))
	if strings.Contains(rs, "{  }") || strings.Contains(rs, "100.64") {
		t.Fatalf("ruleset:\n%s", rs)
	}
}

func TestNftClear(t *testing.T) {
	if got := nftClear(); got != "table inet proxy_router\ndelete table inet proxy_router\n" {
		t.Fatalf("got %q", got)
	}
}

func TestPfRules(t *testing.T) {
	rs := pfRules(NewOptions("utun99", false, true, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}))
	for _, want := range []string{
		"pass quick on lo0 all no state",
		"pass out quick on utun99 all",
		"pass out quick inet from any to { 100.64.0.0/10 }",
		"pass out quick inet6 from any to { fd7a:115c:a1e0::/48 }",
		"user root",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in:\n%s", want, rs)
		}
	}
	// The TUN front and user-facing SOCKS/HTTP listeners use loopback.
	// Its exception must cover SYNs and replies in either direction,
	// without creating PF states that can drop the local second pass.
	if !strings.HasPrefix(rs, "pass quick on lo0 all no state\n") {
		t.Fatalf("loopback must bypass state tracking before filtering:\n%s", rs)
	}
	before(t, rs, "100.64.0.0/10", "port { 53, 853 }")
	before(t, rs, "port { 53, 853 }", "192.168.0.0/16")
	before(t, rs, "port { 53, 853 }", "user root")
	if !strings.HasSuffix(rs, "block return out quick all\n") {
		t.Fatalf("doesn't end blocking:\n%s", rs)
	}
}
