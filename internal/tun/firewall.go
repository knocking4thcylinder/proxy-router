package tun

import (
	"fmt"
	"strings"
)

// The kill switch's rules, built here for both platforms so they can be
// tested anywhere.

// nftTable is the nftables table holding the Linux kill switch.
const nftTable = "inet proxy_router"

// nftRuleset replaces the kill switch table in one transaction (creating it
// first makes the delete succeed when it doesn't exist yet).
//
// The output chain lets through, in order: loopback, the TUN, proxy-router's
// own sockets (they carry Mark), system_route destinations, DHCP and IPv6
// neighbour discovery. Then DNS and DNS-over-TLS are rejected, the LAN is
// let through, and everything else is rejected, so apps fail fast instead of
// hanging.
//
// The dns chain sends plain DNS that would leave outside the TUN (to a LAN
// resolver from a static /etc/resolv.conf, say) to DNSServer instead,
// which is routed into the TUN. So DNS keeps working, answered by Xray,
// without systemd-resolved.
func nftRuleset(o Options) string {
	v4, v6 := o.exempt()
	var b strings.Builder
	fmt.Fprintf(&b, "table %s\ndelete table %s\ntable %s {\n", nftTable, nftTable, nftTable)

	b.WriteString("\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n")
	fmt.Fprintf(&b, "\t\toifname \"lo\" accept\n\t\toifname %q accept\n", o.Name)
	fmt.Fprintf(&b, "\t\tmeta mark %#x accept\n", Mark)
	// DNS the dns chain redirected: it's rerouted into the TUN, but this
	// chain still sees the interface it was headed for.
	fmt.Fprintf(&b, "\t\tip daddr %s ct status dnat accept\n", DNSServer)
	nftSet(&b, "ip daddr", v4, "accept")
	nftSet(&b, "ip6 daddr", v6, "accept")
	b.WriteString("\t\tudp sport 68 udp dport 67 accept\n")
	b.WriteString("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report } accept\n")
	b.WriteString("\t\tmeta l4proto { tcp, udp } th dport { 53, 853 } reject with icmpx type admin-prohibited\n")
	nftSet(&b, "ip daddr", lan4, "accept")
	nftSet(&b, "ip6 daddr", lan6, "accept")
	b.WriteString("\t\treject with icmpx type admin-prohibited\n\t}\n")

	b.WriteString("\tchain dns {\n\t\ttype nat hook output priority -100; policy accept;\n")
	fmt.Fprintf(&b, "\t\toifname \"lo\" return\n\t\toifname %q return\n", o.Name)
	fmt.Fprintf(&b, "\t\tmeta mark %#x return\n", Mark)
	nftSet(&b, "ip daddr", v4, "return")
	fmt.Fprintf(&b, "\t\tmeta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to %s\n", DNSServer)
	b.WriteString("\t}\n}\n")
	return b.String()
}

// nftClear removes the kill switch table, whether or not it exists.
func nftClear() string {
	return fmt.Sprintf("table %s\ndelete table %s\n", nftTable, nftTable)
}

func nftSet(b *strings.Builder, match string, values []string, verdict string) {
	if len(values) > 0 {
		fmt.Fprintf(b, "\t\t%s { %s } %s\n", match, strings.Join(values, ", "), verdict)
	}
}

// pfAnchor is where the macOS kill switch lives. The stock /etc/pf.conf
// evaluates every anchor under com.apple/.
const pfAnchor = "com.apple/proxy-router"

// pfRules is the macOS kill switch: the same policy as nftRuleset. pf has
// no socket marks, so proxy-router's own traffic is recognized by its user,
// root. That also lets other root daemons out; most of macOS's own run as
// dedicated users, and DNS (mDNSResponder) is still forced into the TUN.
func pfRules(o Options) string {
	v4, v6 := o.exempt()
	var b strings.Builder
	// Loopback traffic traverses PF in both directions. Do not create
	// TCP states for it: they can interfere with the second traversal,
	// breaking both the public listeners and the TUN front's local hop.
	// Keep this interface-scoped; external traffic still hits the rules
	// below, including the DNS restrictions and final block.
	fmt.Fprintf(&b, "pass quick on lo0 all no state\npass out quick on %s all\n", o.Name)
	pfSet(&b, "inet", v4)
	pfSet(&b, "inet6", v6)
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n")
	b.WriteString("pass out quick inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv }\n")
	b.WriteString("block return out quick proto { tcp, udp } from any to any port { 53, 853 }\n")
	pfSet(&b, "inet", lan4)
	pfSet(&b, "inet6", lan6)
	b.WriteString("pass out quick proto { tcp, udp } from any to any user root\n")
	b.WriteString("block return out quick all\n")
	return b.String()
}

func pfSet(b *strings.Builder, family string, values []string) {
	if len(values) > 0 {
		fmt.Fprintf(b, "pass out quick %s from any to { %s }\n", family, strings.Join(values, ", "))
	}
}
