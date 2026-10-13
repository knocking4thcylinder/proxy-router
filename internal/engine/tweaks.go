package engine

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

// muxProtocols can carry Xray mux. VLESS with a flow (XTLS Vision) can't.
var muxProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "socks": true, "http": true,
}

// ApplyTweaks adds the Happ-style settings (fragmentation, noises, mux,
// preferred IP) to a server's outbounds. Only the first outbound is the
// server itself; the rest are its own chain helpers and are left alone.
// It returns notes about settings that don't apply to this server.
func ApplyTweaks(obs []map[string]any, cfg *config.Config) ([]map[string]any, []string) {
	if len(obs) == 0 {
		return obs, nil
	}
	var notes []string
	ob := obs[0]
	proto, _ := ob["protocol"].(string)
	ss := child(ob, "streamSettings")
	network, _ := ss["network"].(string)
	// Hysteria2, mKCP and WireGuard ride on UDP; everything else on TCP.
	udp := proto == "hysteria" || proto == "wireguard" || network == "kcp" || network == "hysteria"

	if f := cfg.Fragment; f.Enabled && !udp {
		settings := map[string]any{
			"packets": f.Packets,
			"length":  f.Length.String(),
		}
		if !f.Delay.IsZero() {
			settings["delay"] = f.Delay.String()
		}
		if !f.MaxSplit.IsZero() {
			settings["maxSplit"] = f.MaxSplit.String()
		}
		appendMask(ss, "tcp", map[string]any{"type": "fragment", "settings": settings})
	}

	if cfg.Noises.Enabled && udp {
		var items []any
		for _, n := range cfg.Noises.Items {
			item := map[string]any{"type": orDefault(n.Type, "array")}
			if p, _ := n.JSONPacket(); p != nil {
				item["packet"] = p
			}
			if !n.Rand.IsZero() {
				item["rand"] = n.Rand.String()
			}
			if !n.RandRange.IsZero() {
				item["randRange"] = n.RandRange.String()
			}
			if !n.Delay.IsZero() {
				item["delay"] = n.Delay.String()
			}
			items = append(items, item)
		}
		appendMask(ss, "udp", map[string]any{"type": "noise", "settings": map[string]any{"noise": items}})
	}

	if m := cfg.Mux; m.Enabled {
		flow, _ := child(ob, "settings")["flow"].(string)
		switch {
		case !muxProtocols[proto]:
			notes = append(notes, fmt.Sprintf("mux skipped: not supported by %s", proto))
		case flow != "":
			notes = append(notes, fmt.Sprintf("mux skipped: not compatible with flow %s", flow))
		case network == "xhttp" || network == "splithttp":
			// Stacking mux on XHTTP breaks connections; it multiplexes itself.
			notes = append(notes, "mux skipped: XHTTP has its own multiplexing (xmux)")
		default:
			mux := map[string]any{"enabled": true, "concurrency": m.Concurrency}
			if m.XUDPConcurrency > 0 {
				mux["xudpConcurrency"] = m.XUDPConcurrency
			}
			if m.XUDPProxyUDP443 != "" {
				mux["xudpProxyUDP443"] = m.XUDPProxyUDP443
			}
			ob["mux"] = mux
		}
	}

	if ds := cfg.PreferredIPStrategy(); ds != "" {
		so := child(ss, "sockopt")
		if _, set := so["domainStrategy"]; !set {
			so["domainStrategy"] = ds
		}
	}

	// Don't leave empty objects behind.
	if so, ok := ss["sockopt"].(map[string]any); ok && len(so) == 0 {
		delete(ss, "sockopt")
	}
	if len(ss) == 0 {
		delete(ob, "streamSettings")
	}
	return obs, notes
}

// appendMask adds a finalmask entry, keeping masks the server already uses
// (e.g. Hysteria2's salamander).
func appendMask(ss map[string]any, layer string, mask map[string]any) {
	fm := child(ss, "finalmask")
	list, _ := fm[layer].([]any)
	fm[layer] = append(list, mask)
}

// child returns m[key] as a map, creating it if needed.
func child(m map[string]any, key string) map[string]any {
	c, ok := m[key].(map[string]any)
	if !ok {
		c = map[string]any{}
		m[key] = c
	}
	return c
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// systemRouteRule splits system_route entries into IP and domain matchers.
func systemRouteRules(entries []string) []map[string]any {
	var ips, domains []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
		case strings.HasPrefix(e, "geoip:"), strings.HasPrefix(e, "!geoip:"):
			ips = append(ips, e)
		case isIPOrCIDR(e):
			ips = append(ips, e)
		default:
			domains = append(domains, e)
		}
	}
	var rules []map[string]any
	if len(ips) > 0 {
		rules = append(rules, map[string]any{"ip": ips, "outboundTag": "system", "ruleTag": "system_route"})
	}
	if len(domains) > 0 {
		rules = append(rules, map[string]any{"domain": domains, "outboundTag": "system", "ruleTag": "system_route"})
	}
	return rules
}

func isIPOrCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
