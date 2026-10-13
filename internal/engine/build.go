// Package engine turns proxy-router settings into an Xray config and runs
// Xray-core in-process.
package engine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

// Plan is everything needed to build a runnable Xray config.
type Plan struct {
	Config *config.Config
	Rules  *config.Rules
	State  *config.State
	// Server used for the "proxy" outbound; overrides the saved selection.
	Server *config.Entry
	// Interface to bind outgoing sockets to ("" = system routing).
	Interface string
	// TUN interface to create; empty means proxy-only.
	TUNName string
}

// Build returns the Xray JSON config as a map, plus notes about settings
// that don't apply to the chosen servers.
func Build(p Plan) (map[string]any, []string, error) {
	cfg, rules := p.Config, p.Rules
	var notes []string
	// serverOutbounds prepares a server: Happ-style tweaks, then interface.
	serverOutbounds := func(e config.Entry, tag string) ([]map[string]any, error) {
		obs, err := e.Server.Outbounds(tag)
		if err != nil {
			return nil, err
		}
		obs, n := ApplyTweaks(obs, cfg)
		for _, note := range n {
			notes = append(notes, fmt.Sprintf("%s: %s", e.Server.Name, note))
		}
		return BindInterface(obs, p.Interface), nil
	}

	var outbounds []map[string]any
	usesProxy := rules.Default == "proxy"
	for _, r := range rules.Rules {
		usesProxy = usesProxy || r.Outbound == "proxy"
	}
	proxy := p.Server
	if proxy == nil {
		if cur, ok := p.State.Current(); ok {
			proxy = &cur
		}
	}
	if proxy != nil {
		obs, err := serverOutbounds(*proxy, "proxy")
		if err != nil {
			return nil, nil, err
		}
		outbounds = append(outbounds, obs...)
	} else if usesProxy {
		return nil, nil, fmt.Errorf("no server selected; pick one with `proxy-router use <server>`")
	}
	freedom := func(tag string) map[string]any {
		ob := map[string]any{"tag": tag, "protocol": "freedom"}
		if ds := cfg.PreferredIPStrategy(); ds != "" {
			ob["settings"] = map[string]any{"domainStrategy": ds}
		}
		return ob
	}
	outbounds = append(outbounds, BindInterface([]map[string]any{freedom("direct")}, p.Interface)...)
	outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})
	// "system" follows the OS routing table: it's how traffic for Tailscale
	// and other VPNs' own routes reaches them.
	sysRules := systemRouteRules(cfg.SystemRoute)
	if len(sysRules) > 0 {
		outbounds = append(outbounds, freedom("system"))
	}

	// Outbounds for rules that target a specific server, tagged with the
	// server's name so the access log reads "[socks -> server:USA]".
	serverTags := map[string]string{} // query -> tag
	indexTags := map[int]string{}     // server index -> tag
	for i, r := range rules.Rules {
		query, ok := strings.CutPrefix(r.Outbound, "server:")
		if !ok {
			continue
		}
		query = strings.TrimSpace(query)
		if _, done := serverTags[query]; done {
			continue
		}
		e, err := p.State.Find(query)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.Label(i), err)
		}
		if tag, ok := indexTags[e.Index]; ok {
			serverTags[query] = tag
			continue
		}
		tag := fmt.Sprintf("server:%s", e.Server.Name)
		if slices.ContainsFunc(outbounds, func(o map[string]any) bool { return o["tag"] == tag }) {
			tag = fmt.Sprintf("server:#%d", e.Index) // duplicate names across groups
		}
		serverTags[query], indexTags[e.Index] = tag, tag
		obs, err := serverOutbounds(e, tag)
		if err != nil {
			return nil, nil, err
		}
		outbounds = append(outbounds, obs...)
	}
	outTag := func(o string) string {
		if q, ok := strings.CutPrefix(o, "server:"); ok {
			return serverTags[strings.TrimSpace(q)]
		}
		return o
	}

	routingRules := sysRules
	for _, r := range rules.Rules {
		routingRules = append(routingRules, xrayRules(r, outTag(r.Outbound))...)
	}
	// Explicit catch-all so the default doesn't depend on outbound order.
	routingRules = append(routingRules, map[string]any{
		"network":     "tcp,udp",
		"outboundTag": outTag(rules.Default),
	})

	sniffing := map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    true,
	}
	var inbounds []map[string]any
	if cfg.Listen.Socks != "" {
		in, err := inbound("socks", cfg.Listen.Socks, map[string]any{"udp": true}, sniffing)
		if err != nil {
			return nil, nil, err
		}
		inbounds = append(inbounds, in)
	}
	if cfg.Listen.HTTP != "" {
		in, err := inbound("http", cfg.Listen.HTTP, map[string]any{}, sniffing)
		if err != nil {
			return nil, nil, err
		}
		inbounds = append(inbounds, in)
	}
	if p.TUNName != "" {
		inbounds = append(inbounds, map[string]any{
			"tag":      "tun",
			"protocol": "tun",
			"port":     0,
			"settings": map[string]any{"name": p.TUNName, "MTU": cfg.TUN.MTU},
			"sniffing": sniffing,
		})
	}
	if len(inbounds) == 0 {
		return nil, nil, fmt.Errorf("config.yaml: listen.socks and listen.http are both empty")
	}

	access := "none"
	if cfg.AccessLog {
		access = ""
	}
	out := map[string]any{
		"log":       map[string]any{"loglevel": cfg.LogLevel, "access": access},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": rules.DomainStrategy,
			"rules":          routingRules,
		},
	}
	if rules.DNS != nil {
		out["dns"] = rules.DNS
	}
	return out, notes, nil
}

// BindInterface makes outbounds open their sockets on iface, so they bypass
// another VPN's tunnel. Outbounds that dial through another outbound
// (dialerProxy) or already pick an interface are left alone.
func BindInterface(obs []map[string]any, iface string) []map[string]any {
	if iface == "" {
		return obs
	}
	for _, ob := range obs {
		ss, _ := ob["streamSettings"].(map[string]any)
		if ss == nil {
			ss = map[string]any{}
			ob["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
			ss["sockopt"] = so
		}
		if so["dialerProxy"] != nil && so["dialerProxy"] != "" {
			continue
		}
		if cur, _ := so["interface"].(string); cur == "" {
			so["interface"] = iface
		}
	}
	return obs
}

// xrayRules converts one rule. Domain and IP lists become separate Xray
// rules because Xray ANDs fields within a rule, while users expect
// "these domains or these IPs".
func xrayRules(r config.Rule, tag string) []map[string]any {
	common := map[string]any{"outboundTag": tag}
	if r.Name != "" {
		common["ruleTag"] = r.Name
	}
	if len(r.Port) > 0 {
		common["port"] = strings.Join(r.Port, ",")
	}
	if len(r.Network) > 0 {
		common["network"] = strings.Join(r.Network, ",")
	}
	if len(r.Protocol) > 0 {
		common["protocol"] = []string(r.Protocol)
	}
	if len(r.Source) > 0 {
		common["source"] = []string(r.Source)
	}
	if len(r.Process) > 0 {
		common["process"] = []string(r.Process)
	}
	if len(r.Inbound) > 0 {
		common["inboundTag"] = []string(r.Inbound)
	}
	with := func(k string, v []string) map[string]any {
		m := map[string]any{k: v}
		for ck, cv := range common {
			m[ck] = cv
		}
		return m
	}
	switch {
	case len(r.Domain) > 0 && len(r.IP) > 0:
		return []map[string]any{with("domain", r.Domain), with("ip", r.IP)}
	case len(r.Domain) > 0:
		return []map[string]any{with("domain", r.Domain)}
	case len(r.IP) > 0:
		return []map[string]any{with("ip", r.IP)}
	}
	return []map[string]any{common}
}

func inbound(protocol, listen string, settings, sniffing map[string]any) (map[string]any, error) {
	host, port, err := splitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("config.yaml: listen.%s: %w", protocol, err)
	}
	return map[string]any{
		"tag":      protocol,
		"protocol": protocol,
		"listen":   host,
		"port":     port,
		"settings": settings,
		"sniffing": sniffing,
	}, nil
}
