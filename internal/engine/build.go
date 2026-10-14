// Package engine turns proxy-router settings into an Xray config and runs
// Xray-core in-process.
package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
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
	// TUNListen is the loopback SOCKS address the TUN front forwards to (see
	// BuildTUNFront); empty means proxy-only. Traffic arriving there is
	// tagged "tun".
	TUNListen string
	// When set, server hostnames are resolved now and replaced by IPs.
	Resolve Resolver
}

// target is where a rule sends traffic: an outbound or a balancer.
type target struct {
	tag      string
	balancer bool
}

func (t target) set(m map[string]any) {
	if t.balancer {
		m["balancerTag"] = t.tag
	} else {
		m["outboundTag"] = t.tag
	}
}

// Build returns the Xray JSON config as a map, plus notes about settings
// that don't apply to the chosen servers.
func Build(p Plan) (map[string]any, []string, error) {
	cfg, rules := p.Config, p.Rules
	var (
		notes     []string
		outbounds []map[string]any
		balancers []map[string]any
		observed  []string // balancer selectors the health check covers
		probes    []map[string]any
	)
	// prepare applies Happ-style tweaks, address pinning and interface
	// binding to a server's outbounds (only the servers, not chain helpers).
	prepare := func(name string, obs []map[string]any, primaries int) []map[string]any {
		var n []string
		for i := 0; i < primaries && i < len(obs); i++ {
			_, tn := ApplyTweaks(obs[i:i+1], cfg)
			n = append(n, tn...)
		}
		if p.Resolve != nil {
			n = append(n, PinAddresses(obs, p.Resolve)...)
		}
		for _, note := range dedupe(n) {
			notes = append(notes, fmt.Sprintf("%s: %s", name, note))
		}
		return BindInterface(obs, p.Interface)
	}
	// addBalancer registers a balancer over outbounds whose tags start with
	// one of selector, falling back to the first member, never to direct.
	addBalancer := func(tag string, selector []string, strategy any, fallback string, probe map[string]any) {
		if strategy == nil {
			strategy = map[string]any{"type": "leastPing"}
		}
		balancers = append(balancers, map[string]any{
			"tag": tag, "selector": selector, "strategy": strategy, "fallbackTag": fallback,
		})
		observed = append(observed, selector...)
		if probe != nil {
			probes = append(probes, probe)
		}
	}
	// addServer adds e under tag and returns how rules reach it.
	addServer := func(e config.Entry, tag string) (target, error) {
		obs, err := e.Server.Outbounds(tag)
		if err != nil {
			return target{}, err
		}
		outbounds = append(outbounds, prepare(e.Server.Name, obs, e.Server.Primaries())...)
		pool := e.Server.Pool
		if pool == nil {
			return target{tag: tag}, nil
		}
		var selector []string
		for _, sel := range pool.Selector {
			selector = append(selector, share.MemberTag(tag, sel))
		}
		var strategy, probe map[string]any
		_ = json.Unmarshal(pool.Strategy, &strategy)
		_ = json.Unmarshal(pool.Probe, &probe)
		addBalancer(tag, selector, nilIfEmpty(strategy), obs[0]["tag"].(string), nilIfEmpty(probe))
		return target{tag: tag, balancer: true}, nil
	}

	targets := map[string]target{
		"direct": {tag: "direct"},
		"block":  {tag: "block"},
	}
	used := map[string]bool{rules.Default: true}
	for _, r := range rules.Rules {
		used[r.Outbound] = true
	}

	proxy := p.Server
	if proxy == nil {
		if cur, ok := p.State.Current(); ok {
			proxy = &cur
		}
	}
	if proxy != nil {
		t, err := addServer(*proxy, "proxy")
		if err != nil {
			return nil, nil, err
		}
		targets["proxy"] = t
	} else if used["proxy"] {
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
	sysRules := systemRouteRules(cfg.SystemRoute, p.TUNListen != "")
	if len(sysRules) > 0 {
		outbounds = append(outbounds, freedom("system"))
	}

	// Rules that target a specific server, tagged with the server's name so
	// the access log reads "[socks -> server:USA]".
	byIndex := map[int]target{}
	for i, r := range rules.Rules {
		query, ok := strings.CutPrefix(r.Outbound, "server:")
		if !ok {
			continue
		}
		if _, done := targets[r.Outbound]; done {
			continue
		}
		e, err := p.State.Find(strings.TrimSpace(query))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.Label(i), err)
		}
		if t, ok := byIndex[e.Index]; ok {
			targets[r.Outbound] = t
			continue
		}
		tag := "server:" + e.Server.Name
		if slices.ContainsFunc(outbounds, func(o map[string]any) bool { return o["tag"] == tag }) {
			tag = fmt.Sprintf("server:#%d", e.Index) // duplicate names across groups
		}
		t, err := addServer(e, tag)
		if err != nil {
			return nil, nil, err
		}
		targets[r.Outbound], byIndex[e.Index] = t, t
	}

	// Pools from the rules file.
	for name, spec := range rules.Pools {
		ref := "pool:" + name
		if !used[ref] {
			continue
		}
		seen := map[int]bool{}
		var members []config.Entry
		for _, q := range spec.Servers {
			for _, e := range p.State.FindAll(q) {
				if seen[e.Index] {
					continue
				}
				seen[e.Index] = true
				if e.Server.Pool != nil {
					notes = append(notes, fmt.Sprintf("pool %s: skipping %s (it's a pool itself)", name, e.Server.Name))
					continue
				}
				members = append(members, e)
			}
		}
		if len(members) == 0 {
			return nil, nil, fmt.Errorf("pools.%s: no servers match %v", name, []string(spec.Servers))
		}
		var first string
		for _, e := range members {
			tag := share.MemberTag(ref, strconv.Itoa(e.Index))
			obs, err := e.Server.Outbounds(tag)
			if err != nil {
				return nil, nil, err
			}
			outbounds = append(outbounds, prepare(e.Server.Name, obs, 1)...)
			if first == "" {
				first = tag
			}
		}
		var strategy any
		if spec.Strategy != "" {
			strategy = map[string]any{"type": spec.Strategy}
		}
		addBalancer(ref, []string{share.MemberTag(ref, "")}, strategy, first, nil)
		targets[ref] = target{tag: ref, balancer: true}
	}

	// Xray's own lookups of server names go outside the tunnel.
	routingRules := []map[string]any{{
		"inboundTag": []string{config.DirectDNSTag}, "outboundTag": "direct", "ruleTag": "dns_direct",
	}}
	if p.TUNListen != "" {
		// Answer DNS that arrives through the TUN from Xray's own resolver
		// (cached, DoH through the tunnel) instead of forwarding each UDP
		// query through the servers, which loses some and is slow.
		outbounds = append(outbounds, map[string]any{
			"tag": "dns-out", "protocol": "dns", "settings": map[string]any{"nonIPQuery": "reject"},
		})
		routingRules = append(routingRules, map[string]any{
			"inboundTag": []string{"tun"}, "port": "53", "outboundTag": "dns-out", "ruleTag": "tun_dns",
		})
	}
	routingRules = append(routingRules, sysRules...)
	for _, r := range rules.Rules {
		routingRules = append(routingRules, xrayRules(r, targets[r.Outbound])...)
	}
	// Explicit catch-all so the default doesn't depend on outbound order.
	catchAll := map[string]any{"network": "tcp,udp"}
	targets[rules.Default].set(catchAll)
	routingRules = append(routingRules, catchAll)

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
	if p.TUNListen != "" {
		in, err := inbound("socks", p.TUNListen, map[string]any{"udp": true}, sniffing)
		if err != nil {
			return nil, nil, err
		}
		in["tag"] = "tun"
		inbounds = append(inbounds, in)
	}
	if len(inbounds) == 0 {
		return nil, nil, fmt.Errorf("config.yaml: listen.socks and listen.http are both empty")
	}

	access := "none"
	if cfg.AccessLog {
		access = ""
	}
	routing := map[string]any{
		"domainStrategy": rules.DomainStrategy,
		"rules":          routingRules,
	}
	out := map[string]any{
		"log":       map[string]any{"loglevel": cfg.LogLevel, "access": access},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}
	if len(balancers) > 0 {
		routing["balancers"] = balancers
		out["burstObservatory"] = map[string]any{
			"subjectSelector": observed,
			"pingConfig":      poolProbe(rules.PoolProbe, probes),
		}
	}
	if rules.DNS != nil {
		out["dns"] = rules.DNS
	} else if cfg.ResolveLocally || p.TUNListen != "" {
		hosts := hostnames(outbounds)
		if h := probeHost(out); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
		out["dns"] = cfg.LocalDNS(hosts)
	}
	return out, notes, nil
}

// hostnames lists server hostnames still in outbounds: TLS/REALITY names
// and addresses that couldn't be pinned. If Xray has to resolve one, it
// must not go through the tunnel that needs it.
func hostnames(obs []map[string]any) []string {
	var out []string
	add := func(h string) {
		if h != "" && !isIPOrCIDR(h) && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	for _, ob := range obs {
		settings, _ := ob["settings"].(map[string]any)
		if a, ok := settings["address"].(string); ok {
			add(a)
		}
		for _, key := range []string{"vnext", "servers"} {
			list, _ := settings[key].([]any)
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					a, _ := m["address"].(string)
					add(a)
				}
			}
		}
		peers, _ := settings["peers"].([]any)
		for _, item := range peers {
			if m, ok := item.(map[string]any); ok {
				ep, _ := m["endpoint"].(string)
				if host, _, err := net.SplitHostPort(ep); err == nil {
					add(host)
				}
			}
		}
	}
	return out
}

// probeHost is the pool health check's host, which every pool member must
// be able to reach before anything else works.
func probeHost(xc map[string]any) string {
	bo, _ := xc["burstObservatory"].(map[string]any)
	pc, _ := bo["pingConfig"].(map[string]any)
	dest, _ := pc["destination"].(string)
	if u, err := url.Parse(dest); err == nil {
		return u.Hostname()
	}
	return ""
}

// BuildTUNFront is the long-lived Xray instance that owns the TUN device and
// forwards everything to the main instance's "tun" SOCKS inbound at
// mainAddr. It never reloads: Xray doesn't release a TUN device when an
// instance closes, so recreating it on every config change fails with
// "device or resource busy". The main instance, with all servers, rules and
// DNS, restarts freely behind it.
func BuildTUNFront(name string, mtu int, mainAddr string) (map[string]any, error) {
	host, port, err := splitHostPort(mainAddr)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{map[string]any{
			"tag": "tun-device", "protocol": "tun", "port": 0,
			"settings": map[string]any{"name": name, "MTU": mtu},
		}},
		"outbounds": []any{map[string]any{
			"tag": "main", "protocol": "socks",
			"settings": map[string]any{"address": host, "port": port},
		}},
	}, nil
}

// poolProbe picks the health check: the rules file's, else a provider's,
// else a default. Xray runs one health check for all balancers.
func poolProbe(pp config.PoolProbe, provider []map[string]any) map[string]any {
	probe := map[string]any{
		"destination": "https://www.gstatic.com/generate_204",
		"interval":    "30s",
		"sampling":    2,
		"timeout":     "5s",
	}
	if len(provider) > 0 {
		probe = provider[0]
	}
	if pp.URL != "" {
		probe = map[string]any{"destination": pp.URL, "interval": "30s", "sampling": 2, "timeout": "8s"}
	}
	if pp.Interval != 0 {
		probe["interval"] = pp.Interval.D().String()
	}
	return probe
}

func nilIfEmpty(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	return m
}

func dedupe(s []string) []string {
	var out []string
	for _, v := range s {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
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
func xrayRules(r config.Rule, t target) []map[string]any {
	common := map[string]any{}
	t.set(common)
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
