package share

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Protocols that never carry user traffic to a remote server.
var helperProtocols = map[string]bool{
	"freedom": true, "blackhole": true, "dns": true, "loopback": true,
}

// ParseXrayJSON parses an Xray JSON config, or an array of them (the format
// panels like Remnawave/Marzban serve to Happ). Each config becomes one
// server: its "proxy" outbound (or the first non-helper outbound) plus any
// outbounds it chains through via dialerProxy / proxySettings.
func ParseXrayJSON(data []byte) ([]*Server, []error) {
	data = []byte(strings.TrimSpace(string(data)))
	var configs []map[string]any
	if len(data) > 0 && data[0] == '[' {
		if err := json.Unmarshal(data, &configs); err != nil {
			return nil, []error{fmt.Errorf("json: %w", err)}
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, []error{fmt.Errorf("json: %w", err)}
		}
		configs = []map[string]any{one}
	}

	var (
		servers []*Server
		errs    []error
	)
	for i, cfg := range configs {
		s, err := serverFromConfig(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("config #%d: %w", i+1, err))
			continue
		}
		servers = append(servers, s)
	}
	return servers, errs
}

func serverFromConfig(cfg map[string]any) (*Server, error) {
	if s, err := poolFromConfig(cfg); s != nil || err != nil {
		return s, err
	}
	rawOutbounds, _ := cfg["outbounds"].([]any)
	byTag := map[string]map[string]any{}
	var main map[string]any
	for _, o := range rawOutbounds {
		ob, ok := o.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if tag != "" {
			byTag[tag] = ob
		}
		proto, _ := ob["protocol"].(string)
		if tag == "proxy" || (main == nil && !helperProtocols[proto]) {
			if main == nil || tag == "proxy" {
				main = ob
			}
		}
	}
	if main == nil {
		return nil, fmt.Errorf("no proxy outbound found")
	}
	if _, ok := main["protocol"].(string); !ok {
		return nil, fmt.Errorf("proxy outbound has no protocol")
	}

	// Collect outbounds the main one depends on, transitively.
	var chain []map[string]any
	seen := map[string]bool{}
	mainTag, _ := main["tag"].(string)
	seen[mainTag] = true
	queue := dependencies(main)
	for len(queue) > 0 {
		tag := queue[0]
		queue = queue[1:]
		if seen[tag] {
			continue
		}
		seen[tag] = true
		dep, ok := byTag[tag]
		if !ok {
			return nil, fmt.Errorf("outbound references unknown tag %q", tag)
		}
		chain = append(chain, dep)
		queue = append(queue, dependencies(dep)...)
	}

	var warnings []string
	for _, ob := range append([]map[string]any{main}, chain...) {
		warnings = append(warnings, sanitizeOutbound(ob)...)
	}

	s := &Server{Protocol: main["protocol"].(string)}
	s.Name, _ = cfg["remarks"].(string)
	s.Address, s.Port = endpoint(main)
	if s.Name == "" {
		s.Name = fmt.Sprintf("%s:%d", s.Address, s.Port)
	}
	var err error
	if s.Outbound, err = json.Marshal(main); err != nil {
		return nil, err
	}
	for _, dep := range chain {
		raw, err := json.Marshal(dep)
		if err != nil {
			return nil, err
		}
		s.Chain = append(s.Chain, raw)
	}
	s.Warnings = warnings
	return s, nil
}

// poolFromConfig recognises configs whose user traffic goes to a balancer
// (e.g. "Auto"). It returns nil, nil for ordinary configs.
func poolFromConfig(cfg map[string]any) (*Server, error) {
	routing, _ := cfg["routing"].(map[string]any)
	balancers, _ := routing["balancers"].([]any)
	if len(balancers) == 0 {
		return nil, nil
	}
	// The balancer that handles the user's traffic: a rule with a
	// balancerTag for the socks/http inbounds (or for everything).
	var target string
	rules, _ := routing["rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		bt, _ := rule["balancerTag"].(string)
		if bt == "" {
			continue
		}
		inbounds, _ := rule["inboundTag"].([]any)
		forUser := len(inbounds) == 0
		for _, in := range inbounds {
			if in == "socks" || in == "http" {
				forUser = true
			}
		}
		if forUser {
			target = bt
			break
		}
	}
	if target == "" {
		return nil, nil
	}
	var balancer map[string]any
	for _, b := range balancers {
		if m, _ := b.(map[string]any); m != nil && m["tag"] == target {
			balancer = m
		}
	}
	if balancer == nil {
		return nil, fmt.Errorf("routing uses unknown balancer %q", target)
	}
	var selector []string
	for _, s := range asList(balancer["selector"]) {
		if str, ok := s.(string); ok && str != "" {
			selector = append(selector, str)
		}
	}

	rawOutbounds, _ := cfg["outbounds"].([]any)
	byTag := map[string]map[string]any{}
	var members []map[string]any
	for _, o := range rawOutbounds {
		ob, _ := o.(map[string]any)
		tag, _ := ob["tag"].(string)
		if ob == nil || tag == "" {
			continue
		}
		byTag[tag] = ob
		proto, _ := ob["protocol"].(string)
		if helperProtocols[proto] {
			continue
		}
		for _, sel := range selector {
			if strings.HasPrefix(tag, sel) {
				members = append(members, ob)
				break
			}
		}
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("balancer %q has no servers", target)
	}

	// Helpers any member dials through.
	var chain []map[string]any
	seen := map[string]bool{}
	for _, m := range members {
		t, _ := m["tag"].(string)
		seen[t] = true
	}
	var queue []string
	for _, m := range members {
		queue = append(queue, dependencies(m)...)
	}
	for len(queue) > 0 {
		tag := queue[0]
		queue = queue[1:]
		if seen[tag] {
			continue
		}
		seen[tag] = true
		dep, ok := byTag[tag]
		if !ok {
			return nil, fmt.Errorf("outbound references unknown tag %q", tag)
		}
		chain = append(chain, dep)
		queue = append(queue, dependencies(dep)...)
	}

	s := &Server{Pool: &Pool{Selector: selector}}
	for _, ob := range append(append([]map[string]any{}, members...), chain...) {
		s.Warnings = append(s.Warnings, sanitizeOutbound(ob)...)
	}
	for _, m := range members {
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		s.Pool.Members = append(s.Pool.Members, raw)
	}
	for _, dep := range chain {
		raw, err := json.Marshal(dep)
		if err != nil {
			return nil, err
		}
		s.Chain = append(s.Chain, raw)
	}
	if st, ok := balancer["strategy"]; ok {
		s.Pool.Strategy, _ = json.Marshal(st)
	}
	if bo, ok := cfg["burstObservatory"].(map[string]any); ok && bo["pingConfig"] != nil {
		s.Pool.Probe, _ = json.Marshal(bo["pingConfig"])
	}
	s.Outbound = s.Pool.Members[0]
	s.Protocol, _ = members[0]["protocol"].(string)
	s.Address, s.Port = endpoint(members[0])
	s.Name, _ = cfg["remarks"].(string)
	if s.Name == "" {
		s.Name = fmt.Sprintf("pool of %d", len(members))
	}
	if fb, _ := balancer["fallbackTag"].(string); fb != "" {
		proto, _ := byTag[fb]["protocol"].(string)
		if byTag[fb] == nil || helperProtocols[proto] {
			s.Warnings = append(s.Warnings, fmt.Sprintf(
				"provider falls back to %q (unproxied) when servers look down; using the first server instead", fb))
		}
	}
	return s, nil
}

func asList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case string:
		return []any{x}
	}
	return nil
}

// dependencies returns tags an outbound routes its own traffic through.
func dependencies(ob map[string]any) []string {
	var tags []string
	if ss, ok := ob["streamSettings"].(map[string]any); ok {
		if so, ok := ss["sockopt"].(map[string]any); ok {
			if t, _ := so["dialerProxy"].(string); t != "" {
				tags = append(tags, t)
			}
		}
	}
	if ps, ok := ob["proxySettings"].(map[string]any); ok {
		if t, _ := ps["tag"].(string); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// renameDependencies rewrites dependency tags in place using rename.
func renameDependencies(ob map[string]any, rename func(string) string) {
	if ss, ok := ob["streamSettings"].(map[string]any); ok {
		if so, ok := ss["sockopt"].(map[string]any); ok {
			if t, _ := so["dialerProxy"].(string); t != "" {
				so["dialerProxy"] = rename(t)
			}
		}
	}
	if ps, ok := ob["proxySettings"].(map[string]any); ok {
		if t, _ := ps["tag"].(string); t != "" {
			ps["tag"] = rename(t)
		}
	}
}

// sanitizeOutbound removes options the embedded Xray no longer accepts.
func sanitizeOutbound(ob map[string]any) []string {
	var warnings []string
	if ss, ok := ob["streamSettings"].(map[string]any); ok {
		if tls, ok := ss["tlsSettings"].(map[string]any); ok {
			if v, ok := tls["allowInsecure"]; ok {
				delete(tls, "allowInsecure")
				if v == true {
					warnings = append(warnings, "allowInsecure is no longer supported by Xray; certificate will be verified")
				}
			}
		}
	}
	return warnings
}

// endpoint extracts the server address for display purposes.
func endpoint(ob map[string]any) (string, int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	pick := func(m map[string]any) (string, int) {
		addr, _ := m["address"].(string)
		port, _ := m["port"].(float64)
		if ep, ok := m["endpoint"].(string); ok && addr == "" {
			return ep, 0
		}
		return addr, int(port)
	}
	if a, p := pick(settings); a != "" {
		return a, p
	}
	for _, key := range []string{"vnext", "servers", "peers"} {
		if list, ok := settings[key].([]any); ok && len(list) > 0 {
			if m, ok := list[0].(map[string]any); ok {
				return pick(m)
			}
		}
	}
	return "", 0
}
