package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Rules is the routing rules file.
type Rules struct {
	// Outbound for traffic that matches no rule: proxy, direct or block.
	Default string `yaml:"default"`
	// How domains are resolved for IP rules: AsIs, IPIfNonMatch, IPOnDemand.
	DomainStrategy string `yaml:"domain_strategy"`
	Rules          []Rule `yaml:"rules"`
	// Named groups of servers Xray balances between; use as pool:<name>.
	Pools map[string]PoolSpec `yaml:"pools"`
	// Health check deciding which pool members are usable.
	PoolProbe PoolProbe `yaml:"pool_probe"`
	// Optional Xray "dns" object, passed through unchanged apart from
	// checking its "ext:" file references.
	DNS map[string]any `yaml:"dns"`
}

// PoolSpec defines a pool in the rules file.
type PoolSpec struct {
	// Server queries: an index, group/name, or text matched against names
	// ("Швеция" picks every Swedish server). "*" means all servers.
	Servers StringList `yaml:"servers"`
	// leastPing (fastest working server), leastLoad, random or roundRobin.
	Strategy string `yaml:"strategy"`
}

// PoolProbe is the health check for all pools. Xray allows one per config.
type PoolProbe struct {
	// URL fetched through each member. Use the site you care about, e.g.
	// https://www.youtube.com/ to only use servers where YouTube works.
	URL      string   `yaml:"url"`
	Interval Duration `yaml:"interval"`
}

// Rule matches traffic and sends it to an outbound. Domain and IP lists are
// alternatives (a connection matching either one matches); every other
// field narrows the rule further.
type Rule struct {
	Name     string     `yaml:"name"`
	Outbound string     `yaml:"outbound"`
	Domain   StringList `yaml:"domain"`
	IP       StringList `yaml:"ip"`
	Port     StringList `yaml:"port"`
	Network  StringList `yaml:"network"`
	Protocol StringList `yaml:"protocol"`
	Source   StringList `yaml:"source"`
	Process  StringList `yaml:"process"`
	Inbound  StringList `yaml:"inbound"`
}

// StringList accepts either a single scalar or a list in YAML.
type StringList []string

func (l *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*l = splitCSV(n.Value)
		return nil
	case yaml.SequenceNode:
		var out []string
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: expected a string", item.Line)
			}
			out = append(out, strings.TrimSpace(item.Value))
		}
		*l = out
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list", n.Line)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LoadRules reads and validates a rules file.
func LoadRules(path string) (*Rules, error) {
	data, err := readPath(path, maxConfig)
	if err != nil {
		return nil, fmt.Errorf("rules file: %w (create one with `proxy-router init`)", err)
	}
	r := &Rules{Default: "proxy", DomainStrategy: "IPIfNonMatch"}
	if err := decodeStrict(data, r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

func (r *Rules) validate() error {
	for name, p := range r.Pools {
		if name == "" || strings.ContainsAny(name, "~: ") {
			return fmt.Errorf("pools: bad pool name %q", name)
		}
		if len(p.Servers) == 0 {
			return fmt.Errorf("pools.%s: servers is empty", name)
		}
		switch p.Strategy {
		case "", "leastPing", "leastLoad", "random", "roundRobin":
		default:
			return fmt.Errorf("pools.%s: strategy must be leastPing, leastLoad, random or roundRobin", name)
		}
	}
	if u := r.PoolProbe.URL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("pool_probe.url must be an http(s) URL")
	}
	if iv := r.PoolProbe.Interval.D(); iv != 0 && iv < 10*time.Second {
		return fmt.Errorf("pool_probe.interval must be at least 10s")
	}
	checkOutbound := func(o string) error {
		if name, ok := strings.CutPrefix(o, "pool:"); ok {
			if _, exists := r.Pools[name]; !exists {
				return fmt.Errorf("unknown pool %q (define it under pools:)", name)
			}
			return nil
		}
		return checkOutbound(o)
	}
	if err := checkOutbound(r.Default); err != nil {
		return fmt.Errorf("default: %w", err)
	}
	switch r.DomainStrategy {
	case "AsIs", "IPIfNonMatch", "IPOnDemand":
	default:
		return fmt.Errorf("domain_strategy must be AsIs, IPIfNonMatch or IPOnDemand, got %q", r.DomainStrategy)
	}
	for i, rule := range r.Rules {
		label := rule.Label(i)
		if err := checkOutbound(rule.Outbound); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if len(rule.Domain)+len(rule.IP)+len(rule.Port)+len(rule.Network)+len(rule.Protocol)+
			len(rule.Source)+len(rule.Process)+len(rule.Inbound) == 0 {
			return fmt.Errorf("%s: rule has no conditions", label)
		}
		for _, n := range rule.Network {
			if n != "tcp" && n != "udp" {
				return fmt.Errorf("%s: network must be tcp or udp, got %q", label, n)
			}
		}
		for _, in := range rule.Inbound {
			if in != "socks" && in != "http" && in != "tun" {
				return fmt.Errorf("%s: inbound must be socks, http or tun, got %q", label, in)
			}
		}
		for _, list := range []StringList{rule.Domain, rule.IP, rule.Source} {
			for _, v := range list {
				if err := checkGeoRef(v); err != nil {
					return fmt.Errorf("%s: %w", label, err)
				}
			}
		}
	}
	if err := checkDNSRefs(r.DNS, "dns"); err != nil {
		return err
	}
	return nil
}

// checkGeoRef checks an Xray "ext:file:tag" reference (also ext-ip: and
// ext-domain:) names a file in the assets directory. Xray joins the name
// to the directory as is, so "ext:../../x:tag" would read any file.
func checkGeoRef(v string) error {
	v = strings.TrimPrefix(strings.TrimSpace(v), "!")
	for _, prefix := range []string{"ext:", "ext-ip:", "ext-domain:"} {
		rest, ok := strings.CutPrefix(v, prefix)
		if !ok {
			continue
		}
		file, _, _ := strings.Cut(rest, ":")
		if file == "" || file != filepath.Base(file) || !filepath.IsLocal(file) || strings.ContainsRune(file, '\\') {
			return fmt.Errorf("%q: the file must be a plain name in the assets directory", v)
		}
	}
	return nil
}

// checkDNSRefs runs checkGeoRef on every key and string in the dns block:
// host and server domain lists, expectedIPs and the like all accept them.
func checkDNSRefs(v any, at string) error {
	switch v := v.(type) {
	case string:
		if err := checkGeoRef(v); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
	case []any:
		for i, item := range v {
			if err := checkDNSRefs(item, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := checkGeoRef(k); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if err := checkDNSRefs(v[k], at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

// Label names a rule in messages.
func (r Rule) Label(i int) string {
	if r.Name != "" {
		return fmt.Sprintf("rule %d (%s)", i+1, r.Name)
	}
	return fmt.Sprintf("rule %d", i+1)
}

func checkOutbound(o string) error {
	switch {
	case o == "proxy", o == "direct", o == "block":
		return nil
	case strings.HasPrefix(o, "server:") && strings.TrimSpace(o[len("server:"):]) != "":
		return nil
	case o == "":
		return fmt.Errorf("outbound is required (proxy, direct, block, server:<name> or pool:<name>)")
	}
	return fmt.Errorf("unknown outbound %q (use proxy, direct, block, server:<name> or pool:<name>)", o)
}

// NeedsGeo reports whether the rules reference geoip.dat / geosite.dat.
func (r *Rules) NeedsGeo() (geoip, geosite bool) {
	for _, rule := range r.Rules {
		for _, d := range rule.Domain {
			if strings.HasPrefix(d, "geosite:") {
				geosite = true
			}
		}
		for _, ip := range append(append([]string{}, rule.IP...), rule.Source...) {
			if strings.HasPrefix(ip, "geoip:") || strings.HasPrefix(ip, "!geoip:") {
				geoip = true
			}
		}
	}
	return geoip, geosite
}
