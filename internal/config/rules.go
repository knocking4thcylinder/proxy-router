package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rules is the routing rules file.
type Rules struct {
	// Outbound for traffic that matches no rule: proxy, direct or block.
	Default string `yaml:"default"`
	// How domains are resolved for IP rules: AsIs, IPIfNonMatch, IPOnDemand.
	DomainStrategy string `yaml:"domain_strategy"`
	Rules          []Rule `yaml:"rules"`
	// Optional Xray "dns" object, passed through unchanged.
	DNS map[string]any `yaml:"dns"`
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
	data, err := os.ReadFile(path)
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
		return fmt.Errorf("outbound is required (proxy, direct, block or server:<name>)")
	}
	return fmt.Errorf("unknown outbound %q (use proxy, direct, block or server:<name>)", o)
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
