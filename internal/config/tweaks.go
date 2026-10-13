package config

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Range is "min-max" (or a single number) as in Happ's settings.
type Range struct {
	From, To int
}

func (r *Range) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseRange(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*r = v
	return nil
}

func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	a, b, isRange := strings.Cut(s, "-")
	from, err1 := strconv.Atoi(strings.TrimSpace(a))
	to := from
	var err2 error
	if isRange {
		to, err2 = strconv.Atoi(strings.TrimSpace(b))
	}
	if err1 != nil || err2 != nil || from < 0 {
		return Range{}, fmt.Errorf("%q is not a range like 10-20", s)
	}
	if from > to {
		// Xray accepts this silently and then does nothing.
		return Range{}, fmt.Errorf("%q: min is larger than max", s)
	}
	return Range{from, to}, nil
}

func (r Range) IsZero() bool { return r == Range{} }

// String renders the form Xray expects ("10-20", or "10").
func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Fragment splits the first TCP packets (the TLS ClientHello) to get past
// DPI. Same fields as Happ's "Enable Fragmentation" with type Xray.
type Fragment struct {
	Enabled bool `yaml:"enabled"`
	// "tlshello" or a range of TCP segments, e.g. "1-3".
	Packets  string `yaml:"packets"`
	Length   Range  `yaml:"length"`    // bytes per fragment
	Delay    Range  `yaml:"delay"`     // ms between fragments
	MaxSplit Range  `yaml:"max_split"` // fragments per packet
}

// Noise sends junk UDP packets before a UDP based connection (Hysteria2,
// WireGuard, mKCP). Same fields as Happ's "Enable Noises".
type Noise struct {
	// array (comma separated bytes), str, hex or base64.
	Type   string `yaml:"type"`
	Packet string `yaml:"packet"`
	Delay  Range  `yaml:"delay"` // ms
	// With an empty packet: random length and byte value range.
	Rand      Range `yaml:"rand"`
	RandRange Range `yaml:"rand_range"`
}

type Noises struct {
	Enabled bool    `yaml:"enabled"`
	Items   []Noise `yaml:"items"`
}

type Mux struct {
	Enabled         bool   `yaml:"enabled"`
	Concurrency     int    `yaml:"concurrency"`
	XUDPConcurrency int    `yaml:"xudp_concurrency"`
	XUDPProxyUDP443 string `yaml:"xudp_proxy_udp443"` // reject, allow, skip
}

type TUN struct {
	Enabled bool `yaml:"enabled"`
	// Interface name. macOS needs utunN; empty picks a free one.
	Name string `yaml:"name"`
	MTU  int    `yaml:"mtu"`
	// Also capture IPv6 so it can't leak around the proxy.
	IPv6 bool `yaml:"ipv6"`
}

// PreferredIPStrategy maps preferred_ip to Xray's domainStrategy.
func (c *Config) PreferredIPStrategy() string {
	switch c.PreferredIP {
	case "ipv4":
		return "UseIPv4"
	case "ipv6":
		return "UseIPv6"
	case "ipv4v6":
		return "UseIPv4v6"
	case "ipv6v4":
		return "UseIPv6v4"
	}
	return ""
}

// NoisePacket converts a noise packet to the JSON value Xray expects.
func (n Noise) JSONPacket() (any, error) {
	if n.Packet == "" {
		return nil, nil
	}
	if n.Type == "array" || n.Type == "" {
		var out []int
		for _, part := range strings.Split(n.Packet, ",") {
			part = strings.TrimSpace(part)
			v, err := strconv.ParseInt(part, 0, 16)
			if err != nil || v < 0 || v > 255 {
				return nil, fmt.Errorf("noise packet: %q is not a byte (0-255)", part)
			}
			out = append(out, int(v))
		}
		return out, nil
	}
	return n.Packet, nil
}

func (c *Config) validateTweaks() error {
	if f := c.Fragment; f.Enabled {
		if f.Packets != "tlshello" {
			r, err := ParseRange(f.Packets)
			if err != nil || r.From == 0 {
				return fmt.Errorf("fragment.packets must be tlshello or a range starting at 1, like 1-3")
			}
		}
		if f.Length.From == 0 {
			return fmt.Errorf("fragment.length must start at 1 or more, e.g. 50-100")
		}
	}
	if c.Noises.Enabled {
		if len(c.Noises.Items) == 0 {
			return fmt.Errorf("noises.enabled is true but noises.items is empty")
		}
		for i, n := range c.Noises.Items {
			label := fmt.Sprintf("noises.items[%d]", i)
			switch n.Type {
			case "", "array", "str":
			case "hex":
				if _, err := hex.DecodeString(n.Packet); err != nil {
					return fmt.Errorf("%s: packet is not hex", label)
				}
			case "base64":
			default:
				return fmt.Errorf("%s: type must be array, str, hex or base64", label)
			}
			if _, err := n.JSONPacket(); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			if n.Packet != "" && n.Rand.To > 0 {
				return fmt.Errorf("%s: set either packet or rand, not both", label)
			}
			if n.Packet == "" && n.Rand.To == 0 {
				return fmt.Errorf("%s: needs a packet or a rand length", label)
			}
			if n.RandRange.To > 255 {
				return fmt.Errorf("%s: rand_range must be within 0-255", label)
			}
		}
	}
	if m := c.Mux; m.Enabled {
		if m.Concurrency < 1 || m.Concurrency > 1024 {
			return fmt.Errorf("mux.concurrency must be 1-1024")
		}
		if m.XUDPConcurrency < 0 || m.XUDPConcurrency > 1024 {
			return fmt.Errorf("mux.xudp_concurrency must be 0-1024")
		}
		switch m.XUDPProxyUDP443 {
		case "", "reject", "allow", "skip":
		default:
			return fmt.Errorf("mux.xudp_proxy_udp443 must be reject, allow or skip")
		}
	}
	switch c.PreferredIP {
	case "", "auto", "ipv4", "ipv6", "ipv4v6", "ipv6v4":
	default:
		return fmt.Errorf("preferred_ip must be auto, ipv4, ipv6, ipv4v6 or ipv6v4")
	}
	if c.TUN.MTU != 0 && (c.TUN.MTU < 576 || c.TUN.MTU > 9000) {
		return fmt.Errorf("tun.mtu must be between 576 and 9000")
	}
	return nil
}
