// Package config loads the user-editable settings (config.yaml), the routing
// rules file (routing.yaml) and the CLI-managed state (state.json).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Dir returns the directory holding all proxy-router files.
// $PROXY_ROUTER_HOME overrides the default (~/.config/proxy-router).
func Dir() (string, error) {
	if d := os.Getenv("PROXY_ROUTER_HOME"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "windows" {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "proxy-router"), nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "proxy-router"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// Under sudo (TUN mode) keep using the invoking user's files.
	if u := sudoUser(); u != nil {
		home = u.HomeDir
	}
	return filepath.Join(home, ".config", "proxy-router"), nil
}

// Config is config.yaml.
type Config struct {
	Listen struct {
		Socks string `yaml:"socks"`
		HTTP  string `yaml:"http"`
		// Login required by both, if set. Listening beyond loopback needs
		// one, or AllowOpen.
		User      string `yaml:"user"`
		Password  string `yaml:"password"`
		AllowOpen bool   `yaml:"allow_open"`
	} `yaml:"listen"`
	// Path to the routing rules file, relative to the config directory.
	Rules string `yaml:"rules"`
	// Xray log level: debug, info, warning, error, none.
	LogLevel string `yaml:"log_level"`
	// Print one line per connection showing which outbound handled it.
	AccessLog bool `yaml:"access_log"`
	// Refresh subscriptions older than this when `run` starts. 0 disables.
	UpdateInterval Duration `yaml:"update_interval"`
	// Network interface for proxy-router's own connections: "auto" (bypass
	// another VPN's tunnel if one owns the default route), "none", or a name.
	BindInterface string `yaml:"bind_interface"`
	// User-Agent for subscription requests unless overridden per subscription.
	UserAgent string `yaml:"user_agent"`
	Geo       struct {
		GeoIP   string `yaml:"geoip"`
		GeoSite string `yaml:"geosite"`
	} `yaml:"geo"`
	Ping struct {
		URL     string   `yaml:"url"`
		Timeout Duration `yaml:"timeout"`
		// Max simultaneous tests against one server IP. Providers often
		// put many "servers" behind one entry point that drops bursts.
		PerEndpoint int `yaml:"per_endpoint"`
	} `yaml:"ping"`

	// Destinations that always use the system's own routing: never proxied
	// and never pinned to an interface. Keeps Tailscale and other VPNs'
	// private ranges reachable.
	SystemRoute []string `yaml:"system_route"`

	// Resolve destination names here (DNS-over-HTTPS through the tunnel)
	// and send servers IPs, instead of letting each server resolve them.
	// Servers' own resolvers can return broken answers: with the default
	// subscription, YouTube failed through every server until this was on.
	ResolveLocally bool `yaml:"resolve_locally"`

	// Look server hostnames up with the system resolver (plain DNS) when
	// DNS-over-HTTPS to DirectDoH fails.
	SystemDNSFallback bool `yaml:"system_dns_fallback"`

	// Happ's advanced settings.
	Fragment    Fragment `yaml:"fragment"`
	Noises      Noises   `yaml:"noises"`
	Mux         Mux      `yaml:"mux"`
	PreferredIP string   `yaml:"preferred_ip"` // auto, ipv4, ipv6, ipv4v6, ipv6v4
	TUN         TUN      `yaml:"tun"`

	dir string
}

func defaults() *Config {
	c := &Config{}
	c.Listen.Socks = "127.0.0.1:10808"
	c.Listen.HTTP = "127.0.0.1:10809"
	c.Rules = "routing.yaml"
	c.LogLevel = "warning"
	c.BindInterface = "auto"
	c.UpdateInterval = Duration(12 * time.Hour)
	c.Geo.GeoIP = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	c.Geo.GeoSite = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	c.Ping.URL = "https://www.gstatic.com/generate_204"
	c.Ping.Timeout = Duration(5 * time.Second)
	c.Ping.PerEndpoint = 2
	c.SystemRoute = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "domain:ts.net"}
	c.Fragment = Fragment{Packets: "tlshello", Length: Range{50, 100}, Delay: Range{10, 20}, MaxSplit: Range{3, 6}}
	c.Mux = Mux{Concurrency: 8, XUDPConcurrency: 16, XUDPProxyUDP443: "reject"}
	c.PreferredIP = "ipv4"
	c.ResolveLocally = true
	c.SystemDNSFallback = true
	c.TUN.MTU = 1500
	return c
}

// Load reads config.yaml from dir. A missing file yields the defaults.
func Load(dir string) (*Config, error) {
	c := defaults()
	c.dir = dir
	data, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(data, c); err != nil {
		return nil, fmt.Errorf("config.yaml: %w", err)
	}
	if err := c.validateTweaks(); err != nil {
		return nil, fmt.Errorf("config.yaml: %w", err)
	}
	return c, nil
}

// Dir is the directory the config was loaded from.
func (c *Config) Dir() string { return c.dir }

// AssetDir holds geoip.dat / geosite.dat.
func (c *Config) AssetDir() string { return filepath.Join(c.dir, "assets") }

// RulesPath resolves the rules file path.
func (c *Config) RulesPath() string { return c.resolve(c.Rules) }

func (c *Config) resolve(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if p[0] == '~' {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return filepath.Join(c.dir, p)
}

func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(v)
	if errors.Is(err, io.EOF) {
		return nil // empty file
	}
	return err
}

// Duration is a time.Duration that reads "12h", "30m" or "0" from YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Value == "0" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: bad duration %q (use e.g. 30s, 12h)", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// sudoUser returns the user who ran sudo, when running as root via sudo.
func sudoUser() *user.User {
	if os.Geteuid() != 0 || os.Getenv("SUDO_UID") == "" {
		return nil
	}
	u, err := user.LookupId(os.Getenv("SUDO_UID"))
	if err != nil {
		return nil
	}
	return u
}

// owner is who files written as root should belong to when there's no sudo
// user: the owner of the config directory (the background service runs as
// root with --dir pointing at the user's directory).
var owner struct {
	set      bool
	uid, gid int
}

// SetOwnerFromDir makes GiveBack hand files to dir's owner when running as
// root outside sudo.
func SetOwnerFromDir(dir string) {
	if os.Geteuid() != 0 {
		return
	}
	if st, ok := statOwner(dir); ok && st.uid != 0 {
		owner.set, owner.uid, owner.gid = true, st.uid, st.gid
	}
}

// GiveBack hands a file created as root back to the user, so running as
// root (sudo, or the TUN service) doesn't leave root-owned files behind.
func GiveBack(path string) {
	if u := sudoUser(); u != nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Lchown(path, uid, gid)
		return
	}
	if owner.set && os.Geteuid() == 0 {
		_ = os.Lchown(path, owner.uid, owner.gid)
	}
}

// WriteFileAtomic writes via a temp file so readers never see partial data.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	GiveBack(tmp.Name())
	return os.Rename(tmp.Name(), path)
}
