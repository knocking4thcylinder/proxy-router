// Package config loads the user-editable settings (config.yaml), the routing
// rules file (routing.yaml) and the CLI-managed state (state.json).
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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

	// Happ's advanced settings.
	Fragment    Fragment `yaml:"fragment"`
	Noises      Noises   `yaml:"noises"`
	Mux         Mux      `yaml:"mux"`
	PreferredIP string   `yaml:"preferred_ip"` // auto, ipv4, ipv6, ipv4v6, ipv6v4
	TUN         TUN      `yaml:"tun"`

	dir      string
	assetDir string
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
	c.TUN.MTU = 1500
	return c
}

// Load reads config.yaml from dir. A missing file yields the defaults.
func Load(dir string) (*Config, error) {
	c := defaults()
	c.dir = dir
	if confined.on {
		c.assetDir = confined.assetDir
	}
	data, err := readFile(dir, "config.yaml", maxConfig)
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
	if confined.on && (!filepath.IsLocal(c.Rules) || strings.HasPrefix(c.Rules, "~")) {
		return nil, fmt.Errorf("config.yaml: rules: the TUN service only reads rules files inside %s, not %q", dir, c.Rules)
	}
	for _, e := range c.SystemRoute {
		if err := checkGeoRef(e); err != nil {
			return nil, fmt.Errorf("config.yaml: system_route: %w", err)
		}
	}
	return c, nil
}

// Dir is the directory the config was loaded from.
func (c *Config) Dir() string { return c.dir }

// AssetDir holds geoip.dat / geosite.dat: assets/ in the config
// directory, or the root-owned one given to Confine.
func (c *Config) AssetDir() string {
	if c.assetDir != "" {
		return c.assetDir
	}
	return filepath.Join(c.dir, "assets")
}

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
	if err != nil && confined.on {
		// The service's log may be readable by others (adm, admin); don't
		// copy values from the user's files into it.
		err = errors.New(yamlSnippet.ReplaceAllString(err.Error(), "`...`"))
	}
	return err
}

// yamlSnippet matches the values yaml.v3 quotes in its errors.
var yamlSnippet = regexp.MustCompile("`[^`]*`")

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

// Size limits for files read by the root service.
const (
	maxConfig = 4 << 20
	maxState  = 64 << 20
)

// confined is set by Confine.
var confined confinement

type confinement struct {
	on            bool
	dir, assetDir string
	uid           int
}

// Confine puts this process, running as root, in the TUN service's mode:
// config.yaml, the rules file and state.json are read from dir only
// through readConfined (no symlinks, regular files owned by uid, size
// capped), nothing is ever written there, and geo files live in assetDir,
// a root-owned directory, instead of dir/assets.
func Confine(dir string, uid int, assetDir string) {
	confined.on, confined.dir, confined.uid, confined.assetDir = true, filepath.Clean(dir), uid, assetDir
}

// Confined reports whether Confine was called.
func Confined() bool { return confined.on }

// readFile reads dir/name, through readConfined when confined.
func readFile(dir, name string, max int64) ([]byte, error) {
	if !confined.on {
		return os.ReadFile(filepath.Join(dir, name))
	}
	if filepath.Clean(dir) != confined.dir {
		return nil, fmt.Errorf("%s: the TUN service only reads files in %s", filepath.Join(dir, name), confined.dir)
	}
	return readConfined(dir, name, confined.uid, max)
}

// readPath is readFile for a path that has to be inside the confined
// directory.
func readPath(path string, max int64) ([]byte, error) {
	if !confined.on {
		return os.ReadFile(path)
	}
	rel, err := filepath.Rel(confined.dir, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("%s: the TUN service only reads files in %s", path, confined.dir)
	}
	return readConfined(confined.dir, rel, confined.uid, max)
}

// ReadUserFile reads a small file from the user's directory. As root it
// goes through readConfined with the sudo user as the owner, and refuses
// in the TUN service, which reads nothing there but its config.
func ReadUserFile(dir, name string) ([]byte, error) {
	const max = 1 << 20
	switch {
	case confined.on:
		return nil, errors.New("the TUN service doesn't read " + name)
	case os.Geteuid() != 0:
		return os.ReadFile(filepath.Join(dir, name))
	}
	u := sudoUser()
	if u == nil {
		return readConfined(dir, name, 0, max)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	return readConfined(dir, name, uid, max)
}

// GiveBack hands a file or directory created as root under sudo back to
// the user, so running as root doesn't leave root-owned files behind.
func GiveBack(path string) {
	if o := giveBackTo(); o != nil {
		_ = os.Lchown(path, o.uid, o.gid)
	}
}

type ids struct{ uid, gid int }

// giveBackTo is who files written as root belong to: the sudo user, or
// nobody (keep root's) in the TUN service, which only writes to its own
// root-owned directories.
func giveBackTo() *ids {
	if confined.on {
		return nil
	}
	u := sudoUser()
	if u == nil {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &ids{uid, gid}
}

// WriteFileAtomic writes via a temp file so readers never see partial data.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	_, err := WriteReaderAtomic(path, bytes.NewReader(data), perm)
	return err
}

// WriteReaderAtomic is WriteFileAtomic for data from r; it returns the
// number of bytes written.
func WriteReaderAtomic(path string, r io.Reader, perm os.FileMode) (int64, error) {
	if confined.on {
		if rel, err := filepath.Rel(confined.dir, path); err == nil && (rel == "." || filepath.IsLocal(rel)) {
			return 0, fmt.Errorf("%s: the TUN service doesn't write to %s", path, confined.dir)
		}
	}
	return writeAtomic(path, r, perm, giveBackTo())
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
