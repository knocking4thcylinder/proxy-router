// Package cli implements the proxy-router command line.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/netif"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// Version can be set with -ldflags "-X .../internal/cli.Version=v1.2.3";
// otherwise it comes from the build info.
var Version = ""

// version is Version, the module version "go install ...@version" built,
// or the git commit of a local build.
func version() string {
	if Version != "" {
		return Version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return "dev"
	}
	return "dev-" + rev + dirty
}

var flagDir string

// Execute runs the CLI.
func Execute() error {
	root := &cobra.Command{
		Use:   "proxy-router",
		Short: "A command line proxy client with subscriptions and file-based routing (Xray-core)",
		Long: `proxy-router runs a local SOCKS5/HTTP proxy backed by Xray-core.

Servers come from subscriptions (sub add <url>) or share links (add <link>).
Supported: VLESS (Reality, XTLS Vision, XHTTP, ...), VMess, Trojan,
Shadowsocks (incl. 2022), SOCKS, HTTP(S), Hysteria2 and WireGuard, plus any
Xray outbound delivered through a JSON subscription.

Traffic is routed with rules from a YAML file (routing.yaml by default).

"proxy-router start" runs it in the background and at every login (boot,
in TUN mode); "stop", "restart", "status" and "logs" control it. "run"
runs it in the foreground instead.`,
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagDir, "dir", "", "config directory (default ~/.config/proxy-router, or $PROXY_ROUTER_HOME)")
	root.AddCommand(
		initCmd(), subCmd(), addCmd(), removeCmd(), listCmd(), useCmd(),
		pingCmd(), runCmd(), geoCmd(), configCmd(),
		startCmd(), stopCmd(), restartCmd(), statusCmd(), logsCmd(), uninstallCmd(),
		trayCmd(),
	)
	return root.Execute()
}

// env bundles loaded config and state for commands.
type env struct {
	cfg   *config.Config
	state *config.State
}

// configDir is --dir, or the default config directory.
func configDir() (string, error) {
	if flagDir != "" {
		return filepath.Abs(flagDir)
	}
	return config.Dir()
}

func load() (*env, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	// The TUN service runs on the user's files but never writes to them.
	if !config.Confined() {
		if err := ensureFiles(dir, false); err != nil {
			return nil, err
		}
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	state, err := config.LoadState(dir)
	if err != nil {
		return nil, err
	}
	if config.Confined() {
		applyRefreshed(state)
	}
	engine.SetAssetDir(cfg.AssetDir())
	return &env{cfg: cfg, state: state}, nil
}

// ensureFiles writes default config.yaml / routing.yaml if missing.
func ensureFiles(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	config.GiveBack(dir)
	for name, content := range map[string]string{
		"config.yaml":  defaultConfigYAML,
		"routing.yaml": defaultRoutingYAML,
	} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil && !force {
			continue
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := config.WriteFileAtomic(path, []byte(content), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created %s\n", path)
	}
	return nil
}

func initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create config.yaml and routing.yaml with commented defaults",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := configDir()
			if err != nil {
				return err
			}
			if err := ensureFiles(dir, force); err != nil {
				return err
			}
			fmt.Printf("config directory: %s\n", dir)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files with the defaults")
	return cmd
}

// confineRoot puts a proxy-router running as root (the TUN service, or
// "sudo proxy-router run") in config.Confine's read-only mode. uid owns
// dir: the service gets it from --uid, recorded at install time; under
// sudo it's the sudo user, otherwise root's own.
func confineRoot(dir string, uid int) error {
	if uid < 0 {
		uid = 0
		if id := os.Getenv("SUDO_UID"); id != "" {
			n, err := strconv.Atoi(id)
			if err != nil {
				return fmt.Errorf("bad SUDO_UID %q", id)
			}
			uid = n
		}
	}
	config.Confine(dir, uid, filepath.Join(systemStateDir(), "assets"))
	return nil
}

// systemStateDir is the root-owned directory holding the TUN service's
// binary and geo files (the unit's StateDirectory on Linux).
func systemStateDir() string {
	return filepath.Dir(service.BinaryPath(service.Target{Scope: service.System}))
}

// outboundInterface resolves bind_interface. With "auto" it returns the
// physical interface when another VPN's tunnel owns the default route, and
// a human readable note explaining the choice.
func (e *env) outboundInterface() (iface, note string) {
	switch v := strings.TrimSpace(e.cfg.BindInterface); v {
	case "", "none", "off":
		return "", ""
	case "auto":
		d, err := netif.Detect()
		if err != nil || d.Tunnel == "" {
			return "", ""
		}
		if d.Physical == "" {
			return "", fmt.Sprintf("another VPN (%s) owns the default route and no physical interface was found; connections will go through it", d.Tunnel)
		}
		return d.Physical, fmt.Sprintf("another VPN (%s) owns the default route; bypassing it via %s", d.Tunnel, d.Physical)
	default:
		return v, ""
	}
}

// resolveTTL is how long pinned server addresses are trusted.
const resolveTTL = 10 * time.Minute

var processResolver engine.Resolver

// resolver returns one caching resolver per process, so reloads reuse it.
func (e *env) resolver() engine.Resolver {
	if processResolver == nil {
		processResolver = engine.CachingResolver(e.cfg.PreferredIP, resolveTTL)
	}
	return processResolver
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
