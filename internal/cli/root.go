// Package cli implements the proxy-router command line.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/netif"
)

var Version = "dev"

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

Traffic is routed with rules from a YAML file (routing.yaml by default).`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagDir, "dir", "", "config directory (default ~/.config/proxy-router, or $PROXY_ROUTER_HOME)")
	root.AddCommand(
		initCmd(), subCmd(), addCmd(), removeCmd(), listCmd(), useCmd(),
		pingCmd(), runCmd(), geoCmd(), configCmd(),
	)
	return root.Execute()
}

// env bundles loaded config and state for commands.
type env struct {
	cfg   *config.Config
	state *config.State
}

func load() (*env, error) {
	dir := flagDir
	if dir == "" {
		var err error
		if dir, err = config.Dir(); err != nil {
			return nil, err
		}
	}
	if err := ensureFiles(dir, false); err != nil {
		return nil, err
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	state, err := config.LoadState(dir)
	if err != nil {
		return nil, err
	}
	engine.SetAssetDir(cfg.AssetDir())
	return &env{cfg: cfg, state: state}, nil
}

// ensureFiles writes default config.yaml / routing.yaml if missing.
func ensureFiles(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
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
		if err := config.WriteFileAtomic(path, []byte(content), 0o644); err != nil {
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
			dir := flagDir
			if dir == "" {
				var err error
				if dir, err = config.Dir(); err != nil {
					return err
				}
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
