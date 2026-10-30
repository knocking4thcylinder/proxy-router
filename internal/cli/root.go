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

var flagDir, flagUID string

// Execute runs the CLI.
func Execute() error {
	return newRootCmd(os.Args[1:]).Execute()
}

func newRootCmd(args []string) *cobra.Command {
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
in TUN mode); "stop", "restart", "status" and "logs" control it. "run" also starts in the background;
"run --foreground" stays attached to the terminal.`,
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			config.SetTargetUID(flagUID)
			_, err := config.TargetUser()
			return err
		},
	}
	root.PersistentFlags().StringVar(&flagDir, "dir", "", "config directory (default ~/.config/proxy-router, or $PROXY_ROUTER_HOME)")
	// Set when proxy-router runs itself as root, and in the TUN service's
	// unit: whose files and services root works with.
	root.PersistentFlags().StringVar(&flagUID, "uid", "", "as root: the user to work for (default: the one sudo or pkexec reports)")
	_ = root.PersistentFlags().MarkHidden("uid")
	root.AddCommand(
		initCmd(), subCmd(), addCmd(), removeCmd(), listCmd(), useCmd(),
		pingCmd(), runCmd(), geoCmd(), configCmd(),
		startCmd(), stopCmd(), restartCmd(), statusCmd(), logsCmd(), uninstallCmd(),
		trayCmd(),
	)
	_ = root.RegisterFlagCompletionFunc("dir", completeDirectories)
	root.SetArgs(args)
	root.InitDefaultCompletionCmd()
	configureFishCompletion(root)
	configureCompletions(root, args)
	return root
}

// env bundles loaded config and state for commands.
type env struct {
	cfg   *config.Config
	state *config.State
}

// configDir is --dir, or the default config directory. As root it has to
// pass config.CheckDir.
func configDir() (string, error) {
	get := config.Dir
	if flagDir != "" {
		get = func() (string, error) { return filepath.Abs(flagDir) }
	}
	dir, err := get()
	if err != nil {
		return "", err
	}
	return config.CheckDir(dir)
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
// "sudo proxy-router run") in config.Confine's read-only mode. dir belongs
// to the user root works for (config.TargetUser: the service's --uid,
// recorded at install time, or the sudo/pkexec user), otherwise to root.
func confineRoot(dir string) error {
	uid := 0
	u, err := config.TargetUser()
	if err != nil {
		return err
	}
	if u != nil {
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return fmt.Errorf("bad uid %q", u.Uid)
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
		if err != nil {
			return "", ""
		}
		return bypass(d, e.ownTUN())
	default:
		return v, ""
	}
}

// bypass is outboundInterface's "auto" choice for the default route
// detected in d. own is the TUN of a running proxy-router in TUN mode: not
// another VPN, so connections go through it like everything else. Going
// around it would leave the tunnel, and its kill switch rejects that.
func bypass(d netif.Detection, own string) (iface, note string) {
	switch {
	case d.Tunnel == "":
		return "", ""
	case d.Tunnel == own:
		return "", fmt.Sprintf("TUN mode is on (%s); connections go through it, and so through the server it uses", own)
	case d.Physical == "":
		return "", fmt.Sprintf("another VPN (%s) owns the default route and no physical interface was found; connections will go through it", d.Tunnel)
	}
	return d.Physical, fmt.Sprintf("another VPN (%s) owns the default route; bypassing it via %s", d.Tunnel, d.Physical)
}

// ownTUN is the TUN interface of a running proxy-router in TUN mode (the
// service, or "run --tun"), or "".
func (e *env) ownTUN() string {
	if st, ok := readRunStatus(e.cfg.Dir()); ok && st.Mode == "tun" {
		return st.TUN
	}
	return ""
}

// resolveTTL is how long pinned server addresses are trusted.
const resolveTTL = 10 * time.Minute

var processResolvers = map[string]engine.Resolver{}

// resolver returns one caching resolver per process (and interface and
// settings), so reloads reuse it. Server names are looked up with DoH
// outside the tunnel, from iface like the direct outbound, with the TUN
// kill switch's socket mark (0 outside TUN mode); the system resolver, in
// plain DNS, is only a fallback that can be turned off.
func (e *env) resolver(iface string, mark int) engine.Resolver {
	key := fmt.Sprintf("%s/%d/%s/%t", iface, mark, e.cfg.PreferredIP, e.cfg.SystemDNSFallback)
	if r := processResolvers[key]; r != nil {
		return r
	}
	lookup := engine.DoHLookup(config.DirectDoH, iface, mark)
	if e.cfg.SystemDNSFallback {
		lookup = engine.OrElse(lookup, engine.SystemLookup)
	}
	r := engine.CachingResolver(e.cfg.PreferredIP, resolveTTL, lookup)
	processResolvers[key] = r
	return r
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
