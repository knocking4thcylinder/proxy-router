package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/netif"
	"github.com/knocking4thcylinder/proxy-router/internal/sysproxy"
	"github.com/knocking4thcylinder/proxy-router/internal/tun"
)

type runOptions struct {
	rules       string
	server      string
	systemProxy bool
	noUpdate    bool
	verbose     bool
	tun         bool
	// tunName is chosen once per run so reloads reuse the same interface.
	tunName string
}

func runCmd() *cobra.Command {
	var o runOptions
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the local proxy with the selected server and routing rules",
		Long: `Start the local SOCKS5/HTTP proxy.

While running, proxy-router reloads automatically when the rules file,
config.yaml or the selected server ("proxy-router use") changes, and on
SIGHUP. Subscriptions are refreshed every update_interval.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), o)
		},
	}
	cmd.Flags().StringVarP(&o.rules, "rules", "r", "", "routing rules file (default from config.yaml)")
	cmd.Flags().StringVarP(&o.server, "server", "s", "", "server to use for this run instead of the selected one")
	cmd.Flags().BoolVar(&o.systemProxy, "system-proxy", false, "point the system proxy settings at proxy-router while running (macOS)")
	cmd.Flags().BoolVar(&o.noUpdate, "no-update", false, "don't refresh subscriptions")
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "log every connection and its route")
	cmd.Flags().BoolVar(&o.tun, "tun", false, "capture all system traffic with a TUN interface (needs sudo; same as tun.enabled)")
	return cmd
}

// buildCurrent loads everything from disk and builds the Xray config.
func buildCurrent(o runOptions) (*env, map[string]any, error) {
	e, xc, _, err := buildCurrentNotes(o)
	return e, xc, err
}

func buildCurrentNotes(o runOptions) (*env, map[string]any, []string, error) {
	e, err := load()
	if err != nil {
		return nil, nil, nil, err
	}
	if o.verbose {
		e.cfg.AccessLog = true
		if e.cfg.LogLevel == "none" || e.cfg.LogLevel == "error" {
			e.cfg.LogLevel = "warning"
		}
	}
	rules, err := config.LoadRules(e.rulesPath(o))
	if err != nil {
		return nil, nil, nil, err
	}
	var iface string
	if o.tunName != "" {
		// Our own traffic must leave through the real uplink, or it would
		// loop back into the TUN.
		if iface, err = netif.Physical(o.tunName); err != nil {
			return nil, nil, nil, err
		}
	} else {
		iface, _ = e.outboundInterface()
	}
	plan := engine.Plan{Config: e.cfg, Rules: rules, State: e.state, Interface: iface, TUNName: o.tunName}
	if o.server != "" {
		entry, err := e.state.Find(o.server)
		if err != nil {
			return nil, nil, nil, err
		}
		plan.Server = &entry
	}
	if err := e.ensureGeo(rules); err != nil {
		return nil, nil, nil, err
	}
	xc, notes, err := engine.Build(plan)
	if err != nil {
		return nil, nil, nil, err
	}
	return e, xc, notes, nil
}

func (e *env) rulesPath(o runOptions) string {
	if o.rules != "" {
		return o.rules
	}
	return e.cfg.RulesPath()
}

// ensureGeo downloads geo files the rules need but are missing.
func (e *env) ensureGeo(rules *config.Rules) error {
	needIP, needSite := rules.NeedsGeo()
	for _, f := range []struct {
		need      bool
		name, url string
	}{
		{needIP, "geoip.dat", e.cfg.Geo.GeoIP},
		{needSite, "geosite.dat", e.cfg.Geo.GeoSite},
	} {
		if !f.need {
			continue
		}
		if _, err := os.Stat(filepath.Join(e.cfg.AssetDir(), f.name)); err == nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "rules use %s which is missing; downloading...\n", f.name)
		n, err := engine.DownloadAsset(context.Background(), f.url, e.cfg.AssetDir(), f.name)
		if err != nil {
			return fmt.Errorf("download %s: %w (set HTTPS_PROXY or change geo URLs in config.yaml)", f.name, err)
		}
		fmt.Fprintf(os.Stderr, "downloaded %s (%s)\n", f.name, humanBytes(n))
	}
	return nil
}

// refreshStale updates subscriptions older than the update interval.
// Returns true if anything was fetched.
func refreshStale(ctx context.Context) bool {
	e, err := load()
	if err != nil {
		return false
	}
	interval := e.cfg.UpdateInterval.D()
	if interval <= 0 {
		return false
	}
	var stale []*config.Subscription
	for _, s := range e.state.Subscriptions {
		every := interval
		if h := s.Info.UpdateInterval; h > 0 && time.Duration(h)*time.Hour < every {
			every = time.Duration(h) * time.Hour
		}
		if time.Since(s.UpdatedAt) >= every {
			stale = append(stale, s)
		}
	}
	if len(stale) == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "updating %d subscription(s)...\n", len(stale))
	e.updateAll(ctx, stale)
	if err := e.state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
	}
	return true
}

func run(ctx context.Context, o runOptions) error {
	if e, err := load(); err == nil && e.cfg.TUN.Enabled {
		o.tun = true
	}
	var tunIPv6 bool
	if o.tun {
		if err := tun.RequireRoot(); err != nil {
			return err
		}
		e, err := load()
		if err != nil {
			return err
		}
		tunIPv6 = e.cfg.TUN.IPv6
		if o.tunName = e.cfg.TUN.Name; o.tunName == "" {
			if o.tunName, err = tun.FreeName(); err != nil {
				return err
			}
		}
	}
	if !o.noUpdate {
		refreshStale(ctx)
	}
	e, xc, notes, err := buildCurrentNotes(o)
	if err != nil {
		return err
	}
	if err := checkPorts(e.cfg); err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}

	// start/stop wrap Xray with the TUN routes, which disappear with the
	// interface on every restart.
	start := func(xc map[string]any) (*core.Instance, error) {
		inst, err := engine.Start(xc)
		if err != nil || o.tunName == "" {
			return inst, err
		}
		if err := tun.WaitForInterface(o.tunName, 5*time.Second); err != nil {
			inst.Close()
			return nil, err
		}
		if err := tun.Up(o.tunName, tunIPv6); err != nil {
			inst.Close()
			return nil, err
		}
		return inst, nil
	}
	stop := func(inst *core.Instance) {
		if inst == nil {
			return
		}
		if o.tunName != "" {
			tun.Down(o.tunName, tunIPv6)
		}
		inst.Close()
	}

	raw, _ := json.Marshal(xc)
	inst, err := start(xc)
	if err != nil {
		return err
	}
	defer func() { stop(inst) }()
	printStatus(e, o)

	if o.systemProxy {
		restore, err := setSystemProxy(e.cfg)
		if err != nil {
			return err
		}
		fmt.Println("system proxy enabled")
		defer func() {
			if err := restore(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Println("system proxy restored")
			}
		}()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	watched := []string{
		filepath.Join(e.cfg.Dir(), "config.yaml"),
		filepath.Join(e.cfg.Dir(), "state.json"),
		e.rulesPath(o),
	}
	// Re-check files and, with bind_interface: auto, which interface to use
	// (another VPN starting/stopping, Wi-Fi <-> Ethernet).
	snapshot := func() string {
		s := modTimes(watched)
		if e.cfg.BindInterface == "auto" {
			d, _ := netif.Detect()
			s += d.Tunnel + "/" + d.Physical
		}
		return s
	}
	stamps := snapshot()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	var updates <-chan time.Time
	if iv := e.cfg.UpdateInterval.D(); iv > 0 && !o.noUpdate {
		t := time.NewTicker(min(iv, time.Hour))
		defer t.Stop()
		updates = t.C
	}

	reload := func(reason string) {
		_, next, err := buildCurrent(o)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: not reloading: %v\n", reason, err)
			return
		}
		nextRaw, _ := json.Marshal(next)
		if bytes.Equal(raw, nextRaw) {
			return
		}
		// Ports must be free before the new instance can bind them.
		stop(inst)
		newInst, err := start(next)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: new config failed, keeping the old one: %v\n", reason, err)
			var prev map[string]any
			_ = json.Unmarshal(raw, &prev)
			if inst, err = start(prev); err != nil {
				fmt.Fprintf(os.Stderr, "restart failed: %v\n", err)
			}
			return
		}
		inst, raw = newInst, nextRaw
		fmt.Printf("reloaded (%s)\n", reason)
		if ne, err := load(); err == nil {
			printStatus(ne, o)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				reload("SIGHUP")
				continue
			}
			fmt.Println("\nstopping")
			return nil
		case <-poll.C:
			if now := snapshot(); now != stamps {
				stamps = now
				reload("files or network changed")
			}
		case <-updates:
			if refreshStale(ctx) {
				stamps = snapshot()
				reload("subscriptions updated")
			}
		}
	}
}

// checkPorts fails early, naming the culprit, if a listen address is taken
// (Happ, v2rayN and friends default to the same 10808/10809).
func checkPorts(cfg *config.Config) error {
	for key, addr := range map[string]string{"socks": cfg.Listen.Socks, "http": cfg.Listen.HTTP} {
		if addr == "" {
			continue
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			who := ""
			if _, port, perr := net.SplitHostPort(addr); perr == nil {
				if out, lerr := exec.Command("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN", "-Fc").Output(); lerr == nil {
					for _, line := range strings.Split(string(out), "\n") {
						if name, ok := strings.CutPrefix(line, "c"); ok {
							who = fmt.Sprintf(" (in use by %s)", name)
							break
						}
					}
				}
			}
			return fmt.Errorf("can't listen on %s%s; change listen.%s in %s",
				addr, who, key, filepath.Join(cfg.Dir(), "config.yaml"))
		}
		l.Close()
	}
	return nil
}

func modTimes(paths []string) string {
	var b bytes.Buffer
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%d;", st.ModTime().UnixNano())
		} else {
			b.WriteString("-;")
		}
	}
	return b.String()
}

func printStatus(e *env, o runOptions) {
	server := "(none)"
	if o.server != "" {
		if en, err := e.state.Find(o.server); err == nil {
			server = en.String()
		}
	} else if cur, ok := e.state.Current(); ok {
		server = cur.String()
	}
	fmt.Printf("server: %s\n", server)
	if o.tunName != "" {
		phys, _ := netif.Physical(o.tunName)
		fmt.Printf("tun:    %s (all traffic; proxy-router's own connections leave via %s)\n", o.tunName, phys)
	} else if iface, note := e.outboundInterface(); note != "" {
		fmt.Printf("note:   %s\n", note)
	} else if iface != "" {
		fmt.Printf("via:    %s\n", iface)
	}
	fmt.Printf("rules:  %s\n", e.rulesPath(o))
	if e.cfg.Listen.Socks != "" {
		fmt.Printf("socks5: %s\n", e.cfg.Listen.Socks)
	}
	if e.cfg.Listen.HTTP != "" {
		fmt.Printf("http:   %s\n", e.cfg.Listen.HTTP)
	}
}

func setSystemProxy(cfg *config.Config) (sysproxy.Restore, error) {
	split := func(addr string) (string, int, error) {
		if addr == "" {
			return "", 0, nil
		}
		host, p, err := net.SplitHostPort(addr)
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, err
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		return host, port, nil
	}
	hh, hp, err := split(cfg.Listen.HTTP)
	if err != nil {
		return nil, err
	}
	sh, sp, err := split(cfg.Listen.Socks)
	if err != nil {
		return nil, err
	}
	return sysproxy.Set(hh, hp, sh, sp)
}

func geoCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "geo", Short: "Manage geoip.dat / geosite.dat"}
	cmd.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Download the latest geoip.dat and geosite.dat",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			var errs []error
			for name, url := range map[string]string{"geoip.dat": e.cfg.Geo.GeoIP, "geosite.dat": e.cfg.Geo.GeoSite} {
				n, err := engine.DownloadAsset(cmd.Context(), url, e.cfg.AssetDir(), name)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
					continue
				}
				fmt.Printf("%s: %s\n", name, humanBytes(n))
			}
			return errors.Join(errs...)
		},
	})
	return cmd
}

func configCmd() *cobra.Command {
	var o runOptions
	var quiet bool
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate the rules and print the generated Xray config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.tun {
				o.tunName = "utun99"
				if runtime.GOOS != "darwin" {
					o.tunName = "prtun0"
				}
			}
			_, xc, notes, err := buildCurrentNotes(o)
			if err != nil {
				return err
			}
			for _, n := range notes {
				fmt.Fprintln(os.Stderr, "note:", n)
			}
			if err := engine.Validate(xc); err != nil {
				return err
			}
			if quiet {
				fmt.Fprintln(os.Stderr, "config OK")
				return nil
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(xc)
		},
	}
	cmd.Flags().StringVarP(&o.rules, "rules", "r", "", "routing rules file (default from config.yaml)")
	cmd.Flags().StringVarP(&o.server, "server", "s", "", "server to use instead of the selected one")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only validate, don't print the config")
	cmd.Flags().BoolVar(&o.tun, "tun", false, "show the config TUN mode would use")
	return cmd
}
