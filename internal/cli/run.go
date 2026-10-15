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
	verbose     int
	tun         bool
	noTUN       bool
	force       bool
	// service is set when running as the background service: output goes
	// to the log file, and missing network or another VPN are waited out
	// instead of being errors (both are normal at boot/login).
	service bool
	// tunName is chosen once per run so reloads reuse the same interface.
	tunName string
	// tunListen is the main instance's loopback SOCKS address the TUN front
	// forwards to.
	tunListen string
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
	cmd.Flags().CountVarP(&o.verbose, "verbose", "v", "log every connection and its route; -vv also logs why connections fail")
	cmd.Flags().BoolVar(&o.tun, "tun", false, "capture all system traffic with a TUN interface (needs sudo; same as tun.enabled)")
	cmd.Flags().BoolVar(&o.noTUN, "no-tun", false, "don't use TUN mode even if tun.enabled is set")
	cmd.Flags().BoolVar(&o.force, "force", false, "start TUN mode even though another VPN owns the default route")
	cmd.Flags().BoolVar(&o.service, "service", false, "run as the background service (used by \"proxy-router start\")")
	_ = cmd.Flags().MarkHidden("service")
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
	if o.verbose > 0 {
		e.cfg.AccessLog = true
		if e.cfg.LogLevel == "none" || e.cfg.LogLevel == "error" {
			e.cfg.LogLevel = "warning"
		}
	}
	if o.verbose > 1 && e.cfg.LogLevel != "debug" {
		e.cfg.LogLevel = "info"
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
	plan := engine.Plan{Config: e.cfg, Rules: rules, State: e.state, Interface: iface, TUNListen: o.tunListen}
	if iface != "" || e.cfg.ResolveLocally {
		// Resolve server hostnames here: in TUN mode the system resolver may
		// be routed into the TUN, and with resolve_locally Xray's DNS goes
		// through the proxy, which can't help find the proxy itself.
		plan.Resolve = e.resolver(iface)
	}
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
	dir, err := configDir()
	if err != nil {
		return err
	}
	if o.service {
		config.SetOwnerFromDir(dir)
		if err := redirectOutput(logPath(dir)); err != nil {
			return err
		}
		fmt.Printf("\n=== proxy-router %s service starting, %s ===\n", version(), time.Now().Format(time.RFC3339))
	}
	if st, ok := readRunStatus(dir); ok && st.PID != os.Getpid() {
		if st.Service {
			return errors.New(`the background service is running ("proxy-router stop" stops it; "proxy-router logs -f" shows what it does)`)
		}
		return fmt.Errorf("proxy-router run is already running (pid %d)", st.PID)
	}
	if e, err := load(); err == nil && e.cfg.TUN.Enabled && !o.noTUN {
		o.tun = true
	}
	defer removeRunStatus(dir)

	var tunIPv6 bool
	if o.tun {
		if err := tun.RequireRoot(); err != nil {
			return err
		}
		if stop, err := waitForUplink(ctx, dir, o); err != nil || stop {
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
		if o.tunListen, err = freeLoopback(); err != nil {
			return err
		}
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

	// The main instance restarts on every config change; in TUN mode a
	// separate front instance owns the TUN device and the routes for the
	// whole run (Xray can't hand a TUN device over between instances).
	start := func(xc map[string]any) (*core.Instance, error) {
		return engine.Start(xc)
	}
	stop := func(inst *core.Instance) {
		if inst != nil {
			inst.Close()
		}
	}

	// The front must start before the main instance: Xray keeps the DNS
	// client and outbound manager in process-wide globals, and the instance
	// created last owns them. They have to be the main instance's (its DNS
	// settings, its chain helpers), so it also re-takes them on each reload.
	if o.tunName != "" {
		fc, err := engine.BuildTUNFront(o.tunName, e.cfg.TUN.MTU, o.tunListen)
		if err != nil {
			return err
		}
		front, err := engine.Start(fc)
		if err != nil {
			return fmt.Errorf("TUN: %w", err)
		}
		defer front.Close()
	}

	raw, _ := json.Marshal(xc)
	inst, err := start(xc)
	if err != nil {
		return err
	}
	defer func() { stop(inst) }()

	if o.tunName != "" {
		if err := tun.WaitForInterface(o.tunName, 5*time.Second); err != nil {
			return err
		}
		if err := tun.Up(o.tunName, tunIPv6); err != nil {
			return err
		}
		defer tun.Down(o.tunName, tunIPv6)
	}

	// fatal is set when the proxy couldn't be restored after a reload; run
	// exits instead of staying up with nothing behind it.
	var fatal error
	printStatus(e, o)
	writeRunStatus(dir, describeRun(e, o, "running", ""))

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
		if e.cfg.BindInterface == "auto" || o.tunName != "" {
			d, _ := netif.Detect()
			s += d.Tunnel + "/" + d.Physical
		}
		if o.tunName != "" {
			phys, _ := netif.Physical(o.tunName)
			s += "/" + phys
		}
		return s
	}
	stamps := snapshot()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	// Server IPs are pinned while bypassing system routing; re-resolve them
	// now and then (providers rotate them) and restart only on change.
	reresolve := time.NewTicker(resolveTTL + time.Second)
	defer reresolve.Stop()

	// Refresh stale subscriptions in the background: start right away with
	// the cached servers instead of waiting (with no connectivity in TUN
	// mode) for a slow or blocked subscription server.
	refreshed := make(chan bool, 1)
	if !o.noUpdate {
		go func() { refreshed <- refreshStale(ctx) }()
	}

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
		inst = nil
		newInst, err := start(next)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: new config failed, keeping the old one: %v\n", reason, err)
			var prev map[string]any
			_ = json.Unmarshal(raw, &prev)
			if inst, err = start(prev); err != nil {
				fatal = fmt.Errorf("couldn't restore the proxy after a failed reload: %w", err)
			}
			return
		}
		inst, raw = newInst, nextRaw
		fmt.Printf("%s reloaded (%s)\n", time.Now().Format(time.TimeOnly), reason)
		if ne, err := load(); err == nil {
			printStatus(ne, o)
			writeRunStatus(dir, describeRun(ne, o, "running", ""))
		}
	}

	for fatal == nil {
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
				if o.tunName != "" {
					if err := tun.Sync(o.tunName, tunIPv6); err != nil {
						fmt.Fprintln(os.Stderr, "TUN:", err)
					}
				}
				reload("files or network changed")
			}
		case changed := <-refreshed:
			if changed {
				stamps = snapshot()
				reload("subscriptions updated")
			}
		case <-reresolve.C:
			reload("server addresses changed")
		case <-updates:
			if refreshStale(ctx) {
				stamps = snapshot()
				reload("subscriptions updated")
			}
		}
	}
	return fatal
}

// checkPorts fails early, naming the culprit, if a listen address is taken
// (Happ, v2rayN and friends default to the same 10808/10809).
// freeLoopback returns an unused 127.0.0.1 TCP address.
func freeLoopback() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

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
	st := describeRun(e, o, "", "")
	fmt.Printf("server: %s\n", st.Server)
	if st.TUN != "" {
		fmt.Printf("tun:    %s (all traffic; proxy-router's own connections leave via %s)\n", st.TUN, st.Via)
	} else if st.Note != "" {
		fmt.Printf("note:   %s\n", st.Note)
	} else if st.Via != "" {
		fmt.Printf("via:    %s\n", st.Via)
	}
	fmt.Printf("rules:  %s\n", e.rulesPath(o))
	if st.Socks != "" {
		fmt.Printf("socks5: %s\n", st.Socks)
	}
	if st.HTTP != "" {
		fmt.Printf("http:   %s\n", st.HTTP)
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
				o.tunListen = "127.0.0.1:10807" // placeholder; run picks a free port
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
