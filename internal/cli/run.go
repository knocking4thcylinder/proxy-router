package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/netif"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
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
	// forwards to, and tunLogin the per-run login it uses there.
	tunListen string
	tunLogin  engine.Account
	// pick is where auto-switching moved when it couldn't save that to
	// state.json.
	pick *autoPick
}

func runCmd() *cobra.Command {
	return newRunCmd(run, startService)
}

func newRunCmd(runForeground func(context.Context, runOptions) error, startBackground func(startOptions, bool) error) *cobra.Command {
	var o runOptions
	var foreground bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the local proxy with the selected server and routing rules",
		Long: `Start the local SOCKS5/HTTP proxy in the background and return to the shell.
Like "start", this enables the service at login (at boot in TUN mode).
Use --foreground to keep it attached to this terminal until Ctrl-C.
Use "proxy-router stop" to stop the background proxy and "proxy-router logs -f"
to follow its output.

While running, proxy-router reloads automatically when the rules file,
config.yaml or the selected server ("proxy-router use") changes, and on
SIGHUP. Subscriptions are refreshed every update_interval.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if foreground || o.service {
				return runForeground(cmd.Context(), o)
			}
			return startBackground(startOptions{
				tun: o.tun, noTUN: o.noTUN, force: o.force, verbose: o.verbose,
				rules: o.rules, server: o.server, systemProxy: o.systemProxy, noUpdate: o.noUpdate,
			}, false)
		},
	}
	cmd.Flags().BoolVar(&foreground, "foreground", false, "stay attached to the terminal until Ctrl-C")
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
	cmd.MarkFlagsMutuallyExclusive("tun", "no-tun")
	_ = cmd.MarkFlagFilename("rules")
	_ = cmd.RegisterFlagCompletionFunc("rules", completeFiles)
	_ = cmd.RegisterFlagCompletionFunc("server", completeServers)
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
	own, err := e.ownOptions(o)
	if err != nil {
		return nil, nil, nil, err
	}
	plan := engine.Plan{Config: e.cfg, Rules: rules, State: e.state, Interface: own.Interface,
		Resolve: own.Resolve, TUNListen: o.tunListen, TUNAccount: o.tunLogin}
	if plan.Server, err = o.serverOverride(e); err != nil {
		return nil, nil, nil, err
	}
	if err := e.ensureGeo(rules, plan.Server, own); err != nil {
		return nil, nil, nil, err
	}
	xc, notes, err := engine.Build(plan)
	if err != nil {
		return nil, nil, nil, err
	}
	if o.tunName != "" {
		// The kill switch recognizes proxy-router's own connections by it.
		engine.MarkSockets(xc, own.Mark)
	}
	return e, xc, notes, nil
}

// ownOptions sets up proxy-router's own connections to servers like the
// running proxy's: the interface and, in TUN mode, the socket mark they
// leave with, and how server names are looked up.
func (e *env) ownOptions(o runOptions) (engine.PingOptions, error) {
	var iface string
	var mark int
	if o.tunName != "" {
		// Our own traffic must leave through the real uplink, or it would
		// loop back into the TUN.
		var err error
		if iface, err = netif.Physical(o.tunName); err != nil {
			return engine.PingOptions{}, err
		}
		mark = tun.SocketMark()
	} else {
		iface, _ = e.outboundInterface()
	}
	own := engine.PingOptions{Interface: iface, Config: e.cfg, Mark: mark}
	if iface != "" || e.cfg.ResolveLocally {
		// Resolve server hostnames here: in TUN mode the system resolver may
		// be routed into the TUN, and with resolve_locally Xray's DNS goes
		// through the proxy, which can't help find the proxy itself.
		own.Resolve = e.resolver(iface, mark)
	}
	return own, nil
}

// serverOverride is the server this run uses instead of the selected one:
// --server, or where auto-switching moved (nil: the selected one).
func (o runOptions) serverOverride(e *env) (*config.Entry, error) {
	if o.server != "" {
		entry, err := e.state.Find(o.server)
		if err != nil {
			return nil, err
		}
		return &entry, nil
	}
	if entry, ok := o.pick.entry(e.state); ok {
		return &entry, nil
	}
	return nil, nil
}

func (e *env) rulesPath(o runOptions) string {
	if o.rules != "" {
		return o.rules
	}
	return e.cfg.RulesPath()
}

// ensureGeo downloads geo files the rules need but are missing, through
// server (nil: the selected one) set up as o says.
func (e *env) ensureGeo(rules *config.Rules, server *config.Entry, o engine.PingOptions) error {
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
		n, err := e.downloadGeo(context.Background(), server, o, f.url, f.name)
		if err != nil {
			return fmt.Errorf("download %s: %w (change the geo URLs in config.yaml, or put the file in %s)", f.name, err, e.cfg.AssetDir())
		}
		fmt.Fprintf(os.Stderr, "downloaded %s (%s)\n", f.name, humanBytes(n))
	}
	return nil
}

// geoTries caps how many members of a pool downloadGeo tries.
const geoTries = 3

// downloadGeo fetches a geo file through server (nil: the selected one),
// trying a pool's members in turn. GitHub, where the files come from, is
// often blocked where a proxy is needed, and TUN mode fetches its own
// copies before the TUN is up. Only without any server does it go direct.
func (e *env) downloadGeo(ctx context.Context, server *config.Entry, o engine.PingOptions, url, name string) (int64, error) {
	if server == nil {
		if cur, ok := e.state.Current(); ok {
			server = &cur
		}
	}
	if server == nil {
		return engine.DownloadAsset(ctx, nil, url, e.cfg.AssetDir(), name)
	}
	via := server.Server.Members()
	if via == nil {
		via = []*share.Server{server.Server}
	}
	var errs []error
	for _, s := range via[:min(len(via), geoTries)] {
		client, stop, err := engine.ProxyClient(s, o, url)
		if err == nil {
			var n int64
			n, err = engine.DownloadAsset(ctx, client, url, e.cfg.AssetDir(), name)
			stop()
			if err == nil {
				return n, nil
			}
		}
		errs = append(errs, fmt.Errorf("through %s: %w", clean(s.Name), err))
	}
	return 0, errors.Join(errs...)
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
	fmt.Fprintf(os.Stderr, "proxy is running; refreshing %d subscription(s) in the background...\n", len(stale))
	failed := e.updateAll(ctx, stale)
	if config.Confined() {
		keepRefreshed(e.state, stale)
	} else if err := e.state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "save state: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "subscription refresh finished: %d updated, %d failed\n", len(stale)-failed, failed)
	return true
}

// serviceSubs holds the subscriptions the TUN service refreshed. It
// can't save them to the user's state.json, so it keeps them in memory
// (as JSON, so later loads get their own copies) and load() lays them
// over what it reads. Once the user's own commands save a newer refresh,
// that wins; after a restart the service refreshes again.
var serviceSubs struct {
	sync.Mutex
	subs map[string][]byte
	hwid string
}

func keepRefreshed(s *config.State, subs []*config.Subscription) {
	serviceSubs.Lock()
	defer serviceSubs.Unlock()
	if serviceSubs.subs == nil {
		serviceSubs.subs = map[string][]byte{}
	}
	for _, sub := range subs {
		if data, err := json.Marshal(sub); err == nil {
			serviceSubs.subs[sub.Name] = data
		}
	}
	// The HWID made up for the requests has to stay the same.
	serviceSubs.hwid = s.HWID
}

// applyRefreshed replaces the servers of subscriptions in s with ones
// keepRefreshed has from a later refresh of the same URL.
func applyRefreshed(s *config.State) {
	serviceSubs.Lock()
	defer serviceSubs.Unlock()
	for i, sub := range s.Subscriptions {
		data, ok := serviceSubs.subs[sub.Name]
		if !ok {
			continue
		}
		var r config.Subscription
		if json.Unmarshal(data, &r) != nil || r.URL != sub.URL || !r.UpdatedAt.After(sub.UpdatedAt) {
			continue
		}
		c := *sub
		c.Servers, c.Info, c.UpdatedAt, c.LastError = r.Servers, r.Info, r.UpdatedAt, r.LastError
		s.Subscriptions[i] = &c
	}
	if s.HWID == "" {
		s.HWID = serviceSubs.hwid
	}
}

func run(ctx context.Context, o runOptions) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		// The unit records whose files the service reads (--uid).
		if o.service && flagUID == "" {
			return errors.New(`the TUN service was installed by an older proxy-router; reinstall it with "proxy-router restart"`)
		}
		if err := confineRoot(dir); err != nil {
			return err
		}
	}
	if o.service {
		if err := serviceOutput(dir); err != nil {
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

	// tunOpts is what tun.Up last applied.
	var tunOpts tun.Options
	release := func() {}
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
		if o.tunName = e.cfg.TUN.Name; o.tunName == "" {
			if o.tunName, err = tun.FreeName(); err != nil {
				return err
			}
		}
		// Hold the port until the main instance takes it, so no other
		// program can grab it meanwhile and receive the TUN's traffic.
		reserved, err := freeLoopback()
		if err != nil {
			return err
		}
		defer reserved.Close()
		o.tunListen, o.tunLogin = reserved.Addr().String(), engine.NewAccount()
		release = func() { reserved.Close() }
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
		fc, err := engine.BuildTUNFront(o.tunName, e.cfg.TUN.MTU, o.tunListen, o.tunLogin)
		if err != nil {
			return err
		}
		front, err := engine.Start(fc)
		if err != nil {
			return fmt.Errorf("TUN: %w", err)
		}
		defer front.Close()
	}

	// Auto-switching watches the connections the main instance opens for
	// the server; the watch goes in before any are.
	watch := engine.WatchOutbound("proxy")
	defer watch.Stop()

	raw, _ := json.Marshal(xc)
	release()
	inst, err := start(xc)
	if err != nil {
		return err
	}
	defer func() { stop(inst) }()

	if o.tunName != "" {
		if err := tun.WaitForInterface(o.tunName, 5*time.Second); err != nil {
			return err
		}
		tunOpts = tunOptions(e, o.tunName)
		// The service keeps the kill switch when it exits: it's restarted
		// (by systemd/launchd, or "proxy-router restart"), and when it's
		// stopped, "proxy-router stop" removes it. In the foreground, the
		// user is right there.
		defer func() {
			tun.Down(tunOpts, o.service)
			if o.service && tunOpts.KillSwitch {
				fmt.Println(`TUN: the kill switch stays on until the service is back; "sudo proxy-router stop" removes it`)
			}
		}()
		if err := tun.Up(tunOpts); err != nil {
			return fmt.Errorf("TUN: %w", err)
		}
		if closer, err := serveOutside(o.tunName); err != nil {
			fmt.Fprintln(os.Stderr, "TUN: ping can't go around the TUN:", err)
		} else {
			defer closer.Close()
		}
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
	refreshCtx, cancelRefresh := context.WithCancel(ctx)
	defer cancelRefresh()
	refreshing := false
	refresh := func() {
		if refreshing {
			return
		}
		refreshing = true
		go func() { refreshed <- refreshStale(refreshCtx) }()
	}
	if !o.noUpdate {
		refresh()
	}

	// Network settings drift without the files changing (DHCP rewriting
	// DNS, systemd-resolved restarting); Sync puts them back.
	var tunSync <-chan time.Time
	if o.tunName != "" {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		tunSync = t.C
	}
	// syncTUN follows network and config changes: tun.ipv6, kill_switch
	// and system_route apply without a restart.
	syncTUN := func() {
		if ne, err := load(); err == nil {
			if next := tunOptions(ne, o.tunName); !next.Equal(tunOpts) {
				if err := tun.Up(next); err != nil {
					fmt.Fprintln(os.Stderr, "TUN:", err)
				} else {
					tunOpts = next
					fmt.Printf("%s TUN settings applied\n", time.Now().Format(time.TimeOnly))
				}
			}
		}
		if err := tun.Sync(tunOpts); err != nil {
			fmt.Fprintln(os.Stderr, "TUN:", err)
		}
	}

	var updates <-chan time.Time
	if iv := e.cfg.UpdateInterval.D(); iv > 0 && !o.noUpdate {
		t := time.NewTicker(min(iv, time.Hour))
		defer t.Stop()
		updates = t.C
	}

	// gen counts main instances, so a health check that went through one
	// that has since been replaced is ignored.
	gen := 0
	sw := newSwitcher(watch)
	sw.follow(o, gen)

	// reload rebuilds the config and restarts the main instance if it
	// changed, or always with force.
	reload := func(reason string, force bool) {
		// Whether or not the instance restarts, the selection may have
		// changed.
		defer func() { sw.follow(o, gen) }()
		_, next, err := buildCurrent(o)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: not reloading: %v\n", reason, err)
			if !force {
				return
			}
			_ = json.Unmarshal(raw, &next)
		}
		nextRaw, _ := json.Marshal(next)
		if bytes.Equal(raw, nextRaw) && !force {
			return
		}
		// Ports must be free before the new instance can bind them.
		stop(inst)
		inst = nil
		gen++
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
				reload("SIGHUP", false)
				continue
			}
			fmt.Println("\nstopping")
			return nil
		case <-poll.C:
			if now := snapshot(); now != stamps {
				stamps = now
				if o.tunName != "" {
					syncTUN()
				}
				reload("files or network changed", false)
			}
		case changed := <-refreshed:
			refreshing = false
			if changed {
				stamps = snapshot()
				reload("subscriptions updated", false)
			}
		case <-tunSync:
			if err := tun.Sync(tunOpts); err != nil {
				fmt.Fprintln(os.Stderr, "TUN:", err)
			}
		case <-reresolve.C:
			reload("server addresses changed", false)
		case <-updates:
			refresh()
		case t := <-watch.Trouble():
			sw.trouble(ctx, o, inst, gen, t)
		case <-sw.retry:
			sw.again(ctx, o, inst, gen)
		case r := <-sw.checked:
			sw.check(ctx, o, r, gen)
		case r := <-sw.scanned:
			o.pick = sw.apply(r, o.pick)
			// Always restart: the scan's test instances took over Xray's
			// process-wide state from the running one.
			reload("auto-switch", true)
			stamps = snapshot()
		}
	}
	return fatal
}

// serveOutside lets the user (or root) open sockets that leave through
// the physical interface around the TUN named tunName, for ping.
func serveOutside(tunName string) (io.Closer, error) {
	if !systemRunDirOK() {
		return nil, fmt.Errorf("%s is not a root-owned directory", systemRunDir())
	}
	uid := 0
	if u, err := config.TargetUser(); err != nil {
		return nil, err
	} else if u != nil {
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return nil, err
		}
	}
	// Ping asks for a socket per connection; don't run "ip route" for each.
	var mu sync.Mutex
	var phys string
	var looked time.Time
	physical := func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if phys == "" || time.Since(looked) > 2*time.Second {
			p, err := netif.Physical(tunName)
			if err != nil {
				return "", err
			}
			phys, looked = p, time.Now()
		}
		return phys, nil
	}
	return tun.ServeOutside(outsidePath(), uid, physical)
}

// freeLoopback reserves an unused 127.0.0.1 TCP port; close the listener
// right before binding the port for real. Something could still take it in
// between (or while a reload restarts the main instance), but then the
// main instance fails to start and run exits, which stops the TUN.
func freeLoopback() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
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
	st := describeRun(e, o, "", "")
	fmt.Printf("server: %s\n", st.Server)
	if st.Auto {
		fmt.Println("auto:   checked when its connections show trouble; replaced by the fastest working server when it fails")
	}
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
	if !o.service {
		fmt.Println("Proxy is running in the foreground. Press Ctrl-C to stop.")
		cmd := "proxy-router start"
		if st.TUN != "" {
			cmd += " --tun"
		}
		fmt.Printf("To free this terminal, stop this run, then use: %s\n", cmd)
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
			if os.Geteuid() == 0 {
				// Root updates the TUN service's own copies.
				dir, err := configDir()
				if err != nil {
					return err
				}
				if err := confineRoot(dir); err != nil {
					return err
				}
			}
			e, err := load()
			if err != nil {
				return err
			}
			iface, _ := e.outboundInterface()
			o := engine.PingOptions{Interface: iface, Config: e.cfg, Resolve: e.resolverIf(iface)}
			var errs []error
			for name, url := range map[string]string{"geoip.dat": e.cfg.Geo.GeoIP, "geosite.dat": e.cfg.Geo.GeoSite} {
				n, err := e.downloadGeo(cmd.Context(), nil, o, url, name)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
					continue
				}
				fmt.Printf("%s: %s\n", name, humanBytes(n))
			}
			if st, _ := service.Query(service.Target{Scope: service.System}); st.Installed && os.Geteuid() != 0 {
				fmt.Println(`note: the TUN service keeps its own copies; "sudo proxy-router geo update" updates them`)
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
				o.tunLogin = engine.NewAccount()
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
	_ = cmd.MarkFlagFilename("rules")
	_ = cmd.RegisterFlagCompletionFunc("rules", completeFiles)
	_ = cmd.RegisterFlagCompletionFunc("server", completeServers)
	return cmd
}
