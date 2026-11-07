//go:build linux || (darwin && cgo)

package cli

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// icons/ is rendered from assets/tray/*.svg: rsvg-convert -w 64 for the
// colored icons, -w 44 for the macOS template (monochrome) ones. The
// states differ in shape, not just color, so the template ones tell them
// apart too: a filled disc when connected, a dashed ring while starting or
// waiting, the bare glyph when disconnected, and a badge on it when
// something needs fixing.
//
//go:embed icons/*.png
var trayIcons embed.FS

func trayCmd() *cobra.Command {
	var foreground, allow bool
	cmd := &cobra.Command{
		Use:   "tray",
		Short: "Show a tray icon (menu bar icon on macOS) to control proxy-router",
		Long: `Show an icon in the system tray (the menu bar on macOS) that shows whether
proxy-router is connected, and lets you connect and disconnect, switch
between proxy and TUN mode, pick a server and update subscriptions.

It controls the background service, like "start" and "stop" do; TUN mode
asks for your password in a system dialog (on macOS only once for
connecting and disconnecting). "Start tray at login" in its menu makes the
icon come back after a reboot.

The tray runs in the background and returns right away; quit it from its
menu. --foreground keeps it attached to the terminal instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if allow {
				return allowSudo()
			}
			if os.Geteuid() == 0 {
				return errors.New("run the tray as your user, not root; it asks for your password when TUN mode needs it")
			}
			dir, err := configDir()
			if err != nil {
				return err
			}
			if !foreground {
				// At login the tray host may not be up yet; the
				// login item uses --foreground.
				if err := trayAvailable(); err != nil {
					return err
				}
			}
			if err := ensureFiles(dir, false); err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if exe, err = filepath.EvalSymlinks(exe); err != nil {
				return err
			}
			if err := lockTray(dir); err != nil {
				return err
			}
			if !foreground {
				return detachTray(exe, dir)
			}
			userT, sysT, err := targets()
			if err != nil {
				return err
			}
			t := &tray{dir: dir, exe: exe, userT: userT, sysT: sysT, kick: make(chan struct{}, 1)}
			if panelAvailable() && trayOpensPanelOnTap {
				systray.SetOnTapped(t.togglePanel)
				// The monitor must be listening before the first click.
				watchTrayClicks()
			}
			systray.Run(t.ready, nil)
			// The popover belongs to the tray; don't leave it running alone.
			panelRequest(panelSocket(dir), "quit", nil)
			return nil
		},
	}
	cmd.Flags().BoolVar(&foreground, "foreground", false, "stay attached to the terminal")
	cmd.Flags().BoolVar(&allow, "allow-sudo", false, "as root: let the user connect and disconnect TUN mode without a password (run by the macOS password dialog)")
	_ = cmd.Flags().MarkHidden("allow-sudo")
	return cmd
}

// detachTray starts "tray --foreground" in its own session, so it outlives
// the terminal, and returns once it's clearly up. Its output goes to
// tray.log. The caller holds the tray lock, which is handed over.
func detachTray(exe, dir string) error {
	logName := filepath.Join(dir, "tray.log")
	logf, err := os.OpenFile(logName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	_ = logf.Chmod(0o600)
	cmd := exec.Command(exe, "--dir", dir, "tray", "--foreground")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	trayLock.Close() // released just before the child takes it
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	select {
	case <-exited:
		out, _ := os.ReadFile(logName)
		return fmt.Errorf("the tray exited right away:\n%s", lastLines(string(out), 5))
	case <-time.After(time.Second):
	}
	fmt.Printf("tray started (pid %d); quit it from its menu\n", cmd.Process.Pid)
	return nil
}

// trayLock keeps a second tray from starting; it's held until the process
// exits (and kept referenced so it isn't closed by the GC).
var trayLock *os.File

func lockTray(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, "tray.lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errors.New("the tray is already running")
		}
		return err
	}
	trayLock = f
	return nil
}

type tray struct {
	dir, exe    string
	userT, sysT service.Target
	kick        chan struct{} // asks the loop to refresh now

	mu        sync.Mutex
	lastError string // last failed action, visible even when notifications are disabled
	busy      string // the running action, shown in place of the status
	wantTUN   *bool  // mode picked while disconnected
	last      trayModel
	built     bool

	// service.Outdated compares whole binaries; only redo it when the
	// service's copy changes.
	outdatedKey map[service.Scope]string
	outdatedVal map[service.Scope]bool
}

// trayModel is everything the menu shows; the menu is rebuilt when it
// changes.
type trayModel struct {
	icon       string // on, waiting, off, alert
	status     string
	details    []string
	addrs      []trayAddr // proxy listeners, copied on click
	connected  bool       // the service is running (or starting)
	foreground bool       // "proxy-router run" is active in a terminal
	tun        bool
	needRoot   bool // stopping, or starting in the shown mode, needs root
	outdated   bool
	groups     []trayGroup
	selGroup   string
	selName    string
	auto       bool // the service replaces the server when it stops working
	autoSet    bool // the saved selection lets the service replace the server
	autostart  bool
	busy       bool
	configErr  string
	actionErr  string
}

type trayAddr struct{ label, addr string }

type trayGroup struct {
	name         string
	servers      []string
	subscription bool
}

func (t *tray) ready() {
	t.refresh()
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
			case <-t.kick:
			}
			t.refresh()
		}
	}()
}

func (t *tray) poke() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// refresh rebuilds the menu if anything it shows changed. Only the loop
// in ready (and ready itself, before it starts) calls it.
func (t *tray) refresh() {
	m := t.model()
	t.mu.Lock()
	same := t.built && fmt.Sprintf("%#v", m) == fmt.Sprintf("%#v", t.last)
	t.last, t.built = m, true
	t.mu.Unlock()
	if same {
		return
	}
	setTrayIcon(m.icon)
	systray.SetTooltip(m.tooltip())
	systray.ResetMenu()
	t.build(m)
}

func (t *tray) model() trayModel {
	t.mu.Lock()
	busy, wantTUN, actionErr := t.busy, t.wantTUN, t.lastError
	t.mu.Unlock()

	m := trayModel{actionErr: actionErr}
	us, _ := service.Query(t.userT)
	ss, _ := service.Query(t.sysT)
	st, live := readRunStatus(t.dir)
	m.connected = us.Running || ss.Running || (live && st.Service)
	m.foreground = live && !st.Service
	m.autostart = trayAutostartEnabled()
	m.outdated = (us.Installed && t.outdated(t.userT)) || (ss.Installed && t.outdated(t.sysT))

	e, err := load()
	switch {
	case wantTUN != nil && !m.connected && !m.foreground:
		m.tun = *wantTUN
	case ss.Installed:
		m.tun = true
	case us.Installed:
	case err == nil:
		m.tun = e.cfg.TUN.Enabled
	}
	if err != nil {
		m.configErr = err.Error()
	} else {
		for _, sub := range e.state.Subscriptions {
			g := trayGroup{name: sub.Name, subscription: true}
			for _, s := range sub.Servers {
				g.servers = append(g.servers, s.Name)
			}
			m.groups = append(m.groups, g)
		}
		if len(e.state.Manual) > 0 {
			g := trayGroup{name: config.ManualGroup}
			for _, s := range e.state.Manual {
				g.servers = append(g.servers, s.Name)
			}
			m.groups = append(m.groups, g)
		}
		if cur, ok := e.state.Current(); ok {
			m.selGroup, m.selName = cur.Group, cur.Server.Name
			m.autoSet = e.state.Selected.Auto
		}
	}
	if m.connected {
		m.needRoot = ss.Installed && (ss.Running || ss.Enabled || live && st.Mode == "tun")
	} else {
		m.needRoot = m.tun || ss.Installed
	}

	mode := "Proxy"
	if m.tun {
		mode = "All Traffic"
	}
	m.icon = "off"
	switch {
	case m.foreground:
		m.icon = "on"
		m.status = fmt.Sprintf("Running in a Terminal · %s (pid %d)", mode, st.PID)
	case live && st.State == "waiting":
		m.icon = "waiting"
		m.status = "Waiting: " + st.Waiting
	case live:
		m.icon = "on"
		m.status = "Connected · " + mode
	case m.connected:
		m.icon = "waiting"
		m.status = "Starting…"
	case m.configErr != "":
		m.icon = "alert"
		m.status = "Can't Connect"
	default:
		m.status = "Disconnected"
	}
	if live && st.State != "waiting" {
		server := st.Server // "#3 group/name"
		if strings.HasPrefix(server, "#") {
			_, server, _ = strings.Cut(server, " ")
		}
		if st.Auto {
			server += " (auto)"
		}
		m.auto = st.Auto
		m.details = append(m.details, "Server: "+server)
		if st.TUN != "" {
			via := ""
			if st.Via != "" {
				via = " via " + st.Via
			}
			m.details = append(m.details, "Interface: "+st.TUN+via)
		}
		if st.Socks != "" {
			m.addrs = append(m.addrs, trayAddr{"SOCKS5", st.Socks})
		}
		if st.HTTP != "" {
			m.addrs = append(m.addrs, trayAddr{"HTTP", st.HTTP})
		}
	}
	if !live {
		if _, err := os.Stat(filepath.Join(systemRunDir(), "status.json")); errors.Is(err, os.ErrPermission) {
			m.status, m.icon = "Service Status Unavailable", "alert"
			m.details = append(m.details, "Can't read the service's status; run proxy-router restart")
		}
	}
	if busy != "" {
		m.status, m.busy = busy, true
	}
	return m
}

func (t *tray) outdated(target service.Target) bool {
	fi, err := os.Stat(service.BinaryPath(target))
	if err != nil {
		return false
	}
	key := fmt.Sprint(fi.Size(), fi.ModTime().UnixNano())
	if t.outdatedKey == nil {
		t.outdatedKey, t.outdatedVal = map[service.Scope]string{}, map[service.Scope]bool{}
	}
	if t.outdatedKey[target.Scope] != key {
		t.outdatedKey[target.Scope] = key
		t.outdatedVal[target.Scope] = service.Outdated(target)
	}
	return t.outdatedVal[target.Scope]
}

// tooltip is what hovering the icon shows: the status and the details the
// menu leaves out.
func (m trayModel) tooltip() string {
	return strings.Join(append([]string{"proxy-router " + version(), m.status}, m.details...), "\n")
}

// build lays the menu out one line per decision: the status and the
// switch, then server, mode and addresses, then the rarely used rest under
// More. Problems get a line at the top only while there are any.
func (t *tray) build(m trayModel) {
	systray.AddMenuItem(menuLabel(m.status), "").Disable()
	t.warnings(m)
	if !m.foreground {
		if m.connected {
			t.onClick(systray.AddMenuItem("Disconnect", ""), m.busy, func() {
				t.run("Disconnecting…", m.needRoot, "stop")
			})
		} else {
			t.onClick(systray.AddMenuItem("Connect", ""), m.busy || m.configErr != "", func() {
				t.run("Connecting…", m.needRoot, "start", modeFlag(m.tun))
			})
		}
	}
	if panelAvailable() {
		t.onClick(systray.AddMenuItem("Open Panel", "Show the control window"), false, t.openPanel)
	}
	systray.AddSeparator()

	t.serverMenu(m)
	if !m.foreground {
		t.modeMenu(m)
	}
	if len(m.addrs) > 0 {
		cp := systray.AddMenuItem("Copy Proxy Address", "")
		for _, a := range m.addrs {
			t.onClick(cp.AddSubMenuItem(menuLabel(a.label+"  "+a.addr), ""), false, func() {
				if err := copyText(a.addr); err != nil {
					notify("Couldn't copy the address", err.Error())
				}
			})
		}
	}
	systray.AddSeparator()

	more := systray.AddMenuItem("More", "")
	t.onClick(more.AddSubMenuItem("Edit Routing Rules", ""), false, func() {
		path := filepath.Join(t.dir, "routing.yaml")
		if e, err := load(); err == nil {
			path = e.cfg.RulesPath()
		}
		openText(path)
	})
	t.onClick(more.AddSubMenuItem("Show Log", ""), false, func() { openText(logPath(t.dir)) })
	t.onClick(more.AddSubMenuItem("Open Config Folder", ""), false, func() { openFolder(t.dir) })
	more.AddSeparator()
	t.onClick(more.AddSubMenuItemCheckbox("Start Tray at Login", "", m.autostart), false, func() {
		if err := setTrayAutostart(!m.autostart, t.exe, t.dir); err != nil {
			notify("Couldn't change login item", err.Error())
		}
		t.poke()
	})
	t.onClick(systray.AddMenuItem("Quit Tray", "The service keeps running; use Disconnect to stop it"), false, systray.Quit)
}

// warnings adds a line for each thing that needs the user, each opening
// what fixes it.
func (t *tray) warnings(m trayModel) {
	if m.configErr != "" {
		t.onClick(systray.AddMenuItem(menuLabel("⚠ Config error: "+firstLine(m.configErr)), "Open config.yaml"), false, func() {
			openText(filepath.Join(t.dir, "config.yaml"))
		})
	}
	if m.actionErr != "" {
		t.onClick(systray.AddMenuItem(menuLabel("⚠ "+lastLines(m.actionErr, 1)), "Show the tray's log"), false, func() {
			openText(filepath.Join(t.dir, "tray.log"))
		})
	}
	if m.outdated && !m.foreground {
		t.onClick(systray.AddMenuItem("⚠ Update the Service to This Build", "The service runs a different build of proxy-router"), m.busy, func() {
			t.run("Restarting…", m.needRoot || m.tun, "restart")
		})
	}
}

// modeMenu adds the mode picker, titled with the current mode. Picking the
// other one restarts a running service in it, or is remembered for the
// next Connect.
func (t *tray) modeMenu(m trayModel) {
	title := "Mode: Proxy"
	if m.tun {
		title = "Mode: All Traffic"
	}
	mode := systray.AddMenuItem(title, "")
	for _, c := range []struct {
		tun        bool
		label, tip string
	}{
		{false, "Proxy (SOCKS5 and HTTP)", "Run a local proxy that apps opt in to"},
		{true, "All Traffic (TUN)", "Capture all traffic; asks for your password"},
	} {
		t.onClick(choice(mode, c.label, c.tip, m.tun == c.tun), m.busy || m.configErr != "", func() {
			if m.tun == c.tun {
				return
			}
			if m.connected {
				t.run("Switching mode…", true, "start", modeFlag(c.tun))
				return
			}
			tun := c.tun
			t.mu.Lock()
			t.wantTUN = &tun
			t.mu.Unlock()
			t.poke()
		})
	}
}

// serverMenu adds the server picker, titled with the selected server so
// it's visible without opening it. Big lists are split by country (going
// by the flag servers' names start with), with the subscriptions one
// level down; small ones list the subscriptions directly. Like Happ, a
// name's flag is shown as a round icon instead (a globe for servers
// without one); inside a country it's left out, being the same on every
// line.
func (t *tray) serverMenu(m trayModel) {
	title := "Server: Choose…"
	if m.selName != "" {
		_, name := splitFlag(m.selName)
		title = "Server: " + name
		if m.auto || m.autoSet {
			title += " (auto)"
		}
	}
	servers := systray.AddMenuItem(menuLabel(title)+iconLabelPad, "")
	if m.selName != "" {
		servers.SetIcon(serverIcon(m.selName))
	}
	if m.configErr != "" {
		servers.Disable()
	}
	if len(m.groups) == 0 {
		servers.AddSubMenuItem(`No servers yet ("proxy-router sub add <url>")`, "").Disable()
		return
	}
	t.onClick(servers.AddSubMenuItem("⚡ Fastest Available", "Test every server and pick the fastest one that works"), m.busy, func() {
		t.run("Testing servers…", false, "use", "--fastest")
	})
	servers.AddSeparator()
	countries, other := byCountry(m.groups)
	groupsIn := servers
	if countries != nil {
		for _, c := range append(countries, trayCountry{name: "Other", servers: other}) {
			if len(c.servers) == 0 {
				continue
			}
			sel := slices.ContainsFunc(c.servers, func(s trayServer) bool { return s.group == m.selGroup && s.name == m.selName })
			parent := choice(servers, menuLabel(fmt.Sprintf("%s (%d)", c.name, len(c.servers)))+iconLabelPad, "", sel)
			parent.SetIcon(flagIcon(c.flag))
			for _, s := range c.servers {
				item := choice(parent, menuLabel(s.label), "", s.group == m.selGroup && s.name == m.selName)
				t.onClick(item, m.busy, func() { t.selectServer(s.group, s.name) })
			}
		}
		servers.AddSeparator()
		groupsIn = servers.AddSubMenuItem("Subscriptions", "")
	}
	for _, g := range m.groups {
		label := fmt.Sprintf("%s (%d)", menuLabel(g.name), len(g.servers))
		parent := choice(groupsIn, label, "", g.name == m.selGroup)
		// Actions first: a big subscription's list scrolls.
		t.onClick(parent.AddSubMenuItem("⚡ Fastest Available in This Group", ""), m.busy || len(g.servers) == 0, func() {
			t.run("Testing "+g.name+"…", false, "use", "--fastest", "--group", g.name)
		})
		if g.subscription {
			t.onClick(parent.AddSubMenuItem("Update Subscription", ""), m.busy, func() {
				t.run("Updating "+g.name+"…", false, "sub", "update", "--", g.name)
			})
		}
		parent.AddSeparator()
		if len(g.servers) == 0 {
			parent.AddSubMenuItem("No servers", "").Disable()
		}
		for _, name := range g.servers {
			_, label := splitFlag(name)
			item := choice(parent, menuLabel(label)+iconLabelPad, "", g.name == m.selGroup && name == m.selName)
			item.SetIcon(serverIcon(name))
			t.onClick(item, m.busy, func() { t.selectServer(g.name, name) })
		}
	}
	if slices.ContainsFunc(m.groups, func(g trayGroup) bool { return g.subscription }) {
		groupsIn.AddSeparator()
		t.onClick(groupsIn.AddSubMenuItem("Update All Subscriptions", ""), m.busy, func() {
			t.run("Updating subscriptions…", false, "sub", "update")
		})
	}
}

// choice adds an item to pick from a list, checked if it's the picked
// one. Only that one is checkable: KDE draws an empty box next to every
// other checkable item.
func choice(parent *systray.MenuItem, label, tip string, picked bool) *systray.MenuItem {
	if picked {
		return parent.AddSubMenuItemCheckbox(label, tip, true)
	}
	return parent.AddSubMenuItem(label, tip)
}

// onClick runs f for each click on item, or disables it.
func (t *tray) onClick(item *systray.MenuItem, disabled bool, f func()) {
	if disabled {
		item.Disable()
		return
	}
	go func() {
		for range item.ClickedCh { // closed when the menu is rebuilt
			f()
		}
	}()
}

func modeFlag(tun bool) string {
	if tun {
		return "--tun"
	}
	return "--no-tun"
}

func (t *tray) selectServer(group, name string) {
	e, err := load()
	if err == nil {
		err = fmt.Errorf("%s/%s no longer exists", group, name)
		for _, en := range e.state.Entries() {
			if en.Group == group && en.Server.Name == name {
				e.state.Select(en)
				err = e.state.Save()
				break
			}
		}
	}
	if err != nil {
		notify("Couldn't select the server", err.Error())
	}
	t.poke()
}

// run runs proxy-router with args in the background, showing what's
// happening in the menu. root says it may ask for the password (in the
// system's dialog); dismissing that isn't an error.
func (t *tray) run(what string, root bool, args ...string) {
	t.mu.Lock()
	if t.busy != "" {
		t.mu.Unlock()
		return
	}
	t.lastError = ""
	t.busy = what
	t.mu.Unlock()
	t.poke()
	go func() {
		defer func() {
			t.mu.Lock()
			t.busy = ""
			t.mu.Unlock()
			t.poke()
		}()
		// Commands run as the tray's user. Those that need root for part
		// of their work ask for the password themselves, in the
		// desktop's dialog, and only run that part as root.
		argv := append([]string{t.exe, "--dir", t.dir}, args...)
		switch args[0] {
		case "start", "stop", "restart":
			argv = append(argv, "--password-dialog")
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		fmt.Fprintf(os.Stderr, "%s: %s\n", what, strings.Join(args, " "))
		err := cmd.Run()
		if out.Len() > 0 {
			fmt.Fprint(os.Stderr, out.String())
		}
		if err != nil && root && authCanceled(err, out.String()) {
			t.mu.Lock()
			t.lastError = "Authentication was cancelled."
			t.mu.Unlock()
			return
		}
		if err != nil {
			msg := lastLines(out.String(), 4)
			if msg == "" {
				msg = err.Error()
			}
			t.mu.Lock()
			t.lastError = msg
			t.mu.Unlock()
			fmt.Fprintf(os.Stderr, "action failed: %s: %v\n", msg, err)
			notify("proxy-router: "+strings.TrimSuffix(strings.ToLower(what), "…")+" failed", msg)
			return
		}
		if args[0] == "use" {
			// "fastest: #3 group/name (120ms)"
			notify("proxy-router", firstLine(out.String()))
		}
	}()
}

// panelSocket is the Unix socket a running panel listens on; through it a
// second launch brings that window forward.
func panelSocket(dir string) string { return filepath.Join(dir, "panel.sock") }

// panelRequest sends a command to a running panel, with the anchor when the
// sender knows where the tray icon is. It reports whether one was there to
// ask.
func panelRequest(path, cmd string, a *panelAnchor) bool {
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	if a != nil {
		_, _ = fmt.Fprintf(c, "%s %d %d", cmd, a.X, a.Y)
	} else {
		_, _ = c.Write([]byte(cmd))
	}
	_ = c.Close()
	return true
}

// togglePanel opens the control window below the tray icon, or closes it if
// it is already open.
func (t *tray) togglePanel() { t.panel("toggle") }

// openPanel shows the control window, starting it if it isn't running.
func (t *tray) openPanel() { t.panel("show") }

func (t *tray) panel(cmd string) {
	var anchor *panelAnchor
	if a, ok := statusItemAnchor(); ok {
		anchor = &a
	}
	if panelRequest(panelSocket(t.dir), cmd, anchor) {
		return
	}
	logName := filepath.Join(t.dir, "panel.log")
	logf, err := os.OpenFile(logName, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		notify("Couldn't open the panel", err.Error())
		return
	}
	defer logf.Close()
	args := []string{"--dir", t.dir, "panel"}
	if anchor != nil {
		args = append(args, "--anchor", anchor.String())
	}
	cmd2 := exec.Command(t.exe, args...)
	cmd2.Stdout, cmd2.Stderr = logf, logf
	cmd2.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd2.Start(); err != nil {
		notify("Couldn't open the panel", err.Error())
		return
	}
	go func() { _ = cmd2.Wait() }()
}

func setTrayIcon(name string) {
	regular, _ := trayIcons.ReadFile("icons/" + name + ".png")
	template, _ := trayIcons.ReadFile("icons/" + name + "-template.png")
	if trayUsesTemplate {
		systray.SetTemplateIcon(template, regular)
	} else {
		systray.SetIcon(regular)
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
