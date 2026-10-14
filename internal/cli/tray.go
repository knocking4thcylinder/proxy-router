//go:build linux || (darwin && cgo)

package cli

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
// colored icons, -w 44 for the macOS template (monochrome) ones.
//
//go:embed icons/*.png
var trayIcons embed.FS

func trayCmd() *cobra.Command {
	var foreground bool
	cmd := &cobra.Command{
		Use:   "tray",
		Short: "Show a tray icon (menu bar icon on macOS) to control proxy-router",
		Long: `Show an icon in the system tray (the menu bar on macOS) that shows whether
proxy-router is connected, and lets you connect and disconnect, switch
between proxy and TUN mode, pick a server and update subscriptions.

It controls the background service, like "start" and "stop" do; TUN mode
asks for your password in a system dialog. "Start tray at login" in its
menu makes the icon come back after a reboot.

The tray runs in the background and returns right away; quit it from its
menu. --foreground keeps it attached to the terminal instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			systray.Run(t.ready, nil)
			return nil
		},
	}
	cmd.Flags().BoolVar(&foreground, "foreground", false, "stay attached to the terminal")
	return cmd
}

// detachTray starts "tray --foreground" in its own session, so it outlives
// the terminal, and returns once it's clearly up. Its output goes to
// tray.log. The caller holds the tray lock, which is handed over.
func detachTray(exe, dir string) error {
	logName := filepath.Join(dir, "tray.log")
	logf, err := os.OpenFile(logName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer logf.Close()
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

	mu      sync.Mutex
	busy    string // the running action, shown in place of the status
	wantTUN *bool  // mode picked while disconnected
	last    trayModel
	built   bool

	// service.Outdated compares whole binaries; only redo it when the
	// service's copy changes.
	outdatedKey map[service.Scope]string
	outdatedVal map[service.Scope]bool
}

// trayModel is everything the menu shows; the menu is rebuilt when it
// changes.
type trayModel struct {
	icon       string // on, waiting, off
	status     string
	details    []string
	connected  bool // the service is running (or starting)
	foreground bool // "proxy-router run" is active in a terminal
	tun        bool
	needRoot   bool // stopping, or starting in the shown mode, needs root
	outdated   bool
	groups     []trayGroup
	selGroup   string
	selName    string
	autostart  bool
	busy       bool
	configErr  string
}

type trayGroup struct {
	name    string
	servers []string
}

func (t *tray) ready() {
	systray.SetTooltip("proxy-router " + version())
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
	systray.ResetMenu()
	t.build(m)
}

func (t *tray) model() trayModel {
	t.mu.Lock()
	busy, wantTUN := t.busy, t.wantTUN
	t.mu.Unlock()

	var m trayModel
	us, _ := service.Query(t.userT)
	ss, _ := service.Query(t.sysT)
	st, live := readRunStatus(t.dir)
	m.connected = us.Running || ss.Running || (live && st.Service)
	m.foreground = live && !st.Service
	m.autostart = trayAutostartEnabled()
	m.outdated = (us.Installed && t.outdated(t.userT)) || (ss.Installed && t.outdated(t.sysT))

	e, err := load()
	switch {
	case ss.Installed:
		m.tun = true
	case us.Installed:
	case wantTUN != nil:
		m.tun = *wantTUN
	case err == nil:
		m.tun = e.cfg.TUN.Enabled
	}
	if err != nil {
		m.configErr = err.Error()
	} else {
		for _, sub := range e.state.Subscriptions {
			g := trayGroup{name: sub.Name}
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
		}
	}
	if m.connected {
		m.needRoot = ss.Installed && (ss.Running || ss.Enabled || live && st.Mode == "tun")
	} else {
		m.needRoot = m.tun || ss.Installed
	}

	m.icon = "off"
	switch {
	case m.foreground:
		m.icon = "on"
		m.status = fmt.Sprintf("Running in a terminal (pid %d)", st.PID)
	case live && st.State == "waiting":
		m.icon = "waiting"
		m.status = "Waiting: " + st.Waiting
	case live:
		m.icon = "on"
		m.status = "Connected"
	case m.connected:
		m.icon = "waiting"
		m.status = "Starting…"
	default:
		m.status = "Disconnected"
	}
	if live && st.State != "waiting" {
		server := st.Server // "#3 group/name"
		if strings.HasPrefix(server, "#") {
			_, server, _ = strings.Cut(server, " ")
		}
		m.details = append(m.details, "Server: "+server)
		if st.TUN != "" {
			m.details = append(m.details, "All traffic ("+st.TUN+")")
		}
		if st.Socks != "" {
			m.details = append(m.details, "SOCKS5 "+st.Socks)
		}
		if st.HTTP != "" {
			m.details = append(m.details, "HTTP "+st.HTTP)
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

func (t *tray) build(m trayModel) {
	info := func(s string) { systray.AddMenuItem(menuLabel(s), "").Disable() }
	info(m.status)
	for _, d := range m.details {
		info("    " + d)
	}
	if m.configErr != "" {
		info("Config error: " + firstLine(m.configErr))
	}
	systray.AddSeparator()

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
		tun := systray.AddMenuItemCheckbox("TUN Mode (All Traffic)", "Capture all traffic instead of running a local SOCKS5/HTTP proxy", m.tun)
		t.onClick(tun, m.busy || m.configErr != "", func() {
			if m.connected {
				t.run("Switching mode…", true, "start", modeFlag(!m.tun))
				return
			}
			want := !m.tun
			t.mu.Lock()
			t.wantTUN = &want
			t.mu.Unlock()
			t.poke()
		})
		if m.outdated {
			t.onClick(systray.AddMenuItem("Update Service to This Build", "The service runs a different build of proxy-router"), m.busy, func() {
				t.run("Restarting…", m.needRoot || m.tun, "restart")
			})
		}
	}
	systray.AddSeparator()

	servers := systray.AddMenuItem("Servers", "")
	if m.configErr != "" {
		servers.Disable()
	}
	for _, g := range m.groups {
		parent := servers
		if len(m.groups) > 1 {
			parent = servers.AddSubMenuItem(menuLabel(g.name), "")
		}
		for _, name := range g.servers {
			item := parent.AddSubMenuItemCheckbox(menuLabel(name), "", g.name == m.selGroup && name == m.selName)
			t.onClick(item, false, func() { t.selectServer(g.name, name) })
		}
	}
	if len(m.groups) == 0 {
		servers.AddSubMenuItem(`No servers yet ("proxy-router sub add <url>")`, "").Disable()
	} else {
		servers.AddSeparator()
		t.onClick(servers.AddSubMenuItem("Use the Fastest", "Ping every server and select the fastest"), m.busy, func() {
			t.run("Testing servers…", false, "use", "--fastest")
		})
	}
	t.onClick(servers.AddSubMenuItem("Update Subscriptions", ""), m.busy || len(m.groups) == 0, func() {
		t.run("Updating subscriptions…", false, "sub", "update")
	})
	systray.AddSeparator()

	t.onClick(systray.AddMenuItem("Edit Routing Rules", ""), false, func() {
		path := filepath.Join(t.dir, "routing.yaml")
		if e, err := load(); err == nil {
			path = e.cfg.RulesPath()
		}
		openPath(path)
	})
	t.onClick(systray.AddMenuItem("Show Log", ""), false, func() { openPath(logPath(t.dir)) })
	t.onClick(systray.AddMenuItem("Open Config Folder", ""), false, func() { openPath(t.dir) })
	systray.AddSeparator()
	t.onClick(systray.AddMenuItemCheckbox("Start Tray at Login", "", m.autostart), false, func() {
		if err := setTrayAutostart(!m.autostart, t.exe, t.dir); err != nil {
			notify("Couldn't change login item", err.Error())
		}
		t.poke()
	})
	t.onClick(systray.AddMenuItem("Quit Tray", "The service keeps running; use Disconnect to stop it"), false, systray.Quit)
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
		err := cmd.Run()
		if err != nil && root && authCanceled(err, out.String()) {
			return
		}
		if err != nil {
			msg := lastLines(out.String(), 4)
			if msg == "" {
				msg = err.Error()
			}
			notify("proxy-router: "+strings.TrimSuffix(strings.ToLower(what), "…")+" failed", msg)
			return
		}
		if args[0] == "use" {
			// "fastest: #3 group/name (120ms)"
			notify("proxy-router", firstLine(out.String()))
		}
	}()
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
