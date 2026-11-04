//go:build panel && (linux || (darwin && cgo))

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
)

// panelCmd is the control window the tray opens: the status and the
// server on one screen, the servers sorted by speed on another.
func panelCmd() *cobra.Command {
	var anchorFlag string
	cmd := &cobra.Command{
		Use:    "panel",
		Short:  "Show the control window",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() == 0 {
				return errors.New("run the panel as your user, not root")
			}
			dir, err := configDir()
			if err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			userT, sysT, err := targets()
			if err != nil {
				return err
			}
			anchor, hasAnchor := parsePanelAnchor(anchorFlag)
			p := &panel{t: &tray{dir: dir, exe: exe, userT: userT, sysT: sysT, kick: make(chan struct{}, 1)}}
			if hasAnchor {
				p.anchor = &anchor
			}
			preparePanelProcess()
			return p.run()
		},
	}
	cmd.Flags().StringVar(&anchorFlag, "anchor", "", "x,y of the tray icon's screen position")
	_ = cmd.Flags().MarkHidden("anchor")
	return cmd
}

// The Ember palette.
var (
	pBg      = hexColor("#17181c")
	pCard    = hexColor("#1f2025")
	pLine    = color.NRGBA{255, 255, 255, 18}
	pText    = hexColor("#ecebe8")
	pMute    = hexColor("#8f8d88")
	pDim     = hexColor("#6f6d69")
	pAcc     = hexColor("#ea580c")
	pAccInk  = hexColor("#fdba74")
	pAccSoft = color.NRGBA{234, 88, 12, 36}
	pTint    = color.NRGBA{234, 88, 12, 56}
	pSeg     = hexColor("#2c2d33")
	pGood    = hexColor("#4ade80")
	pWarn    = hexColor("#facc15")
	pBad     = hexColor("#f87171")
	pNone    = color.NRGBA{}
)

func hexColor(s string) color.NRGBA {
	var r, g, b uint8
	fmt.Sscanf(s, "#%02x%02x%02x", &r, &g, &b)
	return color.NRGBA{r, g, b, 255}
}

// panelTheme is Fyne's dark theme in the Ember colors, with no padding:
// the panel spaces things itself.
type panelTheme struct{}

func (panelTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground, theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return pBg
	case theme.ColorNameForeground:
		return pText
	case theme.ColorNamePrimary:
		return pAcc
	case theme.ColorNameScrollBar:
		return color.NRGBA{255, 255, 255, 40}
	}
	return theme.DefaultTheme().Color(n, theme.VariantDark)
}
func (panelTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (panelTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (panelTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNamePadding, theme.SizeNameInnerPadding:
		return 0
	case theme.SizeNameText:
		return 13
	}
	return theme.DefaultTheme().Size(n)
}

type panel struct {
	t      *tray
	app    fyne.App
	win    fyne.Window
	anchor *panelAnchor
	height float32
	styled bool
	open   bool

	mu         sync.Mutex
	results    map[string]engine.PingResult // by group + "\x00" + name
	testing    bool
	done       int
	total      int
	speedDone  int
	speedTotal int
	rev        int // changes whenever a result does
	testedAt   time.Time
	page       string // "home" or "servers"
	shown      string // what's on screen, to skip rebuilding it
}

const (
	// panelRecheck re-tests the selected and failing servers often, so a
	// transient timeout clears instead of sticking until the next scan.
	panelRecheck = 30 * time.Second
	// panelRecheckMax caps failing servers per recheck: with a large
	// subscription, rechecking every one would be a full scan.
	panelRecheckMax = 16
	// panelRescan is how often every server is tested again.
	panelRescan = 5 * time.Minute
)

func pingKey(group, name string) string { return group + "\x00" + name }

func (p *panel) run() error {
	// One panel serves every click: a second launch brings the running
	// window forward instead of opening another one. The lock lasts for
	// the panel's lifetime, and the lock file is never removed: deleting
	// it would let two later panels lock different inodes and both win.
	sock := panelSocket(p.t.dir)
	lock, err := lockPanel(sock)
	if err != nil {
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("panel lock: %w", err)
		}
		// The owning panel may still be starting, so give it a moment to
		// bind the socket before deciding it is unreachable.
		if panelRequestWait(sock, "show", p.anchor, time.Second) {
			return nil
		}
		return errors.New("another panel is running but isn't answering")
	}
	defer lock.Close()

	// We own the lock, so a socket at this path is left over from a panel
	// that exited without cleaning up.
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("panel socket: %w", err)
	}
	_ = os.Chmod(sock, 0o600)
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	}()

	p.app = app.NewWithID("io.github.knocking4thcylinder.proxy-router")
	p.app.Settings().SetTheme(panelTheme{})
	p.win = p.app.NewWindow("proxy-router")
	p.win.SetTitle("proxy-router")
	p.win.SetPadded(false)
	p.win.SetFixedSize(true)
	if dw, ok := p.win.(desktop.Window); ok {
		dw.RequestAlwaysOnTop() // stays over the app it controls
		if p.anchor != nil {
			dw.RequestPosition(p.anchor.X, p.anchor.Y)
		}
	}
	p.win.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			if p.page == "servers" {
				p.show("home")
			} else {
				p.hide()
			}
		}
	})
	p.page = "home"
	p.refresh()
	go p.ping()
	go func() {
		for range time.Tick(panelRecheck) {
			go p.autoTest()
		}
	}()
	go func() {
		for range time.Tick(2 * time.Second) {
			fyne.Do(p.refresh)
		}
	}()
	go p.serve(ln)
	if p.anchor != nil {
		p.reveal()
		p.app.Run()
		return nil
	}
	p.win.ShowAndRun()
	return nil
}

// lockPanel takes the panel's single-instance lock: the kernel drops it when
// the process exits, crashes included. The lock file is never removed, so a
// later panel can't race an earlier one by locking a fresh inode at the same
// path. EWOULDBLOCK means another panel holds it.
func lockPanel(sock string) (*os.File, error) {
	f, err := os.OpenFile(sock+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// panelRequestWait retries a request while the panel that owns the lock is
// still starting up and hasn't bound its socket yet.
func panelRequestWait(path, cmd string, a *panelAnchor, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if panelRequest(path, cmd, a) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// serve carries the tray's requests: show or toggle the window below the
// icon, or quit with the tray.
func (p *panel) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		req, _ := io.ReadAll(io.LimitReader(c, 256))
		_ = c.Close()
		cmd, a, hasAnchor := parsePanelRequest(string(req))
		if cmd == "" {
			continue
		}
		fyne.Do(func() { p.command(cmd, a, hasAnchor) })
	}
}

func (p *panel) command(cmd string, a panelAnchor, hasAnchor bool) {
	if hasAnchor {
		p.anchor = &a
		if p.styled {
			placePanelWindow(a)
		}
	}
	switch cmd {
	case "quit":
		p.app.Quit()
	case "hide":
		p.hide()
	case "toggle":
		if p.open {
			p.hide()
		} else {
			p.reveal()
		}
	default:
		p.reveal()
	}
}

// reveal shows the window under the tray icon, styling it as a popover the
// first time. The icon moves as menu bar items come and go, so every show
// takes the fresh anchor.
func (p *panel) reveal() {
	if p.anchor != nil {
		if dw, ok := p.win.(desktop.Window); ok {
			dw.RequestPosition(p.anchor.X, p.anchor.Y)
		}
	}
	p.open = true
	p.win.Show()
	if p.anchor != nil && !p.styled {
		stylePanelWindow(*p.anchor)
		p.styled = true
		// Removing the title bar changes the content area; size it back
		// and pin the top-left corner before the window is seen moving.
		p.win.Resize(fyne.NewSize(panelWidth, p.height))
		placePanelWindow(*p.anchor)
	}
	p.win.RequestFocus()
	if p.anchor != nil {
		activatePanelWindow()
	}
}

// hide closes the popover without quitting, so the next click is instant.
func (p *panel) hide() {
	p.open = false
	p.win.Hide()
}

// panelAvailable says whether this build has the control window.
func panelAvailable() bool { return true }

func (p *panel) show(page string) {
	p.page = page
	p.shown = ""
	p.refresh()
}

// refresh rebuilds the page when anything on it changed.
func (p *panel) refresh() {
	m := p.t.model()
	st, live := readRunStatus(p.t.dir)
	var obj fyne.CanvasObject
	var key string
	p.mu.Lock()
	key = fmt.Sprintf("%s|%#v|%v|%d|%d|%v|%d", p.page, m, st, len(p.results), p.done, p.testing, p.rev)
	p.mu.Unlock()
	if key == p.shown {
		return
	}
	p.shown = key
	if p.page == "servers" {
		obj = p.servers(m)
	} else {
		obj = p.home(m, st, live)
	}
	p.win.SetContent(obj)
	p.height = obj.MinSize().Height
	p.win.Resize(fyne.NewSize(panelWidth, p.height))
	if p.styled && p.anchor != nil {
		placePanelWindow(*p.anchor)
	}
}

// ping tests every server, updating the page as results come in.
func (p *panel) ping() {
	e, err := load()
	if err != nil {
		return
	}
	p.test(e.state.Entries(), true)
}

// autoTest runs on a timer: a full scan now and then, and cheap rechecks of
// the selected and failing servers in between.
func (p *panel) autoTest() {
	p.mu.Lock()
	testing, at := p.testing, p.testedAt
	p.mu.Unlock()
	if testing {
		return
	}
	if at.IsZero() || time.Since(at) >= panelRescan {
		p.ping()
		return
	}
	p.recheck()
}

// recheck re-tests only the selected server and the ones that failed, so a
// timeout that has cleared shows up without waiting for a full scan.
func (p *panel) recheck() {
	e, err := load()
	if err != nil {
		return
	}
	var entries, failed []config.Entry
	for _, en := range e.state.Entries() {
		selected := e.state.Selected != nil && en.Group == e.state.Selected.Group && en.Server.Name == e.state.Selected.Name
		r, ok := p.result(en.Group, en.Server.Name)
		switch {
		case selected:
			entries = append(entries, en)
		case ok && (r.Err != nil || r.SpeedErr != nil) && len(failed) < panelRecheckMax:
			failed = append(failed, en)
		}
	}
	p.test(append(entries, failed...), false)
}

// test pings entries and merges every progress update into the results, so
// latencies appear while speeds are still being measured.
func (p *panel) test(entries []config.Entry, full bool) {
	p.mu.Lock()
	if p.testing || len(entries) == 0 {
		p.mu.Unlock()
		return
	}
	p.testing = true
	p.done, p.total = 0, len(entries)
	p.speedDone, p.speedTotal = 0, 0
	if p.results == nil {
		p.results = map[string]engine.PingResult{}
	}
	for _, en := range entries {
		k := pingKey(en.Group, en.Server.Name)
		r, ok := p.results[k]
		if !ok {
			// Leave untested servers out of the map so the page shows
			// "…" until their first result arrives.
			continue
		}
		r.Entry = en
		r.Speed, r.SpeedErr = 0, nil
		p.results[k] = r
	}
	p.rev++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.testing = false
		if full {
			p.testedAt = time.Now()
		}
		p.rev++
		p.mu.Unlock()
		fyne.Do(p.refresh)
	}()

	e, err := load()
	if err != nil {
		return
	}
	o, _ := e.pingOptions(16)
	o.OnProgress = func(u engine.PingProgress) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.results == nil {
			p.results = map[string]engine.PingResult{}
		}
		p.results[pingKey(u.Result.Entry.Group, u.Result.Entry.Server.Name)] = u.Result
		switch u.Phase {
		case engine.PhaseSpeed:
			p.speedDone, p.speedTotal = u.Completed, u.Total
		default:
			if u.EntryDone {
				p.done++
			}
		}
		p.rev++
	}
	engine.Ping(context.Background(), entries, o)
}

func (p *panel) result(group, name string) (engine.PingResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.results[pingKey(group, name)]
	return r, ok
}

// ---- home ----

func (p *panel) home(m trayModel, st runStatus, live bool) fyne.CanvasObject {
	// Power, status and how long it's been up, on the state's tint.
	icon := "off"
	status, sub := "Disconnected", "Not protecting any traffic"
	switch {
	case m.busy:
		icon, status, sub = "waiting", m.status, ""
	case live && st.State == "waiting":
		icon, status, sub = "waiting", "Waiting", st.Waiting
	case live:
		icon, status, sub = "on", "Connected", "for "+since(st.Started)
	case m.connected:
		icon, status, sub = "waiting", "Starting…", ""
	case m.configErr != "":
		icon, status, sub = "alert", "Can't connect", firstLine(m.configErr)
	}
	statusColor := pAccInk
	if icon != "on" {
		statusColor = pText
	}
	power := newTap(iconImage("icons/"+icon+".png", 52), func() {
		if m.connected {
			p.t.run("Disconnecting…", m.needRoot, "stop")
		} else {
			p.t.run("Connecting…", m.needRoot, "start", modeFlag(m.tun))
		}
		p.shown = ""
	})
	gear := imageOf(theme.SettingsIcon(), 16)
	hero := container.NewHBox(power, gap(14), container.NewVBox(layout.NewSpacer(), txt(status, 16, statusColor, true, false), gap(2), txt(shorten(sub, 34), 12, pMute, false, false), layout.NewSpacer()), layout.NewSpacer(), container.NewVBox(gear, layout.NewSpacer()))
	var heroBg fyne.CanvasObject = canvas.NewRectangle(pNone)
	if icon == "on" {
		heroBg = canvas.NewVerticalGradient(pTint, pNone)
	}
	top := container.NewStack(heroBg, pad(16, 14, 16, 16, hero))

	// The server, the mode and what auto-switching did.
	var rows []fyne.CanvasObject
	rows = append(rows, newTap(pad(11, 11, 12, 12, p.serverRow(m)), func() { p.show("servers") }))
	if !m.foreground {
		rows = append(rows, hline(), pad(8, 8, 10, 10, p.modeSwitch(m)))
	}
	rows = append(rows, hline(), pad(8, 10, 12, 12, p.switches(m)))
	card := rounded(pCard, pLine, 12, container.NewVBox(rows...))

	// Actions.
	fastest := iconButton("icons/bolt-ink.png", "Fastest Available", pAccInk, func() { p.t.run("Testing servers…", false, "use", "--fastest") })
	acts := []fyne.CanvasObject{fastest}
	if len(m.addrs) > 0 {
		addr := m.addrs[0].addr
		_, port, _ := strings.Cut(addr, ":")
		acts = append(acts, button(":"+port+" ⧉", pText, func() { _ = copyText(addr) }))
	}
	acts = append(acts, button("Log", pText, func() { openText(logPath(p.t.dir)) }))
	actions := container.NewBorder(nil, nil, nil, container.NewHBox(append([]fyne.CanvasObject{gap(6)}, spaced(acts[1:])...)...), acts[0])

	body := container.NewVBox(top)
	if m.actionErr != "" {
		body.Add(pad(0, 0, 12, 12, p.actionErrBanner(m)))
	}
	body.Add(pad(0, 0, 12, 12, card))
	body.Add(pad(12, 12, 12, 12, actions))
	return container.NewStack(canvas.NewRectangle(pBg), body)
}

// actionErrBanner is the tray's last failed action. Notifications are easy
// to miss, and the window is where the user looks when a button did
// nothing; tapping the banner opens the log with the full command output.
func (p *panel) actionErrBanner(m trayModel) fyne.CanvasObject {
	text := container.NewVBox(
		txt("Last action failed", 12, pWarn, true, false),
		txt(shorten(firstLine(m.actionErr), 34), 11.5, pMute, false, false),
	)
	left := container.NewHBox(container.NewVBox(layout.NewSpacer(), txt("⚠", 15, pWarn, true, false), layout.NewSpacer()), gap(9), text)
	row := container.NewBorder(nil, nil, left, txt("Log ›", 11.5, pAccInk, false, false))
	return newTap(rounded(pCard, pLine, 9, pad(9, 9, 10, 10, row)), func() {
		openText(filepath.Join(p.t.dir, "tray.log"))
	})
}

func (p *panel) serverRow(m trayModel) fyne.CanvasObject {
	if m.selName == "" {
		return container.NewHBox(txt("Choose a server", 14, pText, true, false), layout.NewSpacer(), txt("›", 14, pDim, false, false))
	}
	flag, name := splitFlag(m.selName)
	country := m.selGroup
	if _, after, ok := cutLast(name, "|"); ok {
		country = after
		name, _, _ = cutLast(name, "|")
	}
	title := container.NewHBox(txt(shorten(name, 20), 14, pText, true, false))
	if m.auto || m.autoSet {
		title.Add(gap(6))
		title.Add(chip("AUTO"))
	}
	left := container.NewHBox(imageBytes(flagIcon(flag), 26), gap(11), container.NewVBox(title, txt(country, 12, pMute, false, false)))
	right := container.NewHBox(p.latency(m.selGroup, m.selName, 12), gap(8), txt("›", 14, pDim, false, false))
	return container.NewBorder(nil, nil, left, container.NewVBox(layout.NewSpacer(), right, layout.NewSpacer()))
}

// latency shows a server's test result: its speed over its latency, what's
// wrong, or nothing before it's tested.
func (p *panel) latency(group, name string, size float32) fyne.CanvasObject {
	r, ok := p.result(group, name)
	switch {
	case !ok:
		return txt("…", size, pDim, false, true)
	case r.Err != nil:
		return txt(failure(r.Err), size-.5, pBad, false, true)
	}
	lat := container.NewHBox(
		container.NewVBox(layout.NewSpacer(), dot(p.latencyColor(r.Latency), 7), layout.NewSpacer()),
		gap(5),
		txt(fmt.Sprintf("%d ms", r.Latency.Milliseconds()), size, pText, false, true),
	)
	switch {
	case r.Speed > 0:
		return container.NewVBox(txt(speedText(r.Speed), size-.5, speedColor(r.Speed), false, true), lat)
	case r.SpeedErr != nil:
		return container.NewVBox(txt(speedNote(r.SpeedErr), size-.5, pBad, false, true), lat)
	}
	return lat
}

func (p *panel) modeSwitch(m trayModel) fyne.CanvasObject {
	opt := func(label string, tun bool) fyne.CanvasObject {
		on := m.tun == tun
		bg, fg := pNone, pMute
		if on {
			bg, fg = pSeg, pText
		}
		return newTap(rounded(bg, pNone, 7, pad(6, 6, 0, 0, container.NewCenter(txt(label, 12, fg, false, false)))), func() {
			if on || m.busy || m.configErr != "" {
				return
			}
			if m.connected {
				p.t.run("Switching mode…", true, "start", modeFlag(tun))
				return
			}
			p.t.mu.Lock()
			p.t.wantTUN = &tun
			p.t.mu.Unlock()
			p.shown = ""
		})
	}
	return container.NewGridWithColumns(2, opt("Proxy", false), opt("All Traffic", true))
}

// switches lists auto-switching's recent moves, from the log. The header
// row doubles as the switch: tapping it toggles auto-switching on or off
// for the selected server.
func (p *panel) switches(m trayModel) fyne.CanvasObject {
	on := m.auto || m.autoSet
	var head fyne.CanvasObject = container.NewBorder(nil, nil, txt("AUTO-SWITCH", 10.5, pDim, true, false), toggleSwitch(on))
	if m.selName != "" && !m.busy {
		head = newTap(head, func() { p.toggleAuto(!on) })
	}
	rows := []fyne.CanvasObject{head, gap(4)}
	sw := readSwitches(logPath(p.t.dir), 2)
	if len(sw) == 0 {
		rows = append(rows, txt("None yet: the server hasn't stopped working", 11.5, pMute, false, false))
	}
	for _, s := range sw {
		rows = append(rows, container.NewHBox(txt(s.at, 11.5, pDim, false, true), gap(8), txt(shorten(s.from, 14), 11.5, pText, false, false), gap(4), txt("stalled →", 11.5, pBad, false, false), gap(4), txt(shorten(s.to, 14), 11.5, pText, false, false)))
	}
	return container.NewVBox(rows...)
}

// toggleAuto turns auto-switching on or off for the selected server. A
// running service picks the change up from state.json.
func (p *panel) toggleAuto(on bool) {
	e, err := load()
	if err == nil && e.state.Selected == nil {
		err = errors.New("choose a server first")
	}
	if err == nil {
		sel := *e.state.Selected
		sel.Auto = on
		e.state.Selected = &sel
		err = e.state.Save()
	}
	if err != nil {
		notify("Couldn't change auto-switching", err.Error())
		return
	}
	p.shown = ""
	p.refresh()
}

type panelSwitch struct{ at, from, to string }

// readSwitches finds the last n "auto-switch: X stopped working;
// switching to Y" lines in a log.
func readSwitches(path string, n int) []panelSwitch {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []panelSwitch
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		at, rest, ok := strings.Cut(line, " auto-switch: ")
		if !ok {
			continue
		}
		from, rest, ok := strings.Cut(rest, " stopped working; switching to ")
		if !ok {
			continue
		}
		to, _, _ := strings.Cut(rest, " (")
		short := func(s string) string { // "#3 group/name"
			if _, s2, ok := strings.Cut(s, " "); ok && strings.HasPrefix(s, "#") {
				s = s2
			}
			if _, s2, ok := strings.Cut(s, "/"); ok {
				s = s2
			}
			_, s = splitFlag(s)
			s, _, _ = cutLast(s, "|")
			return s
		}
		if len(at) > 5 {
			at = at[:5]
		}
		out = append(out, panelSwitch{at, short(from), short(to)})
	}
	slices.Reverse(out)
	return out[:min(n, len(out))]
}

// ---- servers ----

type panelCountry struct {
	trayCountry
	working, tested int
	best            engine.PingResult
	bestServer      trayServer
	selected        bool
}

func (p *panel) countries(m trayModel) (ok, dead []panelCountry, fastest *panelCountry) {
	cs, other := byCountry(m.groups)
	if cs == nil {
		// A short list: one row per subscription.
		for _, g := range m.groups {
			c := trayCountry{name: g.name}
			for _, s := range g.servers {
				_, label := splitFlag(s)
				c.servers = append(c.servers, trayServer{g.name, s, label})
			}
			cs = append(cs, c)
		}
	} else if len(other) > 0 {
		cs = append(cs, trayCountry{name: "Other", servers: other})
	}
	for _, c := range cs {
		pc := panelCountry{trayCountry: c}
		for _, s := range c.servers {
			if s.group == m.selGroup && s.name == m.selName {
				pc.selected = true
			}
			r, done := p.result(s.group, s.name)
			if !done {
				continue
			}
			pc.tested++
			if r.Err == nil {
				if pc.working == 0 || better(r, pc.best) {
					pc.best, pc.bestServer = r, s
				}
				pc.working++
			}
		}
		if pc.tested == len(c.servers) && pc.working == 0 {
			dead = append(dead, pc)
		} else {
			ok = append(ok, pc)
		}
	}
	// Fastest first; untested ones keep their order, after the tested.
	slices.SortStableFunc(ok, func(a, b panelCountry) int {
		switch {
		case a.working == 0 && b.working == 0:
			return 0
		case a.working == 0:
			return 1
		case b.working == 0:
			return -1
		case better(a.best, b.best):
			return -1
		case better(b.best, a.best):
			return 1
		}
		return 0
	})
	if len(ok) > 0 && ok[0].working > 0 {
		fastest = &ok[0]
	}
	return ok, dead, fastest
}

func (p *panel) servers(m trayModel) fyne.CanvasObject {
	back := newTap(txt("‹", 16, pMute, false, false), func() { p.show("home") })
	top := container.NewBorder(nil, nil, container.NewHBox(back, gap(10), txt("Choose a Server", 14, pText, true, false)), imageOf(theme.SearchIcon(), 15))

	p.mu.Lock()
	testing, done, total, speedDone, speedTotal, at := p.testing, p.done, p.total, p.speedDone, p.speedTotal, p.testedAt
	p.mu.Unlock()
	note := "tested " + panelAgo(at) + " · ↻"
	if testing {
		note = fmt.Sprintf("testing %d/%d…", done, total)
		if speedTotal > 0 {
			note = fmt.Sprintf("speeds %d/%d…", speedDone, speedTotal)
		}
	}
	sortLine := container.NewBorder(nil, nil, txt("Fastest first · working only", 11.5, pDim, false, false), newTap(txt(note, 11.5, pMute, false, false), func() { go p.ping() }))

	ok, dead, fastest := p.countries(m)
	var rows []fyne.CanvasObject
	if fastest != nil {
		s := fastest.bestServer
		label := s.label
		if fastest.flag != "" {
			label += " · " + fastest.name
		}
		detail := fmt.Sprintf("%d ms", fastest.best.Latency.Milliseconds())
		if fastest.best.Speed > 0 {
			detail = speedText(fastest.best.Speed) + " · " + detail
		}
		inner := container.NewBorder(nil, nil,
			container.NewHBox(container.NewVBox(layout.NewSpacer(), iconImage("icons/bolt-white.png", 15), layout.NewSpacer()), gap(10), container.NewVBox(txt("Fastest Available", 13, color.White, true, false), txt(shorten(label, 30), 11.5, color.NRGBA{255, 255, 255, 215}, false, false))),
			container.NewHBox(container.NewVBox(layout.NewSpacer(), imageBytes(flagIcon(fastest.flag), 15), layout.NewSpacer()), gap(5), container.NewVBox(layout.NewSpacer(), txt(detail, 12, color.White, false, true), layout.NewSpacer())))
		rows = append(rows, newTap(rounded(pAcc, pNone, 9, pad(8, 8, 10, 10, inner)), func() { p.t.run("Testing servers…", false, "use", "--fastest") }), gap(4))
	}
	for _, c := range ok {
		rows = append(rows, p.countryRow(c))
	}
	if len(dead) > 0 {
		var names []string
		for _, c := range dead {
			names = append(names, c.name)
		}
		rows = append(rows, gap(6), pad(7, 7, 10, 10, txt(shorten("Not responding: "+strings.Join(names, ", "), 44), 12, pDim, false, false)))
	}
	list := container.NewVBox(rows...)
	scroll := container.NewVScroll(pad(0, 10, 6, 6, list))
	scroll.SetMinSize(fyne.NewSize(340, min(list.MinSize().Height+10, 470)))

	body := container.NewVBox(pad(13, 8, 16, 12, top), pad(0, 6, 16, 16, sortLine))
	if m.actionErr != "" {
		body.Add(pad(0, 0, 16, 16, p.actionErrBanner(m)))
	}
	body.Add(scroll)
	return container.NewStack(canvas.NewRectangle(pBg), body)
}

func (p *panel) countryRow(c panelCountry) fyne.CanvasObject {
	nameColor := pText
	var bg color.Color = pNone
	if c.selected {
		nameColor, bg = pAccInk, pAccSoft
	}
	avail := fmt.Sprintf("%d/%d", c.working, len(c.servers))
	if c.tested < len(c.servers) && c.working == 0 {
		avail = fmt.Sprint(len(c.servers))
	}
	var rating fyne.CanvasObject = txt("…", 12, pDim, false, true)
	if c.working > 0 {
		lat := container.NewHBox(
			container.NewVBox(layout.NewSpacer(), dot(p.latencyColor(c.best.Latency), 6), layout.NewSpacer()),
			gap(5),
			txt(fmt.Sprintf("%d ms", c.best.Latency.Milliseconds()), 12, pText, false, true),
		)
		switch {
		case c.best.Speed > 0:
			rating = container.NewVBox(txt(speedText(c.best.Speed), 11.5, speedColor(c.best.Speed), false, true), lat)
		case c.best.SpeedErr != nil:
			rating = container.NewVBox(txt(speedNote(c.best.SpeedErr), 11, pBad, false, true), lat)
		default:
			rating = lat
		}
	}
	right := container.NewHBox(container.NewVBox(layout.NewSpacer(), txt(avail, 11.5, pDim, false, false), layout.NewSpacer()), gap(12), container.NewGridWrap(fyne.NewSize(72, 38), container.NewHBox(layout.NewSpacer(), rating)))
	row := container.NewBorder(nil, nil, container.NewHBox(imageBytes(flagIcon(c.flag), 20), gap(10), container.NewVBox(layout.NewSpacer(), txt(c.name, 13, nameColor, false, false), layout.NewSpacer())), right)
	return newTap(rounded(bg, pNone, 8, pad(6, 6, 10, 10, row)), func() {
		// The country's fastest working server.
		if c.working > 0 {
			p.t.selectServer(c.bestServer.group, c.bestServer.name)
			p.show("home")
		}
	})
}

// ---- pieces ----

func since(t time.Time) string {
	d := time.Since(t).Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}

func panelAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	return fmt.Sprintf("%d min ago", int(d.Minutes()))
}

func failure(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "stall"):
		return "stalls"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	}
	return "fails"
}

// speedNote is speedFailure for a narrow row: a failed speed test must not
// read like the server itself timed out, and the reason has to fit.
func speedNote(err error) string {
	switch {
	case errors.Is(err, engine.ErrStalled):
		return "stalled"
	case errors.Is(err, engine.ErrTooSlow):
		return "too slow"
	}
	return "no speed"
}

// latencyColor rates a latency against the fastest working server's:
// real delay through a proxy depends so much on the network that fixed
// thresholds paint everything one color.
func (p *panel) latencyColor(d time.Duration) color.Color {
	p.mu.Lock()
	var best time.Duration
	for _, r := range p.results {
		if r.Err == nil && (best == 0 || r.Latency < best) {
			best = r.Latency
		}
	}
	p.mu.Unlock()
	switch {
	case best == 0 || d <= best*3/2:
		return pGood
	case d <= best*3:
		return pWarn
	}
	return pBad
}

// speedColor rates a measured speed in absolute terms: 2 Mbit/s carries
// ordinary traffic, and under half a megabit is painful.
func speedColor(bps float64) color.Color {
	switch {
	case bps >= 2e6/8:
		return pGood
	case bps >= 0.5e6/8:
		return pWarn
	}
	return pBad
}

func shorten(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

func txt(s string, size float32, c color.Color, bold, mono bool) *canvas.Text {
	t := canvas.NewText(s, c)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: bold, Monospace: mono}
	return t
}

func gap(n float32) fyne.CanvasObject {
	r := canvas.NewRectangle(pNone)
	r.SetMinSize(fyne.NewSize(n, n))
	return r
}

func hline() fyne.CanvasObject {
	r := canvas.NewRectangle(pLine)
	r.SetMinSize(fyne.NewSize(1, 1))
	return r
}

func dot(c color.Color, size float32) fyne.CanvasObject {
	d := canvas.NewCircle(c)
	return container.NewGridWrap(fyne.NewSize(size, size), d)
}

func pad(t, b, l, r float32, o fyne.CanvasObject) fyne.CanvasObject {
	return container.New(layout.NewCustomPaddedLayout(t, b, l, r), o)
}

func rounded(fill, stroke color.Color, radius float32, content fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(fill)
	bg.CornerRadius = radius
	if stroke != pNone {
		bg.StrokeColor, bg.StrokeWidth = stroke, 1
	}
	return container.NewStack(bg, content)
}

func chip(s string) fyne.CanvasObject {
	return container.NewVBox(layout.NewSpacer(), rounded(pAccSoft, pNone, 5, pad(1, 1, 6, 6, txt(s, 10, pAccInk, true, false))), layout.NewSpacer())
}

// toggleSwitch is the small on/off control for a row's right edge: a
// rounded track whose knob slides right when it's on.
func toggleSwitch(on bool) fyne.CanvasObject {
	const w, h, k = float32(32), float32(18), float32(14)
	track := canvas.NewRectangle(pSeg)
	track.CornerRadius = h / 2
	track.StrokeColor, track.StrokeWidth = pLine, 1
	if on {
		track.FillColor = pAcc
	}
	track.Resize(fyne.NewSize(w, h))
	knob := canvas.NewCircle(pText)
	knob.Resize(fyne.NewSize(k, k))
	x := float32(2)
	if on {
		x = w - k - 2
	}
	knob.Move(fyne.NewPos(x, (h-k)/2))
	return container.NewGridWrap(fyne.NewSize(w, h), container.NewWithoutLayout(track, knob))
}

func iconButton(icon, label string, fg color.Color, f func()) fyne.CanvasObject {
	content := container.NewCenter(container.NewHBox(container.NewVBox(layout.NewSpacer(), iconImage(icon, 13), layout.NewSpacer()), gap(6), txt(label, 12, fg, false, false)))
	return newTap(rounded(pCard, pLine, 9, pad(8, 8, 10, 10, content)), f)
}

func button(label string, fg color.Color, f func()) fyne.CanvasObject {
	return newTap(rounded(pCard, pLine, 9, pad(8, 8, 10, 10, container.NewCenter(txt(label, 12, fg, false, false)))), f)
}

func imageBytes(b []byte, size float32) fyne.CanvasObject {
	img := canvas.NewImageFromResource(fyne.NewStaticResource(fmt.Sprintf("img%d", len(b)), b))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(size, size))
	return img
}

func iconImage(name string, size float32) fyne.CanvasObject {
	b, _ := trayIcons.ReadFile(name)
	return imageBytes(b, size)
}

func imageOf(r fyne.Resource, size float32) fyne.CanvasObject {
	img := canvas.NewImageFromResource(theme.NewColoredResource(r, theme.ColorNameDisabled))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(size, size))
	return img
}

// spaced puts a small gap between objs.
func spaced(objs []fyne.CanvasObject) []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i, o := range objs {
		if i > 0 {
			out = append(out, gap(6))
		}
		out = append(out, o)
	}
	return out
}

// tap makes anything clickable.
type tap struct {
	widget.BaseWidget
	obj fyne.CanvasObject
	f   func()
}

func newTap(obj fyne.CanvasObject, f func()) *tap {
	t := &tap{obj: obj, f: f}
	t.ExtendBaseWidget(t)
	return t
}

func (t *tap) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(t.obj) }
func (t *tap) Tapped(*fyne.PointEvent)             { t.f() }
func (t *tap) Cursor() desktop.Cursor              { return desktop.PointerCursor }
