//go:build cgo && linux

package cli

import (
	"math"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
	"github.com/go-gl/glfw/v3.4/glfw"
)

const (
	// trayGap is the gap between the tray icon and the panel.
	trayGap = 24
	// edge is how close to a monitor edge a click must be to count as a
	// click on a panel there: Plasma's panel is usually 44-56 px thick.
	edge = 80
	// margin keeps the panel from touching the monitor's edge.
	margin = 6
)

// preparePanelProcess forces Fyne onto XWayland before it initializes GLFW:
// a Wayland window cannot be moved by the application, so the panel could
// not anchor to the tray icon. Systems without XWayland keep the default.
func preparePanelProcess() {
	if os.Getenv("DISPLAY") != "" {
		_ = os.Setenv("FYNE_PLATFORM", "x11")
	}
}

// stylePanelWindow is a no-op: the panel is a Fyne splash window, which has
// no title bar or decorations from the start.
func stylePanelWindow(panelAnchor) {}

// placePanelWindow moves every panel window to its computed spot. There is
// only one, but looking it up keeps the call sites the same as macOS, where
// the window is found natively.
func placePanelWindow(a panelAnchor) {
	app := fyne.CurrentApp()
	if app == nil || app.Driver() == nil {
		return
	}
	for _, win := range app.Driver().AllWindows() {
		requestPanelPosition(win, a)
	}
}

// activatePanelWindow keeps the popover over the app it controls. KWin drops
// the "keep above" state when a window is unmapped, so it has to be requested
// again on every reveal, not just at creation.
func activatePanelWindow() {
	app := fyne.CurrentApp()
	if app == nil || app.Driver() == nil {
		return
	}
	for _, win := range app.Driver().AllWindows() {
		if dw, ok := win.(desktop.Window); ok {
			dw.RequestAlwaysOnTop()
		}
	}
}

// requestPanelPosition places the window before Show on platforms where the
// anchor is not the window's top-left. Linux anchors carry the tray click in
// physical pixels, so compute the window's top-left from it.
func requestPanelPosition(win fyne.Window, a panelAnchor) {
	if win == nil {
		return
	}
	dw, ok := win.(desktop.Window)
	if !ok {
		return
	}
	x, y := panelTopLeft(win, a)
	dw.RequestPosition(x, y)
}

// panelTopLeft computes the window's top-left in the physical pixels GLFW's
// SetPos expects, from the click point and the monitor that holds it.
func panelTopLeft(win fyne.Window, a panelAnchor) (int, int) {
	w, h := panelPixelSize(win)
	mx, my, mw, mh := monitorAt(a.X, a.Y)
	return panelPosition(a, w, h, mx, my, mw, mh)
}

// panelPosition is the placement rule, split out to be testable without a
// display. The click point is in physical pixels, as are the monitor bounds.
func panelPosition(a panelAnchor, panelW, panelH, mx, my, mw, mh int) (int, int) {
	// A tray away from the panel edges usually sits at the top, so open
	// above it; a click on the bottom edge flips that.
	x, y := a.X-panelW/2, a.Y-trayGap-panelH
	switch {
	case a.Y >= my+mh-edge: // bottom bar
		x, y = a.X-panelW/2, a.Y-trayGap-panelH
	case a.Y <= my+edge: // top bar
		x, y = a.X-panelW/2, a.Y+trayGap
	case a.X <= mx+edge: // left bar
		x, y = a.X+trayGap, a.Y-panelH/2
	case a.X >= mx+mw-edge: // right bar
		x, y = a.X-trayGap-panelW, a.Y-panelH/2
	}
	return clampTo(x, mx+margin, mx+mw-panelW-margin),
		clampTo(y, my+margin, my+mh-panelH-margin)
}

// clampTo keeps v in [lo, hi], collapsing the range when the panel is wider
// or taller than the monitor.
func clampTo(v, lo, hi int) int {
	if hi < lo {
		hi = lo
	}
	switch {
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// panelPixelSize is the window's fixed size converted from Fyne units to
// the physical pixels RequestPosition uses. Before the first refresh there
// is no content height yet, so use a typical one; the first show is placed
// again after it becomes visible anyway.
func panelPixelSize(win fyne.Window) (int, int) {
	size := fyne.NewSize(panelWidth, 400)
	scale := float32(1)
	if win != nil {
		if s := win.Canvas().Size(); s.Width > 0 && s.Height > 0 {
			size = s
		}
		if s := win.Canvas().Scale(); s > 0 {
			scale = s
		}
	}
	if app := fyne.CurrentApp(); app != nil && scale <= 0 && app.Settings().Scale() > 0 {
		scale = app.Settings().Scale()
	}
	return int(math.Ceil(float64(size.Width * scale))), int(math.Ceil(float64(size.Height * scale)))
}

// monitorAt returns the monitor containing the click, or the primary one
// when the click is outside every monitor (for example after unplugging a
// display). The returned bounds are in physical pixels.
func monitorAt(x, y int) (int, int, int, int) {
	monitors := glfw.GetMonitors()
	for _, m := range monitors {
		mx, my := m.GetPos()
		mode := m.GetVideoMode()
		if mode == nil {
			continue
		}
		if x >= mx && x < mx+mode.Width && y >= my && y < my+mode.Height {
			return mx, my, mode.Width, mode.Height
		}
	}
	m := glfw.GetPrimaryMonitor()
	if m == nil {
		if len(monitors) == 0 {
			return 0, 0, 0, 0
		}
		m = monitors[0]
	}
	mx, my := m.GetPos()
	if mode := m.GetVideoMode(); mode != nil {
		return mx, my, mode.Width, mode.Height
	}
	return mx, my, 0, 0
}
