//go:build cgo && darwin

package cli

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// newPanelWindow creates an ordinary window; stylePanelWindow turns it into
// the borderless popover once it has been shown.
func newPanelWindow(a fyne.App) fyne.Window {
	return a.NewWindow("proxy-router")
}

// requestPanelPosition places the window before Show. The macOS anchor is
// already the window's top-left corner.
func requestPanelPosition(win fyne.Window, a panelAnchor) {
	if dw, ok := win.(desktop.Window); ok {
		dw.RequestPosition(a.X, a.Y)
	}
}
