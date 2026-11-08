//go:build cgo && linux

package cli

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// newPanelWindow creates the panel as a popover: a splash window has no
// title bar or decorations, and unlike an ordinary window it can be moved
// where the tray icon is.
func newPanelWindow(a fyne.App) fyne.Window {
	if d, ok := a.Driver().(desktop.Driver); ok {
		return d.CreateSplashWindow()
	}
	return a.NewWindow("proxy-router")
}
