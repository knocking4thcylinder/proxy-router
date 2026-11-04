//go:build linux

package cli

// statusItemAnchor has no native status item frame to read on Linux; the
// panel opens as a normal window there.
func statusItemAnchor() (panelAnchor, bool) { return panelAnchor{}, false }

func preparePanelProcess()         {}
func stylePanelWindow(panelAnchor) {}
func placePanelWindow(panelAnchor) {}
func activatePanelWindow()         {}
