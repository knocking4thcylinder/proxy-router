//go:build linux

package cli

import (
	"sync/atomic"
	"time"
)

// lastTrayClick is the global click point, in physical pixels, of the last
// KDE StatusNotifierItem activation. The tray's click handler and the DBus
// monitor that records it run on different connections, so the handler may
// ask for it before the monitor has delivered the message.
var lastTrayClick atomic.Pointer[panelAnchor]

// trayClickWait is how long a panel request waits for the monitor to catch
// up with the click that triggered it. The very first click after the tray
// starts can therefore arrive without coordinates; later ones reuse the
// point already stored.
const trayClickWait = 75 * time.Millisecond

// statusItemAnchor returns the last tray click point. Linux status items
// have no window frame to read, so watchTrayClicks records KDE's Activate
// and ContextMenu coordinates instead.
func statusItemAnchor() (panelAnchor, bool) {
	deadline := time.Now().Add(trayClickWait)
	for {
		if a := lastTrayClick.Load(); a != nil {
			return *a, true
		}
		if !time.Now().Before(deadline) {
			return panelAnchor{}, false
		}
		time.Sleep(3 * time.Millisecond)
	}
}
