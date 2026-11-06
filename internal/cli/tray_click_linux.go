//go:build linux

package cli

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// watchTrayClicks eavesdrops on the session bus for KDE's calls to this
// process's StatusNotifierItem and records the last global click point.
// The monitor connection is private: systray keeps using the shared one for
// its own method calls. Setup runs before systray.Run so no click is missed.
func watchTrayClicks() {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tray click watcher: %v\n", err)
		return
	}
	// KDE resolves the status item to its unique bus name before calling it,
	// while direct callers use the well-known name. A second, ordinary
	// connection resolves the owner when the first such call arrives.
	resolver, err := dbus.ConnectSessionBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tray click watcher: %v\n", err)
	}
	rules := []string{
		"type='method_call',interface='org.kde.StatusNotifierItem',member='Activate'",
		"type='method_call',interface='org.kde.StatusNotifierItem',member='ContextMenu'",
	}
	if err := conn.BusObject().Call("org.freedesktop.DBus.Monitoring.BecomeMonitor", 0, rules, uint(0)).Err; err != nil {
		fmt.Fprintf(os.Stderr, "tray click watcher: %v\n", err)
		conn.Close()
		if resolver != nil {
			resolver.Close()
		}
		return
	}
	ch := make(chan *dbus.Message, 16)
	conn.Eavesdrop(ch)
	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	go func() {
		defer conn.Close()
		if resolver != nil {
			defer resolver.Close()
		}
		owner := ""
		for msg := range ch {
			// The monitor sees every status item on the bus; only this
			// process's clicks should move this process's panel.
			dest, _ := msg.Headers[dbus.FieldDestination].Value().(string)
			if owner == "" && dest != name && resolver != nil {
				_ = resolver.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, name).Store(&owner)
			}
			if !trayClickDestination(dest, name, owner) {
				continue
			}
			if len(msg.Body) < 2 {
				continue
			}
			x, okX := msg.Body[0].(int32)
			y, okY := msg.Body[1].(int32)
			if !okX || !okY {
				continue
			}
			a := panelAnchor{X: int(x), Y: int(y)}
			lastTrayClick.Store(&a)
		}
	}()
}

// trayClickDestination reports whether a monitored call was addressed to this
// status item. Direct callers use the well-known name; KDE resolves it to the
// owning connection's unique name first.
func trayClickDestination(dest, name, owner string) bool {
	return dest == name || (owner != "" && dest == owner)
}
