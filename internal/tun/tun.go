// Package tun routes the system's traffic into Xray's TUN interface.
//
// Only the two halves of the address space (0.0.0.0/1 and 128.0.0.0/1, plus
// ::/1 and 8000::/1 for IPv6) are pointed at the TUN. They beat the default
// route without replacing it, and anything more specific (the LAN,
// Tailscale's peers and 100.64.0.0/10) keeps going where it went before.
// proxy-router's own sockets are bound to the physical interface, so they
// don't loop back into the TUN.
package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RequireRoot fails with a helpful message when not running as root.
func RequireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("TUN mode needs root to create the interface and routes; run: sudo %s", strings.Join(os.Args, " "))
	}
	return nil
}

// WaitForInterface waits until Xray has created the interface.
func WaitForInterface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %s did not appear", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// WaitGone waits until a closed interface is really gone, so a new one
// with the same name can be created ("device or resource busy" otherwise).
func WaitGone(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(name); err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %s is still there after %v", name, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
