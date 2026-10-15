package cli

import (
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/netif"
)

// TestBypass: another VPN is gone around, proxy-router's own TUN isn't (its
// kill switch would reject the traffic).
func TestBypass(t *testing.T) {
	for _, c := range []struct {
		d         netif.Detection
		own, want string
		note      bool
	}{
		{netif.Detection{}, "", "", false},
		{netif.Detection{}, "prtun0", "", false},
		{netif.Detection{Tunnel: "wg0", Physical: "wlan0"}, "", "wlan0", true},
		{netif.Detection{Tunnel: "wg0", Physical: "wlan0"}, "prtun0", "wlan0", true},
		{netif.Detection{Tunnel: "prtun0", Physical: "wlan0"}, "prtun0", "", true},
		{netif.Detection{Tunnel: "utun99", Physical: "en0"}, "utun99", "", true},
		{netif.Detection{Tunnel: "utun4", Physical: "en0"}, "utun99", "en0", true},
		{netif.Detection{Tunnel: "wg0"}, "", "", true},
	} {
		iface, note := bypass(c.d, c.own)
		if iface != c.want || (note != "") != c.note {
			t.Errorf("bypass(%+v, %q) = %q, %q; want %q (note: %t)", c.d, c.own, iface, note, c.want, c.note)
		}
	}
}
