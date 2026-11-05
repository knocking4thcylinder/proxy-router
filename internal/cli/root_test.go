package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/netif"
)

// TestWarningsPrintOnce: the tray reloads the config every 2 seconds, so a
// standing warning must not be written again on each refresh.
func TestWarningsPrintOnce(t *testing.T) {
	var l warningLog
	var out bytes.Buffer
	l.print(&out, []string{"one", "two", "one"})
	l.print(&out, []string{"one", "three"})
	if got, want := out.String(), "note: one\nnote: two\nnote: three\n"; got != want {
		t.Errorf("warnings printed as %q; want %q", got, want)
	}
}

// TestLoadPrintsWarningOnce exercises the tray's reload path: even when load
// runs repeatedly, the warning is written once.
func TestLoadPrintsWarningOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	cfgYAML := "auto_switch:\n  enabled: true\n  interval: 0\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	configWarnings.mu.Lock()
	configWarnings.seen = nil
	configWarnings.mu.Unlock()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	for i := 0; i < 3; i++ {
		if _, err := load(); err != nil {
			os.Stderr = old
			w.Close()
			t.Fatalf("load %d: %v", i, err)
		}
	}
	os.Stderr = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(out), "auto_switch.interval is 0"); got != 1 {
		t.Errorf("warning printed %d times, want 1:\n%s", got, out)
	}
}

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
