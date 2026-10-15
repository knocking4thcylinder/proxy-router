package cli

import (
	"strings"
	"testing"
)

// TestStartArgs: the root half of a TUN start gets the mode spelled out
// and nothing that only the user's half uses.
func TestStartArgs(t *testing.T) {
	for _, c := range []struct {
		o       startOptions
		restart bool
		want    string
	}{
		{startOptions{}, false, "start --tun"},
		{startOptions{noTUN: true}, false, "start --tun"}, // only called for TUN mode
		{startOptions{force: true, verbose: 2}, true, "restart --tun --force -vv"},
		{startOptions{rules: "/tmp/my rules.yaml", server: "Germany", noUpdate: true, systemProxy: true}, false, "start --tun --rules /tmp/my rules.yaml --server Germany --system-proxy --no-update"},
	} {
		if got := strings.Join(c.o.args(c.restart), " "); got != c.want {
			t.Errorf("%+v restart=%v: %q, want %q", c.o, c.restart, got, c.want)
		}
	}
}
