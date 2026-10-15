package cli

import "testing"

func TestSudoAction(t *testing.T) {
	bin, dir := "/Library/Application Support/proxy-router/proxy-router", "/Users/u/.config/proxy-router"
	argv := func(action ...string) []string {
		return append([]string{bin, "--dir", dir, "--uid", "501"}, action...)
	}
	for _, ok := range [][]string{argv("start", "--tun"), argv("stop", "--system")} {
		if !sudoAction(ok) {
			t.Errorf("%q isn't allowed", ok)
		}
	}
	for _, bad := range [][]string{
		argv("start", "--tun", "--force"), argv("restart", "--tun"), argv("uninstall", "--system"),
		argv("stop"), argv("start"), argv(), {bin, "--uid", "501", "--dir", dir, "stop", "--system"},
	} {
		if sudoAction(bad) {
			t.Errorf("%q is allowed", bad)
		}
	}
}
