package cli

import (
	"strings"
	"testing"
)

// TestElevated: pkexec runs the binary itself (so a polkit action for it
// applies and the dialog names it), with no environment passed through.
func TestElevated(t *testing.T) {
	argv := []string{"/var/lib/proxy-router/proxy-router", "--dir", "/home/u/.config/proxy-router", "--uid", "1000", "stop", "--system"}
	got := elevated(argv).Args
	if want := append([]string{"pkexec"}, argv...); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("got %q", got)
	}
}
