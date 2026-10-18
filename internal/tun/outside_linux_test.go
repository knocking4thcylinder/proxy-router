package tun

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestServeOutsideMarks needs root (a user and network namespace will do:
// unshare -rn go test -run TestServeOutsideMarks ./internal/tun).
func TestServeOutsideMarks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	path := filepath.Join(t.TempDir(), "outside.sock")
	l, err := ServeOutside(path, 0, func() (string, error) { return "lo", nil })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		fd, err := OutsideSocket(path, network)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if m, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK); err != nil || m != Mark {
			t.Errorf("%s: mark %#x, %v", network, m, err)
		}
		if dev, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE); err != nil || dev != "lo" {
			t.Errorf("%s: bound to %q, %v", network, dev, err)
		}
		unix.Close(fd)
	}
}
