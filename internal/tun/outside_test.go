//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// marked hands out sockets with a hop limit of 42, so tests can tell them
// from the ones Go creates.
func marked(network string) (int, error) {
	return newOutsideSocket(network, func(fd, family int) error {
		if family == unix.AF_INET6 {
			return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 42)
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, 42)
	})
}

func serveTest(t *testing.T, uid int, open func(string) (int, error)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outside.sock")
	l, err := serveOutside(path, uid, open)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	return path
}

func hops(t *testing.T, c syscall.Conn, family int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	raw.Control(func(fd uintptr) {
		if family == unix.AF_INET6 {
			v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
		} else {
			v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		}
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// TestOutsideControlTCP: a dial through OutsideControl uses the served
// socket and works like any other.
func TestOutsideControlTCP(t *testing.T) {
	path := serveTest(t, os.Getuid(), marked)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Write([]byte("hi"))
			c.Close()
		}
	}()
	d := net.Dialer{Control: OutsideControl(path), Timeout: 5 * time.Second}
	c, err := d.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if h := hops(t, c.(*net.TCPConn), unix.AF_INET); h != 42 {
		t.Errorf("TTL %d: not the served socket", h)
	}
	buf := make([]byte, 2)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf); err != nil || string(buf) != "hi" {
		t.Errorf("read %q, %v", buf, err)
	}
}

// TestOutsideControlUDP: Xray listens on the wildcard to send UDP, which
// Go does with a dual-stack IPv6 socket; the served one must reach IPv4.
func TestOutsideControlUDP(t *testing.T) {
	path := serveTest(t, os.Getuid(), marked)
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	lc := net.ListenConfig{Control: OutsideControl(path)}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if h := hops(t, pc.(*net.UDPConn), unix.AF_INET6); h != 42 {
		t.Errorf("hop limit %d: not the served socket", h)
	}
	if _, err := pc.WriteTo([]byte("hi"), srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := srv.ReadFrom(buf); err != nil || string(buf) != "hi" {
		t.Errorf("read %q, %v", buf, err)
	}
}

func TestOutsideErrors(t *testing.T) {
	path := serveTest(t, os.Getuid(), func(string) (int, error) { return -1, errors.New("no physical interface") })
	if _, err := OutsideSocket(path, "tcp4"); err == nil || err.Error() != "no physical interface" {
		t.Errorf("got %v; want the service's error", err)
	}
	path = serveTest(t, os.Getuid(), marked)
	if _, err := OutsideSocket(path, "unix"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("got %v; want unsupported network", err)
	}
}

// TestOutsideOtherUser: only the user it's for (and root) get sockets.
func TestOutsideOtherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always let in")
	}
	path := serveTest(t, os.Getuid()+1, marked)
	if _, err := OutsideSocket(path, "tcp4"); err == nil {
		t.Error("another user got a socket")
	}
}
