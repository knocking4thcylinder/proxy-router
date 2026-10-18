//go:build darwin || linux

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The outside socket service lets the user's own processes open sockets
// that leave through the physical interface, around the TUN and past its
// kill switch, which only lets out sockets carrying Mark (Linux) or owned
// by root (macOS). A process running as the user can't do either itself.
// "proxy-router ping" uses it while TUN mode is on, so servers are tested
// directly instead of through the server the TUN uses.
//
// Each connection to the unix socket asks for one socket by its network
// ("tcp4", "udp6", ...) and gets it back as SCM_RIGHTS: created here,
// as root, bound to the physical interface and marked.

// outsideTimeout bounds one request on either side.
const outsideTimeout = 5 * time.Second

// ServeOutside serves outside sockets on the unix socket path, to uid and
// root only. iface returns the physical interface to bind them to.
func ServeOutside(path string, uid int, iface func() (string, error)) (io.Closer, error) {
	return serveOutside(path, uid, func(network string) (int, error) {
		name, err := iface()
		if err != nil {
			return -1, err
		}
		return outsideSocket(network, name)
	})
}

func serveOutside(path string, uid int, open func(network string) (int, error)) (io.Closer, error) {
	_ = os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// Anyone may connect; the peer's uid decides (handleOutside). The
	// service can't chown the socket to uid: it runs without CAP_CHOWN.
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := l.AcceptUnix()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleOutside(c, uid, open)
		}
	}()
	return l, nil
}

func handleOutside(c *net.UnixConn, uid int, open func(network string) (int, error)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(outsideTimeout))
	if peer, err := connUID(c); err != nil || (peer != 0 && peer != uid) {
		return
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	fd, err := open(string(buf[:n]))
	if err != nil {
		_, _ = c.Write([]byte(err.Error()))
		return
	}
	defer unix.Close(fd)
	_, _, _ = c.WriteMsgUnix([]byte("ok"), unix.UnixRights(fd), nil)
}

func connUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var uerr error
	if err := raw.Control(func(fd uintptr) { uid, uerr = peerUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, uerr
}

// OutsideSocket asks the service at path for a socket for network.
func OutsideSocket(path, network string) (int, error) {
	c, err := net.DialTimeout("unix", path, outsideTimeout)
	if err != nil {
		return -1, err
	}
	uc := c.(*net.UnixConn)
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(outsideTimeout))
	if _, err := uc.Write([]byte(network)); err != nil {
		return -1, err
	}
	buf, oob := make([]byte, 512), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, err
	}
	var fds []int
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, m := range msgs {
			got, _ := unix.ParseUnixRights(&m)
			fds = append(fds, got...)
		}
	}
	if string(buf[:n]) != "ok" || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		if n == 0 {
			return -1, errors.New("refused")
		}
		return -1, errors.New(string(buf[:n]))
	}
	return fds[0], nil
}

// CheckOutside reports whether the service at path hands out sockets.
func CheckOutside(path string) error {
	fd, err := OutsideSocket(path, "tcp4")
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// OutsideControl is a socket control function (net.Dialer.Control, or
// Xray's dialer controllers) that swaps each new TCP or UDP socket for one
// from the service at path before it connects or binds.
func OutsideControl(path string) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
			return nil
		}
		fd, err := OutsideSocket(path, network)
		if err != nil {
			return fmt.Errorf("outside socket: %w", err)
		}
		defer unix.Close(fd)
		// Go polls its sockets; O_NONBLOCK is shared with the dup.
		if err := unix.SetNonblock(fd, true); err != nil {
			return err
		}
		var derr error
		if err := c.Control(func(s uintptr) { derr = replaceFD(fd, int(s)) }); err != nil {
			return err
		}
		return derr
	}
}

// socketKind is the family and type of a socket for network.
func socketKind(network string) (family, typ int, err error) {
	switch network {
	case "tcp4":
		return unix.AF_INET, unix.SOCK_STREAM, nil
	case "tcp6":
		return unix.AF_INET6, unix.SOCK_STREAM, nil
	case "udp4":
		return unix.AF_INET, unix.SOCK_DGRAM, nil
	case "udp6":
		return unix.AF_INET6, unix.SOCK_DGRAM, nil
	}
	return 0, 0, fmt.Errorf("unsupported network %q", network)
}

// newOutsideSocket creates a socket for network. IPv6 ones are dual-stack,
// as Go makes them for wildcard UDP listens that send to IPv4 too.
func newOutsideSocket(network string, setup func(fd, family int) error) (int, error) {
	family, typ, err := socketKind(network)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(family, typ, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	if family == unix.AF_INET6 {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0)
	}
	if err == nil {
		err = setup(fd, family)
	}
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
