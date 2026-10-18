package tun

import (
	"net"

	"golang.org/x/sys/unix"
)

// outsideSocket is owned by root, created here, so the kill switch lets it
// out, and is bound to iface, so it doesn't route into the TUN.
func outsideSocket(network, iface string) (int, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return -1, err
	}
	return newOutsideSocket(network, func(fd, family int) error {
		if family == unix.AF_INET6 {
			return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
	})
}

func peerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}

func replaceFD(fd, old int) error {
	if err := unix.Dup2(fd, old); err != nil {
		return err
	}
	unix.CloseOnExec(old)
	return nil
}
