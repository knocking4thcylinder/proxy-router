package tun

import "golang.org/x/sys/unix"

// outsideSocket carries Mark, so the kill switch lets it out, and is bound
// to iface, so it doesn't route into the TUN.
func outsideSocket(network, iface string) (int, error) {
	return newOutsideSocket(network, func(fd, _ int) error {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, Mark); err != nil {
			return err
		}
		return unix.BindToDevice(fd, iface)
	})
}

func peerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}

func replaceFD(fd, old int) error { return unix.Dup3(fd, old, unix.O_CLOEXEC) }
