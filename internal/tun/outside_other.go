//go:build !darwin && !linux

package tun

import (
	"errors"
	"io"
	"syscall"
)

var errOutside = errors.New("outside sockets need TUN mode")

func ServeOutside(path string, uid int, iface func() (string, error)) (io.Closer, error) {
	return nil, errOutside
}

func CheckOutside(path string) error { return errOutside }

func OutsideControl(path string) func(network, address string, c syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return errOutside }
}
