//go:build !darwin && !linux

package tun

import (
	"fmt"
	"runtime"
)

func FreeName() (string, error) {
	return "", fmt.Errorf("TUN mode is not supported on %s yet", runtime.GOOS)
}

func Up(name string, ipv6 bool) error { return fmt.Errorf("unsupported") }

func Down(name string, ipv6 bool) {}
