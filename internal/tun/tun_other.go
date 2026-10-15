//go:build !darwin && !linux

package tun

import (
	"fmt"
	"runtime"
)

func FreeName() (string, error) {
	return "", fmt.Errorf("TUN mode is not supported on %s yet", runtime.GOOS)
}

func SocketMark() int { return 0 }

func Up(o Options) error { return fmt.Errorf("unsupported") }

func Down(o Options, keepKillSwitch bool) {}

func Cleanup() error { return nil }

func Sync(o Options) error { return nil }
