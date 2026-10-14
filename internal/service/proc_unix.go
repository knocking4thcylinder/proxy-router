//go:build !windows

package service

import (
	"errors"
	"syscall"
	"time"
)

// Alive reports whether a process exists (owned by anyone).
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitExit(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for Alive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}
