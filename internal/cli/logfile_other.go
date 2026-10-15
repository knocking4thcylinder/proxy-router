//go:build !linux && !darwin && !windows

package cli

import "errors"

func systemOutput() error { return errors.New("the TUN service isn't supported on this system") }

func systemLogName() string { return "" }

func tailSystemLog(n int, follow bool) error {
	return errors.New("the TUN service isn't supported on this system")
}
