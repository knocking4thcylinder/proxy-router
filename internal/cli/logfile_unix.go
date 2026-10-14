//go:build !windows

package cli

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

// maxLog is how large the service log may grow before it's cleared.
const maxLog = 10 << 20

// redirectOutput sends stdout and stderr (ours, Xray's and Go runtime
// crashes alike) to the log file.
func redirectOutput(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	config.GiveBack(path)
	trim(f)
	for _, fd := range []int{1, 2} {
		if err := unix.Dup2(int(f.Fd()), fd); err != nil {
			return fmt.Errorf("redirect output to %s: %w", path, err)
		}
	}
	go func() {
		for range time.Tick(time.Minute) {
			trim(f)
		}
	}()
	return nil
}

// trim empties the log once it's too big. Writers use O_APPEND, so they
// carry on at the new end.
func trim(f *os.File) {
	if st, err := f.Stat(); err == nil && st.Size() > maxLog {
		_ = f.Truncate(0)
		fmt.Fprintf(f, "(log cleared at %s after reaching %d MB)\n", time.Now().Format(time.RFC3339), maxLog>>20)
	}
}
