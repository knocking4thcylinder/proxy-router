//go:build !windows

package cli

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// maxLog is how large the service log may grow before it's cleared.
const maxLog = 10 << 20

// serviceOutput sets up the background service's output. The TUN service
// (root) already writes where its unit or plist says (see systemOutput);
// the user service writes to proxy-router.log in the config directory.
func serviceOutput(dir string) error {
	if os.Geteuid() == 0 {
		return systemOutput()
	}
	return redirectOutput(logPath(dir))
}

// redirectOutput sends stdout and stderr (ours, Xray's and Go runtime
// crashes alike) to the log file.
func redirectOutput(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	// The log may list every site visited; older versions made it 0644.
	_ = f.Chmod(0o600)
	trim(f)
	for _, fd := range []int{1, 2} {
		if err := unix.Dup2(int(f.Fd()), fd); err != nil {
			return fmt.Errorf("redirect output to %s: %w", path, err)
		}
	}
	keepTrimmed(f)
	return nil
}

func keepTrimmed(f *os.File) {
	go func() {
		for range time.Tick(time.Minute) {
			trim(f)
		}
	}()
}

// trim empties the log once it's too big. Writers use O_APPEND, so they
// carry on at the new end.
func trim(f *os.File) {
	if st, err := f.Stat(); err == nil && st.Size() > maxLog {
		_ = f.Truncate(0)
		fmt.Fprintf(f, "(log cleared at %s after reaching %d MB)\n", time.Now().Format(time.RFC3339), maxLog>>20)
	}
}

// systemRunDirOK creates systemRunDir if needed (systemd does for the
// service) and checks that only root can write to it.
func systemRunDirOK() bool {
	d := systemRunDir()
	_ = os.Mkdir(d, 0o755)
	fi, err := os.Lstat(d)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
