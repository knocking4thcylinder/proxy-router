package cli

import (
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// systemOutput: launchd opens service.SystemLog, a root-owned file in a
// root-only directory, as the TUN service's stdout and stderr. Make it
// readable by admins only (whoever could install the service), have both
// share one O_APPEND file description and keep it trimmed.
func systemOutput() error {
	var st unix.Stat_t
	if err := unix.Fstat(1, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil
	}
	if g, err := user.LookupGroup("admin"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = unix.Fchown(1, 0, gid)
		}
	}
	_ = unix.Fchmod(1, 0o640)
	if fl, err := unix.FcntlInt(1, unix.F_GETFL, 0); err == nil {
		_, _ = unix.FcntlInt(1, unix.F_SETFL, fl|unix.O_APPEND)
	}
	_ = unix.Dup2(1, 2)
	trim(os.Stdout)
	keepTrimmed(os.Stdout)
	return nil
}

// systemLogName says where the TUN service's log is.
func systemLogName() string { return service.SystemLog }

// tailSystemLog shows the TUN service's log.
func tailSystemLog(n int, follow bool) error { return tailFile(service.SystemLog, n, follow) }
