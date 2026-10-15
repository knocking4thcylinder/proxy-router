package cli

import (
	"os"
	"os/exec"
	"strconv"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// systemOutput: the TUN service's output goes to the journal
// (StandardOutput=journal), which rotates it.
func systemOutput() error { return nil }

// systemLogName says where the TUN service's log is.
func systemLogName() string { return "journalctl -u " + service.Unit }

// tailSystemLog shows the TUN service's log. Reading the system journal
// as a user needs the systemd-journal or adm group; journalctl says so.
func tailSystemLog(n int, follow bool) error {
	args := []string{"--unit", service.Unit, "--lines", strconv.Itoa(n), "--output", "cat", "--no-pager"}
	if follow {
		args = append(args, "--follow")
	}
	c := exec.Command("journalctl", args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}
