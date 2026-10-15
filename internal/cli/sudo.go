package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// A permission listing can succeed even when executing the command needs
// authentication. Retry via the dialog only for sudo's exact rejection,
// which means the privileged command did not run. Other failures must not
// run the command twice.
func runSudoWithFallback(cmd *exec.Cmd, dialog func() *exec.Cmd) error {
	var stderr bytes.Buffer
	output := cmd.Stderr
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	err := cmd.Run()
	if err != nil && strings.TrimSpace(stderr.String()) == "sudo: a password is required" {
		next := dialog()
		if next == nil {
			return errors.New("this build can't show a password dialog; run proxy-router in a terminal")
		}
		next.Stdin, next.Stdout, next.Stderr = cmd.Stdin, cmd.Stdout, output
		return next.Run()
	}
	if output != nil {
		_, _ = output.Write(stderr.Bytes())
	}
	return err
}

// sudoActions are the root halves of commands (as asRoot runs them) that
// the macOS sudoers rule lets the tray's user run without a password:
// connecting and disconnecting TUN mode. Switching modes and updating the
// service still ask.
var sudoActions = [][]string{{"start", "--tun"}, {"stop", "--system"}}

// sudoArgLists is what the rule allows after the TUN service's binary:
// asRoot's "--dir dir --uid uid", then one of sudoActions.
func sudoArgLists(dir, uid string) [][]string {
	var lists [][]string
	for _, a := range sudoActions {
		lists = append(lists, append([]string{"--dir", dir, "--uid", uid}, a...))
	}
	return lists
}

// sudoAction reports whether argv, as asRoot builds it (binary, --dir,
// --uid, then the action), runs one of sudoActions.
func sudoAction(argv []string) bool {
	if len(argv) < 5 || argv[1] != "--dir" || argv[3] != "--uid" {
		return false
	}
	return slices.ContainsFunc(sudoArgLists(argv[2], argv[4]), func(l []string) bool { return slices.Equal(l, argv[1:]) })
}
