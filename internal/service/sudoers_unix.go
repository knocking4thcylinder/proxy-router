//go:build darwin || linux

package service

import (
	"os"
	"os/user"
	"path/filepath"
)

// SudoersPath holds the rule AllowSudo writes; Remove deletes it with the
// system service. sudo skips files in sudoers.d whose names contain a ".",
// like the temporary one.
const SudoersPath = "/etc/sudoers.d/proxy-router"

// writeSudoers allows the given arguments for the system service's binary.
func writeSudoers(u *user.User, argLists [][]string) error {
	rule, err := sudoersRule(u.Username, BinaryPath(Target{Scope: System}), argLists)
	if err != nil {
		return err
	}
	dir := filepath.Dir(SudoersPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proxy-router.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(rule)
	if err == nil {
		err = tmp.Chmod(0o440)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	// A broken file in sudoers.d breaks sudo altogether.
	if _, err := run("visudo", "-c", "-q", "-f", tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), SudoersPath)
}
