package service

import (
	"errors"
	"fmt"
	"os"
	"os/user"

	"golang.org/x/sys/unix"
)

// AllowSudo provisions the rule after a successful system service start.
// Only grant access to the installed build if it matches the build that
// is running this code and can therefore also remove the rule.
func AllowSudo(u *user.User, argLists [][]string) error {
	lock, err := lockSystemService()
	if err != nil {
		return err
	}
	defer lock.Close()
	t := Target{Scope: System}
	installed, err := RootBinary()
	if err != nil {
		return fmt.Errorf("check the installed TUN service binary: %w", err)
	}
	// /proc/self/exe is this running image even if its original path was
	// replaced while the service was being installed.
	if err := verifySudoersTarget(BinaryPath(t), DefinitionPath(t), installed, "/proc/self/exe"); err != nil {
		return err
	}
	return writeSudoers(u, argLists)
}

func verifySudoersTarget(binary, definition, installed, running string) error {
	if _, err := os.Stat(definition); err != nil {
		return fmt.Errorf("check the installed TUN service definition: %w", err)
	}
	if installed != binary {
		return fmt.Errorf("the TUN service binary path %q resolves to %q", binary, installed)
	}
	same, err := sameContents(installed, running)
	if err != nil {
		return fmt.Errorf("check the installed TUN service build: %w", err)
	}
	if !same {
		return errors.New("the installed TUN service binary differs from the running build")
	}
	return nil
}

// lockSystemService serializes publishing the rule with removing the unit
// and binary. The lock file lives outside the files removed on uninstall.
func lockSystemService() (*os.File, error) {
	f, err := os.OpenFile("/run/proxy-router.service.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		for {
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err == nil {
			return f, nil
		}
		f.Close()
	}
	return nil, fmt.Errorf("lock the TUN service: %w", err)
}

func updateSystemBinary(source string) error {
	lock, err := lockSystemService()
	if err != nil {
		return err
	}
	defer lock.Close()
	return replaceSystemBinary(source)
}
