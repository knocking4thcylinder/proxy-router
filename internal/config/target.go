package config

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/knocking4thcylinder/proxy-router/internal/secpath"
)

// targetUID is --uid: the user a process running as root works for.
var targetUID string

// SetTargetUID sets the user a process running as root works for (--uid).
// "start" and the tray pass it when they elevate, and the TUN service's
// unit has it in ExecStart.
func SetTargetUID(uid string) { targetUID = uid }

// TargetUser returns the user whose files and services a process running
// as root works with, or nil when not running as root or working for root
// itself.
//
// That's --uid; when sudo or pkexec started this process, the uid they
// report (SUDO_UID, PKEXEC_UID) has to match it. Without --uid it's the
// uid they report: they set those variables themselves. Nothing else from
// the environment (SUDO_USER, $HOME, $XDG_CONFIG_HOME, $PROXY_ROUTER_HOME)
// is trusted as root.
func TargetUser() (*user.User, error) {
	if os.Geteuid() != 0 {
		if targetUID != "" && targetUID != strconv.Itoa(os.Getuid()) {
			return nil, errors.New("--uid only applies when running as root")
		}
		return nil, nil
	}
	uid, err := targetUIDFrom(targetUID, os.Getenv)
	if err != nil || uid == "" || uid == "0" {
		return nil, err
	}
	u, err := user.LookupId(uid)
	if err != nil {
		return nil, fmt.Errorf("uid %s: %w", uid, err)
	}
	return u, nil
}

// targetUIDFrom picks the target uid from --uid (flag) and the uids sudo
// and pkexec report, or "" for none.
func targetUIDFrom(flag string, getenv func(string) string) (string, error) {
	uid := flag
	for _, name := range []string{"PKEXEC_UID", "SUDO_UID"} {
		v := getenv(name)
		switch {
		case v == "":
		case uid == "":
			uid = v
		case v != uid:
			if flag != "" {
				return "", fmt.Errorf("--uid %s doesn't match %s=%s", flag, name, v)
			}
			return "", errors.New("PKEXEC_UID and SUDO_UID disagree; pass --uid")
		}
	}
	if uid == "" {
		return "", nil
	}
	n, err := strconv.ParseUint(uid, 10, 31)
	if err != nil {
		return "", fmt.Errorf("bad uid %q", uid)
	}
	return strconv.FormatUint(n, 10), nil
}

// rootUser is the user whose home a process running as root uses: the
// target user, else root.
func rootUser() (*user.User, error) {
	u, err := TargetUser()
	if u != nil || err != nil {
		return u, err
	}
	return user.Current()
}

// CheckDir makes sure a process running as root can trust the config
// directory: it and every directory above it can only be changed by root
// and the user it works for (TargetUser), so no other user can swap files
// in it. Returns dir with symlinks resolved, which is what root should use
// from then on. A directory that doesn't exist yet is checked from its
// nearest existing parent. For other users it returns dir unchanged.
func CheckDir(dir string) (string, error) {
	if os.Geteuid() != 0 {
		return dir, nil
	}
	uid := 0
	u, err := TargetUser()
	if err != nil {
		return "", err
	}
	if u != nil {
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return "", err
		}
	}
	var missing []string
	for p := dir; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			real, err := secpath.Check(p, uid)
			if err != nil {
				return "", fmt.Errorf("config directory: %w", err)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return real, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(p) == p {
			return "", fmt.Errorf("config directory %s: nothing above it exists", dir)
		}
		missing = append(missing, filepath.Base(p))
	}
}
