package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefinitionPath is the launchd plist.
func DefinitionPath(t Target) string {
	if t.Scope == System {
		return "/Library/LaunchDaemons/" + Label + ".plist"
	}
	return filepath.Join(t.User.HomeDir, "Library", "LaunchAgents", Label+".plist")
}

// BinaryPath is where the service's copy of proxy-router lives.
func BinaryPath(t Target) string {
	if t.Scope == System {
		return "/Library/Application Support/proxy-router/proxy-router"
	}
	return filepath.Join(t.User.HomeDir, "Library", "Application Support", "proxy-router", "proxy-router")
}

func domain(t Target) string {
	if t.Scope == System {
		return "system"
	}
	return "gui/" + t.User.Uid
}

// Definition is the plist Install writes for s.
func Definition(s Spec) []byte {
	esc := func(v string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	var args strings.Builder
	for _, a := range append([]string{s.Binary}, s.Args...) {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", esc(a))
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>5</integer>
</dict>
</plist>
`, esc(Label), args.String()))
}

// Install writes the plist, enables it at boot/login and (re)starts it.
func Install(s Spec) error {
	path := DefinitionPath(s.Target)
	if err := writeOwned(s.Target, path, Definition(s)); err != nil {
		return err
	}
	if err := Stop(s.Target); err != nil {
		return err
	}
	svc := domain(s.Target) + "/" + Label
	if _, err := run("launchctl", "enable", svc); err != nil {
		return err
	}
	// bootstrap right after bootout can fail with "Input/output error"
	// while launchd finishes tearing the old job down.
	var err error
	for range 10 {
		if _, err = run("launchctl", "bootstrap", domain(s.Target), path); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

// Stop stops the service and keeps it from starting at boot/login.
func Stop(t Target) error {
	svc := domain(t) + "/" + Label
	st, _ := Query(t)
	if _, err := run("launchctl", "print", svc); err == nil {
		if _, err := run("launchctl", "bootout", svc); err != nil {
			return err
		}
	}
	if exists(DefinitionPath(t)) {
		if _, err := run("launchctl", "disable", svc); err != nil {
			return err
		}
	}
	// The old process tears down its TUN routes on exit; a new one must
	// not start before that.
	waitExit(st.PID, 15*time.Second)
	return nil
}

// Remove stops the service and deletes its files.
func Remove(t Target) error {
	if err := Stop(t); err != nil {
		return err
	}
	if err := os.Remove(DefinitionPath(t)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if t.Scope == System {
		if err := os.Remove(SudoersPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_ = os.RemoveAll(filepath.Dir(BinaryPath(t)))
	return nil
}

// Query reports the service's state.
func Query(t Target) (Status, error) {
	st := Status{Installed: exists(DefinitionPath(t))}
	if !st.Installed {
		return st, nil
	}
	svc := domain(t) + "/" + Label
	if out, err := run("launchctl", "print", svc); err == nil {
		for _, line := range strings.Split(out, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
			if !ok {
				continue
			}
			switch k {
			case "state":
				st.Running = v == "running"
			case "pid":
				st.PID, _ = strconv.Atoi(v)
			}
		}
	}
	st.Enabled = true
	if out, err := run("launchctl", "print-disabled", domain(t)); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `"`+Label+`"`) &&
				(strings.HasSuffix(line, "disabled") || strings.HasSuffix(line, "true")) {
				st.Enabled = false
			}
		}
	}
	return st, nil
}
