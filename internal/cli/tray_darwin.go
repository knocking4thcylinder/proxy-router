//go:build cgo

package cli

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

const trayUsesTemplate = true

func trayAvailable() error { return nil }

func menuLabel(s string) string { return s }

// sudoActions are the actions the sudoers rule lets the tray run without a
// password: connecting and disconnecting TUN mode.
var sudoActions = [][]string{{"start", "--tun"}, {"stop"}}

const passwordPrompt = "proxy-router needs your password for TUN mode. " +
	"Connecting and disconnecting from the menu bar won't ask again."

// runElevated runs proxy-router with args as root. sudoActions go through
// sudo without a password once the sudoers rule allows them; otherwise the
// standard macOS dialog asks for the password, and also writes the rule.
func (t *tray) runElevated(args []string, out *bytes.Buffer) error {
	if cmd := t.sudo(args); cmd != nil {
		err := runOut(cmd, out)
		// sudo's own refusals (the rule is for another user or folder, or
		// the service's binary is gone) start with "sudo: ", and the command
		// didn't run.
		if err == nil || !strings.HasPrefix(out.String(), "sudo: ") {
			return err
		}
		out.Reset()
	}
	self := []string{t.exe, "--dir", t.dir}
	// The action runs even if writing the rule fails; the dialog just comes
	// back next time.
	script := fmt.Sprintf("export %s; %s tray --allow-sudo; %s",
		strings.Join(t.elevationEnv(), " "), shellWords(self), shellWords(append(self, args...)))
	return runOut(exec.Command("osascript", "-e", fmt.Sprintf("do shell script %s with prompt %s with administrator privileges",
		appleString(script), appleString(passwordPrompt))), out)
}

// sudo returns a sudo command that runs args, or nil if the sudoers rule
// can't allow them. The rule is for the system service's root-owned copy of
// proxy-router, so when this build differs from the service's, connecting
// goes through the dialog, which installs this build.
func (t *tray) sudo(args []string) *exec.Cmd {
	if !slices.ContainsFunc(sudoActions, func(a []string) bool { return slices.Equal(a, args) }) {
		return nil
	}
	if _, err := os.Stat(service.SudoersPath); err != nil {
		return nil
	}
	if args[0] == "start" && service.Outdated(t.sysT) {
		return nil
	}
	return exec.Command("sudo", append([]string{"-n", service.BinaryPath(t.sysT), "--dir", t.dir}, args...)...)
}

// allowSudo writes the sudoers rule for sudoActions. It runs as root, from
// the password dialog.
func allowSudo(dir string) error {
	userT, _, err := targets()
	if err != nil {
		return err
	}
	var argLists [][]string
	for _, a := range sudoActions {
		argLists = append(argLists, append([]string{"--dir", dir}, a...))
	}
	return service.AllowSudo(userT.User, argLists)
}

func shellWords(argv []string) string {
	words := make([]string, len(argv))
	for i, a := range argv {
		words[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(words, " ")
}

func appleString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// authCanceled reports whether the password dialog was dismissed.
func authCanceled(_ error, out string) bool { return strings.Contains(out, "(-128)") }

func openPath(path string) {
	args := []string{path}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() && filepath.Ext(path) != ".log" {
		args = []string{"-t", path} // .yaml has no default app
	}
	if err := exec.Command("open", args...).Start(); err != nil {
		notify("Couldn't open "+path, err.Error())
	}
}

func notify(title, body string) {
	script := fmt.Sprintf("display notification %s with title %s", appleString(body), appleString(title))
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", title, body)
	}
}

const trayLabel = service.Label + ".tray"

func trayAutostartPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", trayLabel+".plist")
}

func trayAutostartEnabled() bool {
	_, err := os.Stat(trayAutostartPath())
	return err == nil
}

// setTrayAutostart writes or removes a LaunchAgent; launchd loads it at the
// next login (loading it now would start a second tray).
func setTrayAutostart(on bool, exe, dir string) error {
	path := trayAutostartPath()
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	esc := func(v string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>--dir</string>
		<string>%s</string>
		<string>tray</string>
		<string>--foreground</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`, esc(trayLabel), esc(exe), esc(dir))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return config.WriteFileAtomic(path, []byte(plist), 0o644)
}
