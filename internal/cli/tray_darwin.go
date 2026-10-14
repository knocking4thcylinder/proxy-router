//go:build cgo

package cli

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

const trayUsesTemplate = true

func trayAvailable() error { return nil }

func menuLabel(s string) string { return s }

// elevated runs argv as root through AppleScript, which asks for the
// password in the standard macOS dialog.
func elevated(argv []string) *exec.Cmd {
	var words []string
	for _, a := range argv {
		words = append(words, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	script := fmt.Sprintf("do shell script %s with administrator privileges", appleString(strings.Join(words, " ")))
	return exec.Command("osascript", "-e", script)
}

func appleString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// authCanceled reports whether the password dialog was dismissed.
func authCanceled(_ error, out string) bool { return strings.Contains(out, "(-128)") }

// openText opens a file in the default text editor, whatever its name
// says it is: plain "open" would run a .command file or launch an .app
// bundle the rules path pointed at. Anything that isn't a regular file is
// only revealed in Finder.
func openText(path string) {
	args := []string{"-R", path}
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		args = []string{"-t", path}
	}
	if err := exec.Command("open", args...).Start(); err != nil {
		notify("Couldn't open "+path, err.Error())
	}
}

func openFolder(dir string) {
	if err := exec.Command("open", dir).Start(); err != nil {
		notify("Couldn't open "+dir, err.Error())
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
