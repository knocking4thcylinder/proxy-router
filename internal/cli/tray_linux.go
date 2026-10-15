package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

const trayUsesTemplate = false

// trayAvailable checks that something shows tray icons: a
// StatusNotifierWatcher on the session bus. There's none in SteamOS's
// Gaming Mode, over SSH, or on GNOME without the AppIndicator extension.
func trayAvailable() error {
	const hint = "no tray to show the icon in: needs a desktop with tray (StatusNotifierItem) support; GNOME needs the AppIndicator extension"
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return errors.New(hint)
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return fmt.Errorf("%s (%v)", hint, err)
	}
	var has bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.kde.StatusNotifierWatcher").Store(&has); err != nil || !has {
		return errors.New(hint)
	}
	return nil
}

// menuLabel escapes underscores, which DBus menus take as mnemonics.
func menuLabel(s string) string { return strings.ReplaceAll(s, "_", "__") }

// runElevated runs proxy-router with args as root with pkexec, which asks
// for the password in the desktop's polkit dialog.
func (t *tray) runElevated(args []string, out *bytes.Buffer) error {
	argv := append(append([]string{"env"}, t.elevationEnv()...), t.exe, "--dir", t.dir)
	return runOut(exec.Command("pkexec", append(argv, args...)...), out)
}

// allowSudo is only used on macOS.
func allowSudo(string) error { return errors.New("--allow-sudo is only used on macOS") }

// authCanceled reports whether the password dialog was dismissed.
func authCanceled(err error, _ string) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 126
}

func openPath(path string) {
	if err := exec.Command("xdg-open", path).Start(); err != nil {
		notify("Couldn't open "+path, err.Error())
	}
}

func notify(title, body string) {
	if err := exec.Command("notify-send", "-a", "proxy-router", title, body).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", title, body)
	}
}

func trayAutostartPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", "proxy-router-tray.desktop")
}

func trayAutostartEnabled() bool {
	_, err := os.Stat(trayAutostartPath())
	return err == nil
}

func setTrayAutostart(on bool, exe, dir string) error {
	path := trayAutostartPath()
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// Desktop entry Exec quoting: double quotes, with \ " ` $ escaped.
	q := func(s string) string {
		r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", `$`, `\\$`)
		return `"` + r.Replace(s) + `"`
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=proxy-router
Comment=Tray icon for proxy-router
Exec=%s --dir %s tray --foreground
Terminal=false
X-GNOME-Autostart-enabled=true
`, q(exe), q(dir))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return config.WriteFileAtomic(path, []byte(entry), 0o644)
}
