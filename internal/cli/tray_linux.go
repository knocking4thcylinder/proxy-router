package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/safetext"
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

// menuLabel strips control and bidi characters from s, keeping its
// indent, and escapes underscores, which DBus menus take as mnemonics.
func menuLabel(s string) string {
	text := strings.TrimLeft(s, " ")
	return s[:len(s)-len(text)] + strings.ReplaceAll(safetext.Clean(text, 100), "_", "__")
}

// elevated runs argv as root with pkexec, which asks for the password in
// the desktop's polkit dialog. argv[0] runs directly, not through env, so
// the dialog names it, and a polkit action for it (packaging/linux) can
// apply.
func elevated(argv []string) *exec.Cmd {
	return exec.Command("pkexec", argv...)
}

// authCanceled reports whether the password dialog was dismissed.
func authCanceled(err error, _ string) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 126
}

// openText opens a file in the desktop's text editor (the text/plain
// handler), whatever its name says it is: xdg-open goes by the file's
// type, and a rules path set to, say, a .desktop file would launch it.
// Without an editor to use it opens the folder the file is in.
func openText(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() && textEditor(path) == nil {
		return
	}
	openFolder(filepath.Dir(path))
}

// textEditor starts the text/plain handler on path.
func textEditor(path string) error {
	out, err := exec.Command("xdg-mime", "query", "default", "text/plain").Output()
	app := strings.TrimSpace(string(out))
	if err != nil || app == "" || strings.ContainsAny(app, "/\n") {
		return errors.New("no text editor set")
	}
	if _, err := exec.LookPath("gtk-launch"); err == nil {
		return exec.Command("gtk-launch", app, path).Run()
	}
	for _, dir := range appDirs() {
		if file := filepath.Join(dir, app); statOK(file) {
			return exec.Command("gio", "launch", file, path).Run()
		}
	}
	return errors.New("can't start " + app)
}

// appDirs are where desktop entries live, most important first.
func appDirs() []string {
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		home, _ := os.UserHomeDir()
		data = filepath.Join(home, ".local", "share")
	}
	dirs := os.Getenv("XDG_DATA_DIRS")
	if dirs == "" {
		dirs = "/usr/local/share:/usr/share"
	}
	var out []string
	for _, d := range append([]string{data}, filepath.SplitList(dirs)...) {
		out = append(out, filepath.Join(d, "applications"))
	}
	return out
}

func statOK(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func openFolder(dir string) {
	if err := exec.Command("xdg-open", dir).Start(); err != nil {
		notify("Couldn't open "+dir, err.Error())
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
	qexe, err := desktopExecArg(exe)
	if err != nil {
		return err
	}
	qdir, err := desktopExecArg(dir)
	if err != nil {
		return err
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=proxy-router
Comment=Tray icon for proxy-router
Exec=%s --dir %s tray --foreground
Terminal=false
X-GNOME-Autostart-enabled=true
`, qexe, qdir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return config.WriteFileAtomic(path, []byte(entry), 0o644)
}

// desktopExecArg quotes one argument for a desktop entry's Exec key: in
// double quotes with \ " ` $ backslash-escaped, % doubled (it starts field
// codes like %f), and then every backslash doubled again because Exec is a
// string value with its own escapes. A control character can't be
// written: a newline would end the key and start another.
func desktopExecArg(s string) (string, error) {
	if !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%q can't go in a desktop entry: it contains control characters", s)
	}
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", `$`, `\\$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`, nil
}
