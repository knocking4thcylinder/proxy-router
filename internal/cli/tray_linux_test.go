package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// parseExec splits an Exec value the way the Desktop Entry spec says:
// string escapes first, then quoted arguments with \-escapes inside, and
// %% as a literal % (any other field code fails the test).
func parseExec(t *testing.T, v string) []string {
	t.Helper()
	// String-value escapes.
	var s strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			s.WriteByte(v[i])
			continue
		}
		i++
		switch v[i] {
		case 's':
			s.WriteByte(' ')
		case 'n':
			s.WriteByte('\n')
		case 't':
			s.WriteByte('\t')
		case 'r':
			s.WriteByte('\r')
		case '\\':
			s.WriteByte('\\')
		default:
			s.WriteByte('\\')
			s.WriteByte(v[i])
		}
	}
	line := s.String()
	var args []string
	for line = strings.TrimLeft(line, " "); line != ""; line = strings.TrimLeft(line, " ") {
		var b strings.Builder
		if line[0] != '"' {
			w, rest, _ := strings.Cut(line, " ")
			if strings.ContainsAny(w, `"\$`+"`") {
				t.Fatalf("reserved character outside quotes in %q", w)
			}
			args, line = append(args, w), rest
			continue
		}
		i := 1
		for ; i < len(line) && line[i] != '"'; i++ {
			c := line[i]
			switch {
			case c == '\\':
				i++
				if !strings.ContainsRune(`"`+"`"+`$\`, rune(line[i])) {
					t.Fatalf("bad escape \\%c in %q", line[i], line)
				}
				b.WriteByte(line[i])
			case c == '$' || c == '`':
				t.Fatalf("unescaped %c in %q", c, line)
			case c == '%':
				if i+1 >= len(line) || line[i+1] != '%' {
					t.Fatalf("field code in %q", line)
				}
				b.WriteByte('%')
				i++
			default:
				b.WriteByte(c)
			}
		}
		if i >= len(line) {
			t.Fatalf("unterminated quote in %q", line)
		}
		args, line = append(args, b.String()), line[i+1:]
	}
	return args
}

func TestDesktopExecArg(t *testing.T) {
	for _, a := range []string{
		"/usr/bin/proxy-router", "/home/a b/.config/proxy-router", `back\slash`, `dq"`, "sq'",
		"$HOME", "`id`", "100%", "%f", "%%u", "a;b|c&d", "~/x", "ünï",
	} {
		q, err := desktopExecArg(a)
		if err != nil {
			t.Fatalf("%q: %v", a, err)
		}
		got := parseExec(t, q+" --dir "+q)
		if len(got) != 3 || got[0] != a || got[2] != a {
			t.Errorf("%q quoted as %q reads back as %q", a, q, got)
		}
	}
	for _, bad := range []string{"a\nExec=evil", "a\rb", "a\x00", "a\tb", "a\x7f", "a\u0085", "\xff"} {
		if q, err := desktopExecArg(bad); err == nil {
			t.Errorf("accepted %q as %q", bad, q)
		}
	}
}

// TestTrayAutostartEntry writes the entry for awkward paths and, where
// desktop-file-validate is installed, has it checked.
func TestTrayAutostartEntry(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	exe, dir := "/opt/my apps/proxy-router", `/home/u/100% "cfg" $x`
	if err := setTrayAutostart(true, exe, dir); err != nil {
		t.Fatal(err)
	}
	path := trayAutostartPath()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var execLine string
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "Exec="); ok {
			execLine = v
		}
	}
	got := parseExec(t, execLine)
	if want := []string{exe, "--dir", dir, "tray", "--foreground"}; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("Exec reads back as %q", got)
	}
	if err := setTrayAutostart(true, exe, "/home/u\nX-Evil=1"); err == nil {
		t.Fatal("wrote an entry with a newline in the path")
	}
	if _, err := exec.LookPath("desktop-file-validate"); err == nil {
		if out, err := exec.Command("desktop-file-validate", path).CombinedOutput(); err != nil || strings.Contains(string(out), "error") {
			t.Fatalf("%v\n%s\n%s", err, out, data)
		}
	}
	if err := setTrayAutostart(false, exe, dir); err != nil || statOK(filepath.Join(cfg, "autostart", "proxy-router-tray.desktop")) {
		t.Fatalf("not removed: %v", err)
	}
}

// TestElevated: pkexec runs the binary itself (so a polkit action for it
// applies and the dialog names it), with no environment passed through.
func TestElevated(t *testing.T) {
	argv := []string{"/var/lib/proxy-router/proxy-router", "--dir", "/home/u/.config/proxy-router", "--uid", "1000", "stop", "--system"}
	got := elevated(argv).Args
	if want := append([]string{"pkexec"}, argv...); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("got %q", got)
	}
}

func TestMenuLabel(t *testing.T) {
	for in, want := range map[string]string{
		"de_1":                     "de__1",
		"    Server: g/\x1b[31mx‮": "    Server: g/x",
		"a\nb":                     "a b",
	} {
		if got := menuLabel(in); got != want {
			t.Errorf("menuLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
