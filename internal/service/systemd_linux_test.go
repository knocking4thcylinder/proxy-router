package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// unquote splits an ExecStart value the way systemd does, for the subset
// quote produces: bare words, and double-quoted words with \-escapes
// (\\ \" \xNN \uNNNN), $$ and %%.
func unquote(t *testing.T, line string) []string {
	t.Helper()
	var words []string
	for line = strings.TrimLeft(line, " "); line != ""; line = strings.TrimLeft(line, " ") {
		if line[0] != '"' {
			w, rest, _ := strings.Cut(line, " ")
			words, line = append(words, w), rest
			continue
		}
		var b strings.Builder
		i := 1
		for ; i < len(line) && line[i] != '"'; i++ {
			switch c := line[i]; c {
			case '\\':
				i++
				switch line[i] {
				case 'x':
					n, err := strconv.ParseUint(line[i+1:i+3], 16, 8)
					if err != nil {
						t.Fatalf("bad \\x in %q", line)
					}
					b.WriteByte(byte(n))
					i += 2
				case 'u':
					n, err := strconv.ParseUint(line[i+1:i+5], 16, 16)
					if err != nil {
						t.Fatalf("bad \\u in %q", line)
					}
					b.WriteRune(rune(n))
					i += 4
				default:
					b.WriteByte(line[i])
				}
			case '$', '%':
				if i+1 >= len(line) || line[i+1] != c {
					t.Fatalf("unescaped %c in %q", c, line)
				}
				b.WriteByte(c)
				i++
			default:
				b.WriteByte(c)
			}
		}
		if i >= len(line) {
			t.Fatalf("unterminated quote in %q", line)
		}
		words, line = append(words, b.String()), line[i+1:]
	}
	return words
}

func TestQuoteRoundTrip(t *testing.T) {
	args := []string{
		"plain", "", "with space", "tab\there", `back\slash`, `dq"`, "sq'", "$HOME", "${X}",
		"100%", "%h", "semi;colon", "new\nline", "cr\r", "nul\x00", "esc\x1b", "del\x7f",
		"c1\u0085", "ünïcødé", "/home/a b/.config/proxy-router",
	}
	for _, a := range args {
		q := quote(a)
		if strings.IndexFunc(q, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }) >= 0 {
			t.Errorf("quote(%q) = %q has a raw control character", a, q)
		}
		if !utf8.ValidString(q) {
			t.Errorf("quote(%q) = %q isn't UTF-8", a, q)
		}
		got := unquote(t, "x "+q+" y")
		if len(got) != 3 || got[1] != a {
			t.Errorf("quote(%q) = %q reads back as %q", a, q, got)
		}
	}
}

// TestDefinitionOneLine: whatever the arguments, ExecStart stays one line
// and no other line of the unit changes.
func TestDefinitionOneLine(t *testing.T) {
	u := &user.User{Uid: "1000", Gid: "1000", Username: "u", HomeDir: "/home/u"}
	base := Definition(Spec{Target: Target{Scope: System, User: u}, Binary: "/b", Args: []string{"x"}})
	evil := "/home/u\n[Service]\nExecStartPre=/bin/sh -c 'id'\r\n"
	def := Definition(Spec{Target: Target{Scope: System, User: u}, Binary: "/b", Args: []string{evil}})
	bl, dl := strings.Split(string(base), "\n"), strings.Split(string(def), "\n")
	if len(bl) != len(dl) {
		t.Fatalf("line count changed:\n%s", def)
	}
	for i := range bl {
		if strings.HasPrefix(bl[i], "ExecStart=") {
			if got := unquote(t, strings.TrimPrefix(dl[i], "ExecStart=")); fmt.Sprint(got) != fmt.Sprint([]string{"/b", evil}) {
				t.Fatalf("ExecStart reads back as %q", got)
			}
			continue
		}
		if bl[i] != dl[i] {
			t.Fatalf("line %d changed: %q", i+1, dl[i])
		}
	}
}

func TestRemoveUnitFilesRetriesSudoersCleanup(t *testing.T) {
	dir := t.TempDir()
	definition, sudoers := filepath.Join(dir, "proxy-router.service"), filepath.Join(dir, "proxy-router")
	if err := os.WriteFile(definition, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory makes removal fail even when running as root.
	if err := os.Mkdir(sudoers, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoers, "blocking"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeUnitFiles(System, definition, sudoers); err == nil {
		t.Fatal("expected the sudoers removal to fail")
	}
	if _, err := os.Stat(definition); err != nil {
		t.Fatalf("unit definition must remain for a retry: %v", err)
	}
	if err := os.RemoveAll(sudoers); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sudoers, nil, 0o440); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := removeUnitFiles(System, definition, sudoers); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{definition, sudoers} {
		if _, err := os.Stat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s must be absent after removal: %v", name, err)
		}
	}
}
