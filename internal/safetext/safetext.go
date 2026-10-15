// Package safetext makes untrusted text (server names, provider messages,
// error strings) safe to print to a terminal or put in a tray menu.
package safetext

import (
	"strings"
	"unicode/utf8"
)

// Clean returns s on a single line with terminal escape sequences, control
// characters and bidi overrides removed, trimmed and cut to at most max
// runes (no limit if max <= 0). Tabs and line breaks become spaces.
func Clean(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == 0x1b: // ESC
			i += escapeLen(s[i+1:]) + 1
			continue
		case r == 0x9b: // C1 CSI
			i += csiLen(s[i+size:]) + size
			continue
		case r == 0x90, r == 0x9d, r == 0x98, r == 0x9e, r == 0x9f: // C1 DCS, OSC, SOS, PM, APC
			i += stringLen(s[i+size:]) + size
			continue
		case r == '\t', r == '\n', r == '\r', r == '\v', r == '\f', r == 0x85, r == 0x2028, r == 0x2029:
			b.WriteByte(' ')
		case r == utf8.RuneError && size == 1, r < 0x20, r >= 0x7f && r < 0xa0, isBidiControl(r):
		default:
			b.WriteRune(r)
		}
		i += size
	}
	out := strings.TrimSpace(b.String())
	if max > 0 && utf8.RuneCountInString(out) > max {
		out = string([]rune(out)[:max-1]) + "…"
	}
	return out
}

// isBidiControl reports the embedding, override and isolate characters
// (and the marks), which can make text display in a different order than
// it's stored.
func isBidiControl(r rune) bool {
	return r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 ||
		r == 0x200e || r == 0x200f || r == 0x061c
}

// escapeLen is the length of the escape sequence after an ESC.
func escapeLen(s string) int {
	if s == "" {
		return 0
	}
	switch s[0] {
	case '[':
		return 1 + csiLen(s[1:])
	case ']', 'P', 'X', '^', '_':
		return 1 + stringLen(s[1:])
	}
	// nF sequences: intermediates, then one final byte.
	n := 0
	for n < len(s) && s[n] >= 0x20 && s[n] <= 0x2f {
		n++
	}
	if n < len(s) && s[n] >= 0x30 && s[n] <= 0x7e {
		n++
	}
	return n
}

// csiLen is the length of a CSI sequence's parameters, intermediates and
// final byte.
func csiLen(s string) int {
	for n := 0; n < len(s); n++ {
		if c := s[n]; c >= 0x40 && c <= 0x7e {
			return n + 1
		} else if c < 0x20 || c > 0x3f {
			return n // malformed; drop just the introducer
		}
	}
	return len(s)
}

// stringLen is the length of an OSC/DCS-style string up to and including
// its terminator (BEL, ESC \ or C1 ST). Unterminated strings run to the end.
func stringLen(s string) int {
	for n := 0; n < len(s); n++ {
		switch {
		case s[n] == 0x07:
			return n + 1
		case s[n] == 0x1b && n+1 < len(s) && s[n+1] == '\\':
			return n + 2
		case strings.HasPrefix(s[n:], "\u009c"):
			return n + len("\u009c")
		}
	}
	return len(s)
}
