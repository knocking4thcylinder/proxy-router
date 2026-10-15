package safetext

import "testing"

func TestClean(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		max      int
	}{
		{"🇩🇪 Germany_1", "🇩🇪 Germany_1", 0},
		{"  padded\t", "padded", 0},
		{"line1\nline2\r\nline3", "line1 line2  line3", 0},
		{"\x1b[31mred\x1b[0m", "red", 0},
		{"\x1b[2J\x1b[Hclear", "clear", 0},
		{"\x1b]0;title\x07name", "name", 0},
		{"\x1b]8;;https://evil\x1b\\link\x1b]8;;\x1b\\", "link", 0},
		{"\x1bPdcs data\x1b\\after", "after", 0},
		{"\x1b(Bcharset", "charset", 0},
		{"\x1b", "", 0},
		{"a\x1b[", "a", 0},
		{"\u009b31mc1csi", "c1csi", 0},
		{"\u009d0;t\u009cosc", "osc", 0},
		{"bell\x07back\bspace\x00nul\x7fdel", "bellbackspacenuldel", 0},
		{"\u0085nel", "nel", 0},
		{"user‮gnp.exe", "usergnp.exe", 0},
		{"⁦iso⁩ ‏mark", "iso mark", 0},
		{"bad\xffutf8", "badutf8", 0},
		{"abcdef", "abc…", 4},
		{"日本語テキスト", "日本…", 3},
		{"abc", "abc", 3},
	} {
		if got := Clean(tc.in, tc.max); got != tc.want {
			t.Errorf("Clean(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
