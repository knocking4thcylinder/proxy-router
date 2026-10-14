package cli

import "testing"

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
