//go:build linux

package cli

import "testing"

func TestTrayClickDestination(t *testing.T) {
	const (
		name  = "org.kde.StatusNotifierItem-123-1"
		owner = ":1.42"
	)
	tests := []struct {
		name        string
		dest, owner string
		want        bool
	}{
		{"well-known name", "org.kde.StatusNotifierItem-123-1", "", true},
		{"unique owner", ":1.42", owner, true},
		{"other item", "org.kde.StatusNotifierItem-456-1", owner, false},
		{"other connection", ":1.99", owner, false},
		{"owner not resolved yet", ":1.42", "", false},
		{"no destination", "", owner, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trayClickDestination(tt.dest, name, tt.owner); got != tt.want {
				t.Errorf("trayClickDestination(%q, %q, %q) = %v, want %v", tt.dest, name, tt.owner, got, tt.want)
			}
		})
	}
}
