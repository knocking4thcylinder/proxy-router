package cli

import (
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

func TestUpdateChannel(t *testing.T) {
	old := Channel
	t.Cleanup(func() { Channel = old })

	tests := []struct {
		build, configured, want string
	}{
		{update.StableChannel, "auto", update.StableChannel},
		{update.NightlyChannel, "auto", update.NightlyChannel},
		{update.StableChannel, "", update.StableChannel},
		{update.NightlyChannel, "", update.NightlyChannel},
		{update.StableChannel, update.NightlyChannel, update.NightlyChannel},
		{update.NightlyChannel, update.StableChannel, update.StableChannel},
	}
	for _, tt := range tests {
		Channel = tt.build
		if got := updateChannel(tt.configured); got != tt.want {
			t.Errorf("updateChannel(%q) with a %s build = %q, want %q", tt.configured, tt.build, got, tt.want)
		}
	}
}
