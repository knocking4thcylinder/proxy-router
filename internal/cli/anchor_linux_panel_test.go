//go:build panel && linux

package cli

import "testing"

func TestPanelPositionFollowsTrayPanelEdge(t *testing.T) {
	const (
		pw, ph = 340, 400
		mw, mh = 1920, 1080
	)
	tests := []struct {
		name string
		a    panelAnchor
		x, y int
	}{
		{"bottom bar opens above and clamps right", panelAnchor{1850, 1070}, 1574, 646},
		{"top bar opens below", panelAnchor{960, 10}, 790, 34},
		{"left bar opens right", panelAnchor{10, 500}, 34, 300},
		{"right bar opens left", panelAnchor{1910, 500}, 1546, 300},
		{"elsewhere opens above", panelAnchor{960, 540}, 790, 116},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y := panelPosition(tt.a, pw, ph, 0, 0, mw, mh)
			if x != tt.x || y != tt.y {
				t.Fatalf("panelPosition(%v) = %d,%d, want %d,%d", tt.a, x, y, tt.x, tt.y)
			}
		})
	}
}

func TestPanelPositionClampsToMonitor(t *testing.T) {
	// A panel wider and taller than the monitor still starts at the margin.
	x, y := panelPosition(panelAnchor{150, 150}, 340, 400, 0, 0, 300, 300)
	if x != margin || y != margin {
		t.Fatalf("small monitor: got %d,%d, want %d,%d", x, y, margin, margin)
	}
}

func TestPanelPositionUsesClickMonitorOrigin(t *testing.T) {
	// The second monitor starts at x=1920; the panel follows it there.
	x, y := panelPosition(panelAnchor{2800, 1070}, 340, 400, 1920, 0, 1920, 1080)
	if x != 2630 || y != 646 {
		t.Fatalf("second monitor: got %d,%d, want 2630,646", x, y)
	}
}
