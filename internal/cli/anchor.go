package cli

import (
	"strconv"
	"strings"
)

// panelWidth is the control window's fixed width, in Fyne units.
const panelWidth = 340

// panelAnchor locates the tray icon on screen. On macOS it is the top-left
// corner of the control window in the screen coordinates Fyne uses: from the
// top-left of the main display, y growing down. On Linux it is the global
// click point in physical pixels, because a StatusNotifierItem has no window
// frame to read; the panel works out where to open from that point.
type panelAnchor struct{ X, Y int }

func (a panelAnchor) String() string {
	return strconv.Itoa(a.X) + "," + strconv.Itoa(a.Y)
}

// parsePanelAnchor reads the "x,y" value of the panel command's --anchor flag.
func parsePanelAnchor(s string) (panelAnchor, bool) {
	x, y, ok := strings.Cut(s, ",")
	if !ok {
		return panelAnchor{}, false
	}
	xi, err := strconv.Atoi(x)
	if err != nil {
		return panelAnchor{}, false
	}
	yi, err := strconv.Atoi(y)
	if err != nil {
		return panelAnchor{}, false
	}
	return panelAnchor{xi, yi}, true
}

// parsePanelRequest splits a command from the tray ("toggle 812 24") into
// the command and the anchor it carries, when it has one.
func parsePanelRequest(s string) (cmd string, a panelAnchor, hasAnchor bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "", panelAnchor{}, false
	}
	cmd = f[0]
	if len(f) < 3 {
		return cmd, panelAnchor{}, false
	}
	x, errX := strconv.Atoi(f[1])
	y, errY := strconv.Atoi(f[2])
	if errX != nil || errY != nil {
		return cmd, panelAnchor{}, false
	}
	return cmd, panelAnchor{x, y}, true
}
