//go:build darwin && cgo

package cli

/*
#cgo LDFLAGS: -framework Cocoa

typedef struct {
	double x;
	double y;
	int ok;
} pr_anchor;

pr_anchor pr_status_item_anchor(double panel_width);
void pr_panel_prepare(void);
void pr_panel_style(double x, double y);
void pr_panel_place(double x, double y);
void pr_panel_activate(void);
*/
import "C"

// statusItemAnchor finds the app's status bar window and returns where the
// control window should open: centered under the icon, just below the menu
// bar. It is only meaningful in the tray process, which owns the item.
func statusItemAnchor() (panelAnchor, bool) {
	a := C.pr_status_item_anchor(C.double(panelWidth))
	if a.ok == 0 {
		return panelAnchor{}, false
	}
	return panelAnchor{X: int(a.x), Y: int(a.y)}, true
}

// preparePanelProcess turns the panel into an accessory app before its window
// exists: no Dock icon, no app menu, just the popover.
func preparePanelProcess() { C.pr_panel_prepare() }

// stylePanelWindow makes the panel's window a borderless floating popover.
// It must be called after the window is shown, on the main thread.
func stylePanelWindow(a panelAnchor) {
	C.pr_panel_style(C.double(a.X), C.double(a.Y))
}

// placePanelWindow puts the top-left corner of the window back at the anchor,
// keeping it there when the content grows downwards.
func placePanelWindow(a panelAnchor) {
	C.pr_panel_place(C.double(a.X), C.double(a.Y))
}

// activatePanelWindow brings the accessory app and its window to the front.
func activatePanelWindow() { C.pr_panel_activate() }
