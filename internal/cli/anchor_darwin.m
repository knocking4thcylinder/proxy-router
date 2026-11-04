#import <Cocoa/Cocoa.h>

typedef struct {
	double x;
	double y;
	int ok;
} pr_anchor;

// pr_status_window returns the menu bar item's window. NSStatusBarWindow is
// private, but it is an ordinary visible window in the app's window list.
// AppKit also keeps hidden placeholders parked below the screen origin, so
// take the highest one: that is the item actually shown in the menu bar.
static NSWindow *pr_status_window(void) {
	NSWindow *best = nil;
	for (NSWindow *w in [NSApp windows]) {
		NSRect f = [w frame];
		if (![w isVisible] || f.size.width < 1 || f.size.height < 1 || f.origin.y < 0)
			continue;
		if (![NSStringFromClass([w class]) containsString:@"StatusBarWindow"])
			continue;
		if (!best || f.origin.y > [best frame].origin.y)
			best = w;
	}
	return best;
}

// pr_panel_window returns the Fyne/GLFW window. The panel process has one.
static NSWindow *pr_panel_window(void) {
	NSWindow *fallback = nil;
	for (NSWindow *w in [NSApp windows]) {
		if (![w isVisible])
			continue;
		if ([NSStringFromClass([w class]) containsString:@"GLFW"])
			return w;
		if (!fallback)
			fallback = w;
	}
	return fallback;
}

// pr_place sets the window's top-left corner, converting from the top-left
// screen coordinates GLFW and Fyne use to AppKit's bottom-left ones.
static void pr_place(NSWindow *w, double x, double y) {
	NSScreen *primary = [[NSScreen screens] firstObject];
	if (!primary)
		return;
	CGFloat screenHeight = [primary frame].size.height;
	[w setFrameTopLeftPoint:NSMakePoint((CGFloat)x, screenHeight - (CGFloat)y)];
}

// pr_read_anchor reads the status item's position; must run on the main
// thread, where AppKit's window list and screens are safe to touch.
static pr_anchor pr_read_anchor(double panelWidth) {
	pr_anchor a = {0, 0, 0};
	[NSApplication sharedApplication];
	NSWindow *item = pr_status_window();
	if (!item)
		return a;

	NSRect f = [item frame];
	NSScreen *screen = [item screen];
	if (!screen)
		screen = [NSScreen mainScreen];
	NSScreen *primary = [[NSScreen screens] firstObject];
	if (!primary)
		primary = screen;
	if (!screen || !primary)
		return a;

	NSRect visible = [screen visibleFrame];
	CGFloat screenHeight = [primary frame].size.height;

	// Center under the icon, but keep the whole panel on that screen.
	CGFloat x = f.origin.x + f.size.width/2 - panelWidth/2;
	CGFloat minX = visible.origin.x + 6;
	CGFloat maxX = visible.origin.x + visible.size.width - panelWidth - 6;
	if (maxX < minX)
		maxX = minX;
	if (x < minX)
		x = minX;
	if (x > maxX)
		x = maxX;

	a.x = x;
	a.y = screenHeight - f.origin.y + 6; // the icon's bottom edge, plus a gap
	a.ok = 1;
	return a;
}

pr_anchor pr_status_item_anchor(double panelWidth) {
	// Clicking the status item runs on the main thread; menu items don't.
	// Hop over to the main queue in that case, so both paths get the anchor.
	if ([NSThread isMainThread]) {
		@autoreleasepool {
			return pr_read_anchor(panelWidth);
		}
	}
	__block pr_anchor a = {0, 0, 0};
	dispatch_sync(dispatch_get_main_queue(), ^{
		@autoreleasepool {
			a = pr_read_anchor(panelWidth);
		}
	});
	return a;
}

void pr_panel_prepare(void) {
	@autoreleasepool {
		if (![NSThread isMainThread])
			return;
		[NSApplication sharedApplication];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	}
}

void pr_panel_style(double x, double y) {
	@autoreleasepool {
		if (![NSThread isMainThread])
			return;
		[NSApplication sharedApplication];
		NSWindow *w = pr_panel_window();
		if (!w)
			return;

		[w setStyleMask:NSWindowStyleMaskBorderless];
		[w setLevel:NSFloatingWindowLevel];
		[w setCollectionBehavior:NSWindowCollectionBehaviorFullScreenNone];
		[w setHidesOnDeactivate:NO];
		[w setReleasedWhenClosed:NO];
		[w setMovable:NO];
		[w setMovableByWindowBackground:NO];
		[w setHasShadow:YES];
		[w setAnimationBehavior:NSWindowAnimationBehaviorNone];
		[w setBackgroundColor:[NSColor blackColor]];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
		pr_place(w, x, y);
	}
}

void pr_panel_place(double x, double y) {
	@autoreleasepool {
		if (![NSThread isMainThread])
			return;
		NSWindow *w = pr_panel_window();
		if (w)
			pr_place(w, x, y);
	}
}

void pr_panel_activate(void) {
	@autoreleasepool {
		if (![NSThread isMainThread])
			return;
		NSWindow *w = pr_panel_window();
		[NSApp activateIgnoringOtherApps:YES];
		if (w)
			[w makeKeyAndOrderFront:nil];
	}
}

