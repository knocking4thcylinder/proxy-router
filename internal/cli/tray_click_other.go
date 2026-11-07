//go:build !linux

package cli

// watchTrayClicks is only needed on Linux, where the StatusNotifierItem
// protocol loses the click coordinates. macOS reads its status item natively.
func watchTrayClicks() {}
