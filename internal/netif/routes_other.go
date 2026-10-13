//go:build !darwin && !linux

package netif

// defaultRoutes isn't implemented here; auto-detection is a no-op and
// bind_interface can be set explicitly instead.
func defaultRoutes() ([]Route, error) { return nil, nil }
