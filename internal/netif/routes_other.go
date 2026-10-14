//go:build !darwin && !linux

package netif

// familyRoutes isn't implemented here; auto-detection is a no-op and
// bind_interface can be set explicitly instead.
func familyRoutes(family string) ([]Route, error) { return nil, nil }
