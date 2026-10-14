package tun

func FreeName() (string, error) { return "prtun0", nil }

func routes(ipv6 bool) [][]string {
	r := [][]string{{"-4", "0.0.0.0/1"}, {"-4", "128.0.0.0/1"}}
	if ipv6 {
		r = append(r, []string{"-6", "::/1"}, []string{"-6", "8000::/1"})
	}
	return r
}

// Up points the split default routes at the interface.
func Up(name string, ipv6 bool) error {
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	for _, r := range routes(ipv6) {
		if err := run("ip", r[0], "route", "replace", r[1], "dev", name); err != nil {
			Down(name, ipv6)
			return err
		}
	}
	return nil
}

// Down removes the routes.
func Down(name string, ipv6 bool) {
	for _, r := range routes(ipv6) {
		_ = run("ip", r[0], "route", "del", r[1])
	}
}

// Sync has nothing to do on Linux: SO_BINDTODEVICE works without extra
// routes.
func Sync(name string, ipv6 bool) error { return nil }
