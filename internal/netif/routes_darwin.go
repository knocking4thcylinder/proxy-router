package netif

// familyRoutes parses `netstat -rn -f family`; the kernel lists the active
// default route first.
func familyRoutes(family string) ([]Route, error) {
	out, err := Command("netstat", "-rn", "-f", family).Output()
	if err != nil {
		return nil, err
	}
	return parseNetstat(string(out)), nil
}
