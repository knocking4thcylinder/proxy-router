package netif

import "os/exec"

// defaultRoutes parses `netstat -rn -f inet`; the kernel lists the active
// default route first.
func defaultRoutes() ([]Route, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil, err
	}
	return parseNetstat(string(out)), nil
}
