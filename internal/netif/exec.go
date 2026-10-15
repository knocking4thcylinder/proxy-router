package netif

import (
	"os"
	"os/exec"
	"path/filepath"
)

// systemDirs is where the network tools live. proxy-router runs them as
// root, so they're never looked up in $PATH, which the invoking user (or a
// sudo configuration) controls.
var systemDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Tool returns the absolute path of a system tool such as ip, nft, route
// or scutil, or "" if it isn't installed.
func Tool(name string) string {
	for _, dir := range systemDirs {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// Command is exec.Command for a system tool, by absolute path.
func Command(name string, args ...string) *exec.Cmd {
	p := Tool(name)
	if p == "" {
		// Fails with "no such file" when run, naming the tool.
		p = filepath.Join(systemDirs[0], name)
	}
	return exec.Command(p, args...)
}
