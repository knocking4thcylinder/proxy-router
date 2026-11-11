package cli

import (
	"os/exec"
	"strings"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

// binaryVersion asks another copy of proxy-router (the service's, after a
// background update) what release it is. It only reports release versions;
// a dev build has no version to compare.
func binaryVersion(path string) (string, bool) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(out))
	for i := len(fields) - 1; i >= 0; i-- {
		if update.IsRelease(fields[i]) {
			return fields[i], true
		}
	}
	return "", false
}

// newerBinary reports whether the proxy-router at path is a newer release
// than this process. Replacing it with this build would be a downgrade.
func newerBinary(path string) bool {
	v, ok := binaryVersion(path)
	return ok && update.Compare(v, version()) > 0
}

// newerService is newerBinary for a service's own copy.
func newerService(t service.Target) bool {
	return newerBinary(service.BinaryPath(t))
}
