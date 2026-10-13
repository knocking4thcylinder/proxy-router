//go:build !darwin

package sysproxy

import (
	"fmt"
	"runtime"
)

type Restore func() error

func Set(httpHost string, httpPort int, socksHost string, socksPort int) (Restore, error) {
	return nil, fmt.Errorf("--system-proxy is not supported on %s yet; point your apps at the listen addresses instead", runtime.GOOS)
}
