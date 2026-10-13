// Package sysproxy points the OS proxy settings at the local inbounds.
package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

// kind is a networksetup proxy type: web (HTTP), secureweb (HTTPS),
// socksfirewall (SOCKS).
type saved struct {
	service, kind string
	enabled       bool
	server, port  string
}

// Restore undoes Set.
type Restore func() error

// Set enables the HTTP/HTTPS/SOCKS proxies on every enabled network service.
// Empty addresses are skipped. The returned function restores the
// previous settings.
func Set(httpHost string, httpPort int, socksHost string, socksPort int) (Restore, error) {
	services, err := networkServices()
	if err != nil {
		return nil, err
	}
	var prev []saved
	restore := func() error {
		var errs []string
		for _, s := range prev {
			if s.server != "" && s.port != "" && s.port != "0" {
				if err := networksetup("-set"+s.kind+"proxy", s.service, s.server, s.port); err != nil {
					errs = append(errs, err.Error())
				}
			}
			state := "off"
			if s.enabled {
				state = "on"
			}
			if err := networksetup("-set"+s.kind+"proxystate", s.service, state); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("restoring system proxy: %s", strings.Join(errs, "; "))
		}
		return nil
	}
	apply := func(service, kind, host string, port int) error {
		s, err := current(service, kind)
		if err != nil {
			return err
		}
		prev = append(prev, s)
		return networksetup("-set"+kind+"proxy", service, host, fmt.Sprint(port))
	}
	for _, svc := range services {
		if httpHost != "" {
			if err := apply(svc, "web", httpHost, httpPort); err != nil {
				return nil, undo(err, restore)
			}
			if err := apply(svc, "secureweb", httpHost, httpPort); err != nil {
				return nil, undo(err, restore)
			}
		}
		if socksHost != "" {
			if err := apply(svc, "socksfirewall", socksHost, socksPort); err != nil {
				return nil, undo(err, restore)
			}
		}
	}
	return restore, nil
}

func undo(err error, restore Restore) error {
	if rerr := restore(); rerr != nil {
		return fmt.Errorf("%w (and %v)", err, rerr)
	}
	return err
}

func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("networksetup: %w", err)
	}
	var services []string
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// First line is a legend; "*" marks disabled services.
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("no enabled network services found")
	}
	return services, nil
}

func current(service, kind string) (saved, error) {
	out, err := exec.Command("networksetup", "-get"+kind+"proxy", service).Output()
	if err != nil {
		return saved{}, fmt.Errorf("networksetup -get%sproxy %q: %w", kind, service, err)
	}
	s := saved{service: service, kind: kind}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			s.enabled = v == "Yes"
		case "Server":
			s.server = v
		case "Port":
			s.port = v
		}
	}
	return s, nil
}

func networksetup(args ...string) error {
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
