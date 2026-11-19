// Package sysproxy points the OS proxy settings at the local inbounds.
package sysproxy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runSetup runs networksetup; tests replace it. CombinedOutput: on failure
// the parsers below ignore anything that isn't a "key : value" line, and
// the errors carry the tool's own explanation.
var runSetup = func(args ...string) (string, error) {
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	return string(out), err
}

// warn reports a problem that doesn't stop the system proxy; tests replace
// it.
var warn = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "system proxy: "+format+"\n", args...)
}

// kind is a networksetup proxy type: web (HTTP), secureweb (HTTPS),
// socksfirewall (SOCKS).
type saved struct {
	service, kind string
	enabled       bool
	server, port  string
}

// pacSaved is a service's auto-proxy (PAC) settings that Set turned off.
// While a PAC (or proxy auto-discovery) is enabled, macOS ignores the
// manual HTTP/HTTPS/SOCKS proxies entirely, so Set switches it off for as
// long as it runs and puts it back on stop.
type pacSaved struct {
	service   string
	enabled   bool
	url       string
	discovery bool
}

// Restore undoes Set.
type Restore func() error

// Set enables the HTTP/HTTPS/SOCKS proxies on every enabled network
// service, turning off any auto-proxy (PAC) that would shadow them. Empty
// addresses are skipped. The returned function restores the previous
// settings.
func Set(httpHost string, httpPort int, socksHost string, socksPort int) (Restore, error) {
	services, err := networkServices()
	if err != nil {
		return nil, err
	}
	var prev []saved
	var pac []pacSaved
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
		for _, p := range pac {
			if err := restorePAC(p); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("restoring system proxy: %s", strings.Join(errs, "; "))
		}
		return nil
	}
	// A PAC answers "which proxy?" for every app; the manual proxies never
	// take effect while one is on. Turn it off for the run, restoring it
	// with everything else.
	clearPAC := func(service string) {
		p, err := currentPAC(service)
		if err != nil {
			warn("can't check the auto-proxy (PAC) on %s: %v; the system proxy may not take effect", service, err)
			return
		}
		if !p.enabled && !p.discovery {
			return
		}
		pac = append(pac, p)
		warn("the auto-proxy (PAC) on %s shadows the system proxy; turning it off until proxy-router stops", service)
		if p.enabled {
			if err := networksetup("-setautoproxystate", service, "off"); err != nil {
				warn("can't turn the auto-proxy (PAC) off on %s: %v; the system proxy may not take effect", service, err)
			}
		}
		if p.discovery {
			if err := networksetup("-setproxyautodiscovery", service, "off"); err != nil {
				warn("can't turn auto proxy discovery off on %s: %v", service, err)
			}
		}
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
		clearPAC(svc)
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

// restorePAC puts back what clearPAC turned off.
func restorePAC(p pacSaved) error {
	var errs []string
	if p.enabled {
		if p.url != "" {
			// -setautoproxyurl also switches the PAC on, but say it
			// explicitly: some macOS versions only take the URL.
			if err := networksetup("-setautoproxyurl", p.service, p.url); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if err := networksetup("-setautoproxystate", p.service, "on"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if p.discovery {
		if err := networksetup("-setproxyautodiscovery", p.service, "on"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restoring the auto-proxy on %s: %s", p.service, strings.Join(errs, "; "))
	}
	return nil
}

func networkServices() ([]string, error) {
	out, err := runSetup("-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("networksetup: %w", err)
	}
	var services []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
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
	out, err := runSetup("-get"+kind+"proxy", service)
	if err != nil {
		return saved{}, fmt.Errorf("networksetup -get%sproxy %q: %w", kind, service, err)
	}
	return parseProxy(out, saved{service: service, kind: kind}), nil
}

// currentPAC reads a service's auto-proxy (PAC) settings. A PAC failure is
// the caller's to warn about; a discovery failure warns here, since a
// silently unknown discovery state is exactly the shadowing this exists to
// remove.
func currentPAC(service string) (pacSaved, error) {
	p := pacSaved{service: service}
	out, err := runSetup("-getautoproxyurl", service)
	if err != nil {
		return p, fmt.Errorf("networksetup -getautoproxyurl %q: %w", service, err)
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			p.enabled = v == "Yes"
		case "URL":
			p.url = v
		}
	}
	if out, err := runSetup("-getproxyautodiscovery", service); err == nil {
		p.discovery = discoveryOn(out)
	} else {
		warn("can't check proxy auto-discovery on %s: %v; the system proxy may not take effect", service, err)
	}
	return p, nil
}

// parseProxy reads `networksetup -get<kind>proxy` output into s.
func parseProxy(out string, s saved) saved {
	for _, line := range strings.Split(out, "\n") {
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
	return s
}

// discoveryOn reads `networksetup -getproxyautodiscovery` output, which
// prints "Auto Proxy Discovery: On" or "Auto Proxy Discovery: Off".
func discoveryOn(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == "Auto Proxy Discovery" {
			v = strings.TrimSpace(v)
			return v == "On" || v == "Enabled"
		}
	}
	return false
}

func networksetup(args ...string) error {
	out, err := runSetup(args...)
	if err != nil {
		return fmt.Errorf("networksetup %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}
