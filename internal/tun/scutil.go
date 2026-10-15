package tun

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// macOS DNS goes through the dynamic store (scutil). Up overrides the DNS
// servers of the primary network service with Setup:/Network/Service/<id>/DNS,
// which takes precedence over what DHCP puts in State:, and isn't written to
// disk: a reboot reverts it. What it replaced is saved under dnsBackupKey,
// also in the dynamic store, so even a later process (after a crash) can
// put it back.

const dnsBackupKey = "State:/Network/io.github.knocking4thcylinder.proxy-router/DNS"

var serviceID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func setupDNSKey(service string) string {
	return "Setup:/Network/Service/" + service + "/DNS"
}

// dnsBackup is what Up replaced.
type dnsBackup struct {
	Service string
	// HadKey is whether the service had a Setup DNS dictionary at all.
	HadKey bool
	// Servers are its ServerAddresses, if any.
	Servers []string
}

// parseScutil reads the top level of a dictionary printed by "scutil show":
// scalars become one-element slices, arrays keep their order. ok is false
// for "No such key".
func parseScutil(out string) (dict map[string][]string, ok bool) {
	if !strings.Contains(out, "<dictionary>") {
		return nil, false
	}
	dict = map[string][]string{}
	depth, key := 0, ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "}":
			depth--
			continue
		case strings.HasSuffix(line, "<dictionary> {") && depth == 0:
			depth = 1
			continue
		}
		k, v, found := strings.Cut(line, " : ")
		if !found {
			continue
		}
		if depth == 1 {
			key = k
			if strings.HasSuffix(v, "{") {
				depth++
				dict[key] = []string{}
			} else {
				dict[key] = []string{v}
			}
		} else if depth == 2 {
			if strings.HasSuffix(v, "{") {
				depth++
			} else {
				dict[key] = append(dict[key], v)
			}
		} else if strings.HasSuffix(v, "{") {
			depth++
		}
	}
	return dict, true
}

// cleanAddrs keeps the entries that are IP addresses, so nothing else can
// end up in a scutil script.
func cleanAddrs(in []string) []string {
	var out []string
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.String())
		}
	}
	return out
}

func parseBackup(out string) (dnsBackup, bool) {
	d, ok := parseScutil(out)
	if !ok || len(d["Service"]) != 1 || !serviceID.MatchString(d["Service"][0]) {
		return dnsBackup{}, false
	}
	return dnsBackup{
		Service: d["Service"][0],
		HadKey:  len(d["HadKey"]) == 1 && d["HadKey"][0] == "1",
		Servers: cleanAddrs(d["Servers"]),
	}, true
}

// backupScript saves b.
func backupScript(b dnsBackup) string {
	had := "0"
	if b.HadKey {
		had = "1"
	}
	s := fmt.Sprintf("d.init\nd.add Service %s\nd.add HadKey %s\n", b.Service, had)
	if servers := cleanAddrs(b.Servers); len(servers) > 0 {
		s += "d.add Servers * " + strings.Join(servers, " ") + "\n"
	}
	return s + "set " + dnsBackupKey + "\n"
}

// applyDNSScript points the service's DNS at DNSServer, keeping its other
// settings (search domains).
func applyDNSScript(service string) string {
	key := setupDNSKey(service)
	return fmt.Sprintf("d.init\nget %s\nd.add ServerAddresses * %s\nset %s\n", key, DNSServer, key)
}

// restoreDNSScript undoes applyDNSScript and drops the backup.
func restoreDNSScript(b dnsBackup) string {
	key := setupDNSKey(b.Service)
	var s string
	switch servers := cleanAddrs(b.Servers); {
	case !b.HadKey:
		s = "remove " + key + "\n"
	case len(servers) > 0:
		s = fmt.Sprintf("d.init\nget %s\nd.add ServerAddresses * %s\nset %s\n", key, strings.Join(servers, " "), key)
	default:
		s = fmt.Sprintf("d.init\nget %s\nd.remove ServerAddresses\nset %s\n", key, key)
	}
	return s + "remove " + dnsBackupKey + "\n"
}
