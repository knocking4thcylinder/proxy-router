package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Resolver turns a server hostname into an IP.
type Resolver func(host string) (string, error)

// PinAddresses replaces server hostnames in outbounds with IPs from resolve,
// keeping the hostname wherever it was implicitly used (TLS/REALITY SNI,
// WebSocket/HTTPUpgrade/XHTTP Host, gRPC authority) so nothing changes on
// the wire.
//
// This matters whenever proxy-router's own lookups can't be trusted to work:
// in TUN mode the system resolver is often routed into the TUN itself, which
// needs the server's address to carry anything, so nothing would ever
// connect.
func PinAddresses(obs []map[string]any, resolve Resolver) []string {
	var notes []string
	for _, ob := range obs {
		settings, _ := ob["settings"].(map[string]any)
		if settings == nil {
			continue
		}
		pin := func(host string) (string, bool) {
			if host == "" || isIPOrCIDR(host) {
				return host, false
			}
			ip, err := resolve(host)
			if err != nil {
				notes = append(notes, fmt.Sprintf("can't resolve %s now (%v); Xray will try itself", host, err))
				return host, false
			}
			keepHostname(ob, host)
			return ip, true
		}
		if a, ok := settings["address"].(string); ok {
			if ip, changed := pin(a); changed {
				settings["address"] = ip
			}
		}
		for _, key := range []string{"vnext", "servers"} {
			list, _ := settings[key].([]any)
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if a, ok := m["address"].(string); ok {
					if ip, changed := pin(a); changed {
						m["address"] = ip
					}
				}
			}
		}
		// WireGuard: "host:port" endpoints.
		peers, _ := settings["peers"].([]any)
		for _, item := range peers {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			ep, _ := m["endpoint"].(string)
			host, port, err := net.SplitHostPort(ep)
			if err != nil {
				continue
			}
			if ip, changed := pin(host); changed {
				m["endpoint"] = net.JoinHostPort(ip, port)
			}
		}
	}
	return notes
}

// keepHostname fills in the fields Xray would otherwise derive from the
// address, before the address becomes an IP.
func keepHostname(ob map[string]any, host string) {
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		return
	}
	setIfEmpty := func(parent, key string) {
		m, ok := ss[parent].(map[string]any)
		if !ok {
			if parent != "tlsSettings" && parent != "realitySettings" {
				return
			}
			m = map[string]any{}
			ss[parent] = m
		}
		if v, _ := m[key].(string); v == "" {
			m[key] = host
		}
	}
	switch ss["security"] {
	case "tls":
		setIfEmpty("tlsSettings", "serverName")
	case "reality":
		setIfEmpty("realitySettings", "serverName")
	}
	switch ss["network"] {
	case "ws":
		setIfEmpty("wsSettings", "host")
	case "httpupgrade":
		setIfEmpty("httpupgradeSettings", "host")
	case "xhttp", "splithttp":
		setIfEmpty("xhttpSettings", "host")
		setIfEmpty("splithttpSettings", "host")
	case "grpc":
		setIfEmpty("grpcSettings", "authority")
	}
}

// CachingResolver resolves with the system resolver, preferring the given
// family ("ipv4", "ipv6", or anything else for no preference), and caches
// answers for ttl.
func CachingResolver(prefer string, ttl time.Duration) Resolver {
	type entry struct {
		ip  string
		exp time.Time
	}
	var (
		mu    sync.Mutex
		cache = map[string]entry{}
	)
	return func(host string) (string, error) {
		mu.Lock()
		if e, ok := cache[host]; ok && time.Now().Before(e.exp) {
			mu.Unlock()
			return e.ip, nil
		}
		mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return "", err
		}
		ip := pickFamily(addrs, prefer)
		if ip == "" {
			return "", fmt.Errorf("no addresses")
		}
		mu.Lock()
		cache[host] = entry{ip, time.Now().Add(ttl)}
		mu.Unlock()
		return ip, nil
	}
}

func pickFamily(addrs []netip.Addr, prefer string) string {
	for _, want4 := range []bool{prefer != "ipv6", prefer == "ipv6"} {
		for _, a := range addrs {
			if a.Unmap().Is4() == want4 {
				return a.Unmap().String()
			}
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Unmap().String()
	}
	return ""
}
