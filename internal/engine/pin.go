package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
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

// Lookup returns the addresses of host.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemLookup asks the system resolver: plain DNS, which the network can
// read and tamper with.
func SystemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// DoHLookup asks the DNS-over-HTTPS servers in turn, connecting from iface
// ("" = system routing) like the direct outbound, so the queries neither
// show server names to the network nor depend on the tunnel.
func DoHLookup(servers []string, iface string) Lookup {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, err := xnet.ParseDestination("tcp:" + addr)
		if err != nil {
			return nil, err
		}
		return internet.DialSystem(ctx, dest, &internet.SocketConfig{Interface: iface})
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext:         dial,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     30 * time.Second,
	}}
	return dohLookup(client, servers)
}

func dohLookup(client *http.Client, servers []string) Lookup {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		var errs []error
		for _, server := range servers {
			var addrs []netip.Addr
			var err error
			sctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
				var got []netip.Addr
				if got, err = dohQuery(sctx, client, server, host, qtype); err != nil {
					break
				}
				addrs = append(addrs, got...)
			}
			cancel()
			if err == nil && len(addrs) > 0 {
				return addrs, nil
			}
			if err == nil {
				err = fmt.Errorf("%s: no addresses", server)
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

// dohQuery is one RFC 8484 query.
func dohQuery(ctx context.Context, client *http.Client, server, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, err
	}
	q, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", server, resp.Status)
	}
	var m dnsmessage.Message
	if err := m.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s: %w", server, err)
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("%s: %s", server, m.RCode)
	}
	var out []netip.Addr
	for _, a := range m.Answers {
		switch r := a.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(r.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(r.AAAA))
		}
	}
	return out, nil
}

// OrElse tries lookup, then fallback.
func OrElse(lookup, fallback Lookup) Lookup {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		addrs, err := lookup(ctx, host)
		if err == nil {
			return addrs, nil
		}
		return fallback(ctx, host)
	}
}

// CachingResolver resolves with lookup, preferring the given family
// ("ipv4", "ipv6", or anything else for no preference), and caches answers
// for ttl.
func CachingResolver(prefer string, ttl time.Duration, lookup Lookup) Resolver {
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

		// Room for DoHLookup's 4s per server and then a fallback.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		addrs, err := lookup(ctx, host)
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
