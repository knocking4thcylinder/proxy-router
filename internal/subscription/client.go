package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// maxRedirects is how many redirects Fetch follows.
	maxRedirects = 5
	// maxBody caps the subscription size, after decompression.
	maxBody = 32 << 20
)

// ErrInsecureURL is returned for http:// URLs without Request.AllowHTTP.
var ErrInsecureURL = errors.New("plain http subscription URLs let anyone on the network change the server list")

// deviceHeaders identify the device; with custom headers they go only to
// the host the user gave.
var deviceHeaders = []string{"x-hwid", "x-device-os", "x-device-model", "Authorization", "Cookie"}

// policy decides where Fetch may connect. Tests swap in their own.
type policy struct {
	// nonPublic reports addresses that only a local subscription URL may
	// lead to.
	nonPublic func(netip.AddrPort) bool
	rootCAs   *x509.CertPool
}

var defaultPolicy = policy{nonPublic: func(ap netip.AddrPort) bool { return isNonPublic(ap.Addr()) }}

var (
	cgnat   = netip.MustParsePrefix("100.64.0.0/10")
	thisNet = netip.MustParsePrefix("0.0.0.0/8")
)

// isNonPublic reports loopback, private, link-local and similar addresses
// that a provider shouldn't be able to point the fetch at.
func isNonPublic(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() ||
		cgnat.Contains(a) || thisNet.Contains(a)
}

// local reports whether u itself points at a non-public address (a LAN or
// loopback panel), in which case redirects may stay there too.
func (p policy) local(ctx context.Context, u *url.URL) bool {
	port := uint16(443)
	if u.Scheme == "http" {
		port = 80
	}
	if n, err := strconv.ParseUint(u.Port(), 10, 16); err == nil {
		port = uint16(n)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		return p.nonPublic(netip.AddrPortFrom(a, port))
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !p.nonPublic(netip.AddrPortFrom(a, port)) {
			return false
		}
	}
	return true
}

// client builds the HTTP client for one fetch of origin. Unless the
// subscription is local, every connection is checked after DNS resolution
// so a redirect or a rebinding DNS answer can't reach the LAN or loopback.
func (p policy) client(origin *url.URL, local, allowHTTP bool, custom map[string]string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	guarded := *dialer
	if !local {
		guarded.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || p.nonPublic(ap) {
				return fmt.Errorf("refusing to connect to non-public address %s", address)
			}
			return nil
		}
	}
	// A proxy the user set in the environment is trusted to go anywhere.
	var proxies sync.Map
	transport := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			u, err := http.ProxyFromEnvironment(r)
			if u != nil {
				proxies.Store(proxyAddr(u), true)
			}
			return u, err
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, ok := proxies.Load(addr); ok {
				return dialer.DialContext(ctx, network, addr)
			}
			return guarded.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{RootCAs: p.rootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			prev := via[len(via)-1]
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// http only when the user opted in and nothing before was https.
			if r.URL.Scheme != "https" && !(r.URL.Scheme == "http" && allowHTTP && prev.URL.Scheme == "http") {
				return fmt.Errorf("refusing redirect from %s to %s", Redact(prev.URL.String()), Redact(r.URL.String()))
			}
			// Go re-sends custom headers to any host; keep the device ID and
			// the user's headers for the host they were meant for.
			for _, hop := range append(via[1:], r) {
				if !strings.EqualFold(hop.URL.Host, origin.Host) {
					for _, k := range deviceHeaders {
						r.Header.Del(k)
					}
					for k := range custom {
						r.Header.Del(k)
					}
					break
				}
			}
			return nil
		},
	}
}

// proxyAddr is the host:port the transport dials for proxy u.
func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	switch u.Scheme {
	case "https":
		port = "443"
	case "socks5", "socks5h":
		port = "1080"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// Redact hides the userinfo, path and query of a subscription URL, which
// often carry the access token.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<subscription>"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactErr rewrites the URL in errors from http.Client, which quote it in
// full.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: Redact(ue.URL), Err: ue.Err}
	}
	return err
}
