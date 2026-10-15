package subscription

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

const link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#ok"

// testPolicy trusts httptest's certificate and treats the listed ports on
// loopback as non-public, standing in for LAN addresses.
func testPolicy(srv *httptest.Server, blocked ...*httptest.Server) policy {
	pool := x509.NewCertPool()
	if c := srv.Certificate(); c != nil {
		pool.AddCert(c)
	}
	ports := map[uint16]bool{}
	for _, b := range blocked {
		ports[netip.MustParseAddrPort(b.Listener.Addr().String()).Port()] = true
	}
	return policy{
		nonPublic: func(ap netip.AddrPort) bool { return ports[ap.Port()] },
		rootCAs:   pool,
	}
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchSendsHeaders(t *testing.T) {
	var got http.Header
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header
		w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("My \x1b[31mVPN‮")))
		w.Header().Set("announce", "base64:"+base64.StdEncoding.EncodeToString([]byte("hello\n\x1b]0;pwned\x07world")))
		w.Write([]byte(link))
	})
	res, err := testPolicy(srv).fetch(context.Background(), Request{
		URL: srv.URL + "/sub/token", HWID: "dev1", Headers: map[string]string{"X-Key": "k"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("x-hwid") != "dev1" || got.Get("X-Key") != "k" || got.Get("User-Agent") != DefaultUserAgent {
		t.Errorf("headers = %v", got)
	}
	if res.Info.Title != "My VPN" || res.Info.Announce != "hello world" {
		t.Errorf("info = %+v", res.Info)
	}
}

func TestFetchRejectsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(link)) }))
	defer srv.Close()
	_, err := testPolicy(srv).fetch(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("err = %v, want ErrInsecureURL", err)
	}
	if _, err := testPolicy(srv).fetch(context.Background(), Request{URL: srv.URL, AllowHTTP: true}); err != nil {
		t.Fatalf("with AllowHTTP: %v", err)
	}
	if _, err := Fetch(context.Background(), Request{URL: "ftp://example.com/x"}); err == nil {
		t.Fatal("ftp URL accepted")
	}
}

func TestFetchRefusesDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(link)) }))
	defer plain.Close()
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/sub", http.StatusFound)
	})
	_, err := testPolicy(srv).fetch(context.Background(), Request{URL: srv.URL, AllowHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("err = %v, want refused redirect", err)
	}
}

func TestFetchRedirectLimit(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	})
	_, err := testPolicy(srv).fetch(context.Background(), Request{URL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("err = %v, want redirect limit", err)
	}
}

func TestFetchRedirectDropsHeaders(t *testing.T) {
	var got http.Header
	other := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header
		w.Write([]byte(link))
	})
	var first http.Header
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		first = r.Header
		http.Redirect(w, r, other.URL+"/moved", http.StatusFound)
	})
	_, err := testPolicy(srv).fetch(context.Background(), Request{
		URL:     srv.URL,
		HWID:    "dev1",
		Headers: map[string]string{"X-Key": "k", "Authorization": "Bearer secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Get("x-hwid") != "dev1" || first.Get("Authorization") == "" {
		t.Errorf("first hop headers = %v", first)
	}
	for _, k := range []string{"x-hwid", "x-device-os", "x-device-model", "X-Key", "Authorization"} {
		if v := got.Get(k); v != "" {
			t.Errorf("%s = %q sent to another host", k, v)
		}
	}
	if got.Get("User-Agent") != DefaultUserAgent {
		t.Errorf("User-Agent = %q", got.Get("User-Agent"))
	}
}

func TestFetchRefusesNonPublicRedirect(t *testing.T) {
	hit := false
	lan := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte(link))
	})
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, lan.URL, http.StatusFound)
	})
	_, err := testPolicy(srv, lan).fetch(context.Background(), Request{URL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "non-public") || hit {
		t.Fatalf("err = %v, hit = %v; want the connection refused", err, hit)
	}

	// A subscription that is itself on the LAN may redirect within it.
	if _, err := testPolicy(srv, lan, srv).fetch(context.Background(), Request{URL: srv.URL}); err != nil || !hit {
		t.Fatalf("local subscription: err = %v, hit = %v", err, hit)
	}
}

func TestDialGuard(t *testing.T) {
	// The check runs on the address actually dialed, after DNS, so a name
	// that resolves (or rebinds) to a blocked address is refused too.
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(link)) })
	p := testPolicy(srv, srv)
	u, _ := url.Parse("https://localhost/")
	c := p.client(u, false, false, nil)
	_, port, _ := strings.Cut(srv.Listener.Addr().String(), ":")
	_, err := c.Get("https://localhost:" + port + "/")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("err = %v, want refused", err)
	}
}

func TestIsNonPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1":       true,
		"10.1.2.3":        true,
		"172.16.0.1":      true,
		"192.168.1.1":     true,
		"169.254.169.254": true,
		"100.100.1.1":     true,
		"0.0.0.0":         true,
		"224.0.0.1":       true,
		"::1":             true,
		"fe80::1":         true,
		"fd00::1":         true,
		"::ffff:10.0.0.1": true,
		"1.1.1.1":         false,
		"8.8.8.8":         false,
		"2606:4700::1111": false,
	} {
		if got := isNonPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isNonPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestFetchBodyLimit(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxBody+1)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(big)
	zw.Close()
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gzip" {
			// Small on the wire, too big once the transport inflates it.
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gz.Bytes())
			return
		}
		w.Write(big)
	})
	for _, path := range []string{"/plain", "/gzip"} {
		_, err := testPolicy(srv).fetch(context.Background(), Request{URL: srv.URL + path})
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s: err = %v, want size error", path, err)
		}
	}
}

func TestFetchErrorsHideSecrets(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/empty/SECRET" {
			// Parse errors quote at most the first 40 bytes of a bad line.
			w.Write([]byte("<html><head><title>Subscription expired</title></head><body>SECRET"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("token SECRET is expired"))
	})
	dead := serve(t, nil)
	dead.Close()
	for _, u := range []string{
		srv.URL + "/sub/SECRET?token=SECRET",
		srv.URL + "/empty/SECRET",
		strings.Replace(dead.URL, "https://", "https://user:SECRET@", 1) + "/SECRET",
		"https://bad host/SECRET",
	} {
		_, err := testPolicy(srv).fetch(context.Background(), Request{URL: u})
		if err == nil {
			t.Errorf("%s: no error", u)
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks the secret: %v", err)
		}
	}
}

func TestDecodeCleansNames(t *testing.T) {
	res := Decode([]byte("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#" +
		url.PathEscape("\x1b[2J‮evil\nname") + "\n" +
		"vless://11111111-2222-3333-4444-555555555555@example.org:443?security=tls#" + url.PathEscape("\x1b[0m")))
	if len(res.Servers) != 2 {
		t.Fatalf("servers = %d, errors = %v", len(res.Servers), res.Errors)
	}
	if got := res.Servers[0].Name; got != "evil name" {
		t.Errorf("name = %q", got)
	}
	if got := res.Servers[1].Name; got != "example.org:443" {
		t.Errorf("empty name = %q, want the address", got)
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:pw@sub.example.com:8443/api/sub/TOKEN?x=1": "https://sub.example.com:8443/…",
		"https://example.com": "https://example.com/…",
		"not a url":           "<subscription>",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}
