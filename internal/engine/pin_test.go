package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestPinAddressesKeepsHostname(t *testing.T) {
	resolve := func(host string) (string, error) {
		if host == "dead.example" {
			return "", errors.New("nxdomain")
		}
		return "203.0.113.7", nil
	}
	cases := []struct {
		link string
		want map[string]string // dotted path -> value
	}{
		{"vless://id@srv.example:443?security=reality&pbk=k&sni=www.microsoft.com#r", map[string]string{
			"settings.address": "203.0.113.7", "streamSettings.realitySettings.serverName": "www.microsoft.com"}},
		{"trojan://pw@srv.example:443#t", map[string]string{
			"settings.address": "203.0.113.7", "streamSettings.tlsSettings.serverName": "srv.example"}},
		{"vless://id@srv.example:80?type=ws&path=%2F#w", map[string]string{
			"settings.address": "203.0.113.7", "streamSettings.wsSettings.host": "srv.example"}},
		{"vless://id@1.2.3.4:443#ip", map[string]string{"settings.address": "1.2.3.4"}},
		{"vless://id@dead.example:443#d", map[string]string{"settings.address": "dead.example"}},
	}
	for _, c := range cases {
		s, err := share.ParseLink(c.link)
		if err != nil {
			t.Fatal(err)
		}
		obs, _ := s.Outbounds("proxy")
		PinAddresses(obs, resolve)
		raw, _ := json.Marshal(obs[0])
		var ob map[string]any
		json.Unmarshal(raw, &ob)
		for path, want := range c.want {
			if got := dig(ob, path); got != want {
				t.Errorf("%s: %s = %v, want %s", c.link, path, got, want)
			}
		}
	}
}

func TestPinWireGuardEndpoint(t *testing.T) {
	s, err := share.ParseLink("wireguard://cHJpdg@wg.example:51820?publickey=cHVi#wg")
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := s.Outbounds("proxy")
	PinAddresses(obs, func(string) (string, error) { return "2001:db8::1", nil })
	peer := obs[0]["settings"].(map[string]any)["peers"].([]any)[0].(map[string]any)
	if peer["endpoint"] != "[2001:db8::1]:51820" {
		t.Fatalf("endpoint = %v", peer["endpoint"])
	}
}

func dig(m map[string]any, path string) any {
	var cur any = m
	for _, k := range splitDots(path) {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// dohServer answers srv.example with 203.0.113.7 and 2001:db8::7, and
// NXDOMAIN for anything else.
func dohServer(t *testing.T, queries *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		body, _ := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || q.Unpack(body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		question := q.Questions[0]
		hdr := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
		switch {
		case question.Name.String() != "srv.example.":
			resp.RCode = dnsmessage.RCodeNameError
		case question.Type == dnsmessage.TypeA:
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}})
		case question.Type == dnsmessage.TypeAAAA:
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr,
				Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::7").As16()}})
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoHLookup(t *testing.T) {
	var queries atomic.Int32
	srv := dohServer(t, &queries)
	broken := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer broken.Close()
	// The broken server shares the test CA, so one client trusts both.
	lookup := dohLookup(srv.Client(), []string{broken.URL + "/dns-query", srv.URL + "/dns-query"})

	ctx := context.Background()
	addrs, err := lookup(ctx, "srv.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}
	if !slices.Equal(addrs, want) {
		t.Errorf("addrs = %v, want %v", addrs, want)
	}
	if _, err := lookup(ctx, "missing.example"); err == nil {
		t.Error("NXDOMAIN must be an error")
	}
	// DoHLookup's own client dials through Xray's system dialer (which
	// binds to an interface when given one).
	plain := httptest.NewServer(srv.Config.Handler)
	defer plain.Close()
	if addrs, err := DoHLookup([]string{plain.URL + "/dns-query"}, "", 0)(ctx, "srv.example"); err != nil || len(addrs) != 2 {
		t.Errorf("DoHLookup: %v, %v", addrs, err)
	}

	// Only when DoH fails does the fallback get asked, and the answer is
	// cached.
	var fallbacks atomic.Int32
	fallback := func(ctx context.Context, host string) ([]netip.Addr, error) {
		fallbacks.Add(1)
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	}
	resolve := CachingResolver("ipv6", time.Minute, OrElse(lookup, fallback))
	for range 2 {
		if ip, err := resolve("srv.example"); err != nil || ip != "2001:db8::7" {
			t.Errorf("srv.example = %s, %v", ip, err)
		}
	}
	if fallbacks.Load() != 0 {
		t.Error("fallback used although DoH answered")
	}
	if ip, err := resolve("missing.example"); err != nil || ip != "198.51.100.1" || fallbacks.Load() != 1 {
		t.Errorf("missing.example = %s, %v (fallbacks %d)", ip, err, fallbacks.Load())
	}
	// With the fallback off, a DoH failure is final.
	resolve = CachingResolver("ipv4", time.Minute, lookup)
	if _, err := resolve("missing.example"); err == nil {
		t.Error("expected an error without a fallback")
	}
	before := queries.Load()
	resolve("srv.example")
	resolve("srv.example")
	if n := queries.Load() - before; n != 2 { // A + AAAA, once
		t.Errorf("%d queries for a cached name, want 2", n)
	}
}
