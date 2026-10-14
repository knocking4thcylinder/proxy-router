package engine

import (
	"encoding/json"
	"errors"
	"testing"

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
