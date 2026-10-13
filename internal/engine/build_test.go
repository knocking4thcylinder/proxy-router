package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func testState(t *testing.T) *config.State {
	t.Helper()
	st, err := config.LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{
		"vless://" + testUUID + "@nl.example.com:443?security=reality&pbk=SDdyN0ZHVmUo4QaKlwvqP0ilZnG-xXAo4F7xC1oeeEk&sni=a.com#Netherlands",
		"trojan://pw@us.example.com:443#USA",
	} {
		s, err := share.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		st.Manual = append(st.Manual, s)
	}
	st.Select(st.Entries()[0])
	return st
}

func writeRules(t *testing.T, yaml string) *config.Rules {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := config.LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuildRouting(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	rules := writeRules(t, `
default: direct
rules:
  - name: ru
    outbound: direct
    domain: [domain:ru, full:ya.ru]
    ip: 77.88.0.0/16
  - outbound: server:USA
    domain: openai.com
    port: 443
  - outbound: block
    protocol: bittorrent
  - outbound: proxy
    process: [Telegram]
`)
	xc, _, err := Build(Plan{Config: cfg, Rules: rules, State: testState(t)})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(xc)

	// The generated config must be accepted by Xray.
	if _, err := core.LoadConfig("json", strings.NewReader(string(data))); err != nil {
		t.Fatalf("xray rejected config: %v\n%s", err, data)
	}

	var got struct {
		Outbounds []struct{ Tag string } `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	json.Unmarshal(data, &got)
	var tags []string
	for _, o := range got.Outbounds {
		tags = append(tags, o.Tag)
	}
	if strings.Join(tags, ",") != "proxy,direct,block,system,server:USA" {
		t.Errorf("outbound tags = %v", tags)
	}
	r := got.Routing.Rules
	// 2 system_route rules (Tailscale) first, then the user's rules with
	// domain+ip split, then the catch-all.
	if len(r) != 8 {
		t.Fatalf("want 8 xray rules, got %d: %v", len(r), r)
	}
	if r[0]["outboundTag"] != "system" || r[1]["outboundTag"] != "system" {
		t.Errorf("system_route rules must come first: %v %v", r[0], r[1])
	}
	r = r[2:]
	if r[0]["domain"] == nil || r[1]["ip"] == nil || r[0]["ip"] != nil {
		t.Errorf("domain/ip not split: %v %v", r[0], r[1])
	}
	if r[2]["outboundTag"] != "server:USA" || r[2]["port"] != "443" {
		t.Errorf("server rule = %v", r[2])
	}
	if last := r[5]; last["outboundTag"] != "direct" || last["network"] != "tcp,udp" {
		t.Errorf("catch-all = %v", last)
	}
}

func TestBuildNeedsServer(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	st := testState(t)
	st.Selected = nil
	rules := writeRules(t, "default: proxy\n")
	if _, _, err := Build(Plan{Config: cfg, Rules: rules, State: st}); err == nil {
		t.Fatal("expected an error without a selected server")
	}
	// Direct-only rules don't need a server.
	rules = writeRules(t, "default: direct\n")
	if _, _, err := Build(Plan{Config: cfg, Rules: rules, State: st}); err != nil {
		t.Fatal(err)
	}
}

func TestRulesValidation(t *testing.T) {
	for _, bad := range []string{
		"default: nowhere\n",
		"rules:\n  - outbound: proxy\n",                      // no conditions
		"rules:\n  - outbound: proxy\n    domian: [a.com]\n", // typo
		"rules:\n  - outbound: proxy\n    network: icmp\n",
		"domain_strategy: Whatever\n",
	} {
		p := filepath.Join(t.TempDir(), "r.yaml")
		os.WriteFile(p, []byte(bad), 0o644)
		if _, err := config.LoadRules(p); err == nil {
			t.Errorf("expected error for:\n%s", bad)
		}
	}
}
