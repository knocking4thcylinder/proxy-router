package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
)

// providerAuto mimics the "Авто" entry providers send to Happ: user traffic
// goes to a leastLoad balancer over "bridge*" outbounds that falls back to
// direct (through a loopback to a second, empty balancer).
func providerAuto(ports ...int) string {
	var obs []string
	for i, p := range ports {
		tag := "bridge"
		if i > 0 {
			tag = fmt.Sprintf("bridge-%d", i+1)
		}
		obs = append(obs, fmt.Sprintf(`{"tag": %q, "protocol": "vless",
			"settings": {"vnext": [{"address": "127.0.0.1", "port": %d, "users": [{"id": %q, "encryption": "none"}]}]},
			"streamSettings": {"network": "tcp"}}`, tag, p, testUUID))
	}
	return fmt.Sprintf(`[{"remarks": "Авто",
		"outbounds": [%s,
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole"},
			{"tag": "loop-to-whitelist", "protocol": "loopback", "settings": {"inboundTag": "entry-whitelist-fallback"}}],
		"routing": {
			"rules": [
				{"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
				{"type": "field", "network": "tcp,udp", "inboundTag": ["socks", "http"], "balancerTag": "Balancer"},
				{"type": "field", "inboundTag": ["entry-whitelist-fallback"], "balancerTag": "WhitelistBalancer"}],
			"balancers": [
				{"tag": "Balancer", "selector": ["bridge"], "strategy": {"type": "leastLoad", "settings": {"expected": 6, "baselines": ["1s"], "tolerance": 0.5}}, "fallbackTag": "loop-to-whitelist"},
				{"tag": "WhitelistBalancer", "selector": ["whitelist"], "strategy": {"type": "leastLoad"}, "fallbackTag": "direct"}]},
		"burstObservatory": {"pingConfig": {"timeout": "5s", "interval": "1m", "sampling": 2, "httpMethod": "HEAD", "destination": "http://www.gstatic.com/generate_204"}, "subjectSelector": ["bridge", "whitelist"]}
	}]`, strings.Join(obs, ","))
}

func TestParseProviderPool(t *testing.T) {
	res := subscription.Decode([]byte(providerAuto(1001, 1002, 1003)))
	if len(res.Errors) > 0 || len(res.Servers) != 1 {
		t.Fatalf("servers=%d errors=%v", len(res.Servers), res.Errors)
	}
	s := res.Servers[0]
	if s.Name != "Авто" || s.Pool == nil || len(s.Pool.Members) != 3 || s.Primaries() != 3 {
		t.Fatalf("pool not recognised: %+v", s)
	}
	if !strings.Contains(strings.Join(s.Warnings, " "), "falls back") {
		t.Errorf("expected a warning about the unproxied fallback, got %v", s.Warnings)
	}
	obs, _ := s.Outbounds("proxy")
	var tags []string
	for _, o := range obs {
		tags = append(tags, o["tag"].(string))
	}
	if strings.Join(tags, ",") != "proxy~bridge,proxy~bridge-2,proxy~bridge-3" {
		t.Errorf("member tags = %v", tags)
	}
	if m := s.Members(); len(m) != 3 || m[1].Port != 1002 {
		t.Errorf("members = %+v", m)
	}
}

func TestBuildPoolNeverFallsBackToDirect(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	st, _ := config.LoadState(t.TempDir())
	st.Manual = subscription.Decode([]byte(providerAuto(1001, 1002))).Servers
	st.Select(st.Entries()[0])
	xc, _, err := Build(Plan{Config: cfg, Rules: writeRules(t, "default: proxy\n"), State: st})
	if err != nil {
		t.Fatal(err)
	}
	bal := xc["routing"].(map[string]any)["balancers"].([]map[string]any)[0]
	if bal["tag"] != "proxy" || bal["fallbackTag"] != "proxy~bridge" {
		t.Fatalf("balancer = %v", bal)
	}
	sel := bal["selector"].([]string)
	if len(sel) != 1 || sel[0] != "proxy~bridge" {
		t.Fatalf("selector = %v", sel)
	}
	rules := xc["routing"].(map[string]any)["rules"].([]map[string]any)
	if last := rules[len(rules)-1]; last["balancerTag"] != "proxy" {
		t.Fatalf("catch-all should use the balancer: %v", last)
	}
	if _, ok := xc["burstObservatory"]; !ok {
		t.Fatal("pool needs a health check")
	}
}

func TestTUNSystemRouteGuard(t *testing.T) {
	rules := systemRouteRules([]string{"100.64.0.0/10", "domain:ts.net"}, true)
	if len(rules) != 4 || rules[0]["outboundTag"] != "block" || rules[0]["inboundTag"] == nil || rules[1]["outboundTag"] != "system" {
		t.Fatalf("rules = %v", rules)
	}
	if r := systemRouteRules([]string{"100.64.0.0/10"}, false); len(r) != 1 {
		t.Fatalf("without TUN there's nothing to guard: %v", r)
	}
}

// TestPoolEndToEnd runs a real balancer: the first member (also the
// fallback) is dead, so traffic only works once the health check has moved
// the pool to the live member.
func TestPoolEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from target")
	}))
	defer target.Close()

	dead := freePort(t, false)
	alive := freePort(t, false)
	startServer(t, map[string]any{"protocol": "vless", "port": alive, "settings": map[string]any{
		"clients": []any{map[string]any{"id": testUUID}}, "decryption": "none"}})

	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	socks := freePort(t, false)
	cfg.Listen.Socks = fmt.Sprintf("127.0.0.1:%d", socks)
	cfg.Listen.HTTP = ""
	cfg.LogLevel = "none"
	st, _ := config.LoadState(dir)
	var links []*share.Server
	for _, p := range []int{dead, alive} {
		s, err := share.ParseLink(fmt.Sprintf("vless://%s@127.0.0.1:%d?type=tcp#m%d", testUUID, p, p))
		if err != nil {
			t.Fatal(err)
		}
		links = append(links, s)
	}
	st.Manual = links
	rulesPath := filepath.Join(dir, "r.yaml")
	os.WriteFile(rulesPath, []byte(fmt.Sprintf(`default: pool:all
domain_strategy: AsIs
pools:
  all:
    servers: "*"
pool_probe:
  url: %s
  interval: 10s
`, target.URL)), 0o644)
	rules, err := config.LoadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	xc, _, err := Build(Plan{Config: cfg, Rules: rules, State: st})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := Start(xc)
	if err != nil {
		raw, _ := json.MarshalIndent(xc, "", " ")
		t.Fatalf("start: %v\n%s", err, raw)
	}
	defer inst.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", socks))
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		DialContext: (&net.Dialer{}).DialContext,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	for ctx.Err() == nil {
		resp, err := client.Get(target.URL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) == "hello from target" {
				t.Logf("pool moved to the live member after %v", time.Since(start).Round(time.Millisecond))
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("pool never routed around the dead member")
}

func TestTUNAnswersDNSItself(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	st := testState(t)
	xc, _, err := Build(Plan{Config: cfg, Rules: writeRules(t, "default: proxy\n"), State: st, TUNListen: "127.0.0.1:10807"})
	if err != nil {
		t.Fatal(err)
	}
	rules := xc["routing"].(map[string]any)["rules"].([]map[string]any)
	if rules[0]["outboundTag"] != "direct" || rules[1]["outboundTag"] != "dns-out" || rules[1]["port"] != "53" {
		t.Fatalf("server-name lookups, then DNS from the TUN, must come first: %v / %v", rules[0], rules[1])
	}
	servers := fmt.Sprint(xc["dns"].(map[string]any)["servers"])
	// Without a resolver the server address stays a hostname: it must be
	// looked up outside the tunnel, never with DoH through it.
	if strings.Contains(servers, "full: ") || strings.Contains(servers, "full:]") {
		t.Errorf("empty name in dns servers: %s", servers)
	}
	for _, want := range []string{"full:nl.example.com", "dns-direct", "localhost", "domain:ts.net"} {
		if !strings.Contains(servers, want) {
			t.Errorf("dns servers missing %q: %s", want, servers)
		}
	}
}
