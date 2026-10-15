package share

import (
	"encoding/json"
	"strings"
	"testing"
)

// hostile is a JSON config using options a provider must not control.
const hostile = `{"remarks": "evil",
  "outbounds": [
    {"tag": "proxy", "protocol": "vless", "sendThrough": "origin",
     "settings": {"address": "a.com", "port": 443, "id": "11111111-2222-3333-4444-555555555555",
       "encryption": "none", "reverse": {"tag": "r"}},
     "streamSettings": {
       "network": "xhttp", "security": "tls",
       "tlsSettings": {"serverName": "a.com", "masterKeyLog": "/root/keys",
         "certificates": [null, {"certificateFile": "/etc/shadow", "keyFile": "/etc/ssh/ssh_host_ed25519_key"}],
         "echSockopt": {"mark": 1}},
       "xhttpSettings": {"path": "/x", "extra": {
         "path": "/ignored", "xPaddingBytes": "100-1000",
         "downloadSettings": {"address": "b.com", "port": 443, "network": "xhttp",
           "sockopt": {"interface": "eth9", "dialerProxy": "frag"},
           "xhttpSettings": {"downloadSettings": {"network": "raw"}}}}},
       "finalmask": {"udp": [{"type": "xicmp", "settings": {"listenIp": "0.0.0.0"}}, null],
         "quicParams": {"debug": true, "congestion": "bbr"}},
       "sockopt": {"mark": 255, "interface": "lo", "tproxy": "redirect", "tcpCongestion": "bbr",
         "customSockopt": [null], "tcpFastOpen": true}}},
    {"tag": "frag", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:22",
      "fragment": {"packets": "tlshello", "length": "100-200"}}}
  ]}`

func TestSanitizeHostileConfig(t *testing.T) {
	servers, errs := ParseXrayJSON([]byte(hostile))
	if len(errs) > 0 || len(servers) != 1 {
		t.Fatalf("servers=%d errs=%v", len(servers), errs)
	}
	s := servers[0]
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "ignored unsupported or unsafe options") {
		t.Errorf("want one summary warning, got %v", s.Warnings)
	}
	obs, err := s.Outbounds("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("outbounds = %d", len(obs))
	}
	raw, _ := json.Marshal(obs)
	for _, bad := range []string{"sendThrough", "reverse", "masterKeyLog", "certificate", "keyFile",
		"echSockopt", "/ignored", "xicmp", "debug", "mark", `"interface"`, "tproxy", "tcpCongestion",
		"customSockopt", "redirect", `"raw"`} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("%s survived: %s", bad, raw)
		}
	}
	ob := obs[0]
	x := get(ob, "streamSettings.xhttpSettings").(map[string]any)
	if x["path"] != "/x" || x["xPaddingBytes"] != "100-1000" {
		t.Errorf("xhttp extra not applied: %v", x)
	}
	if get(ob, "streamSettings.xhttpSettings.downloadSettings.address") != "b.com" {
		t.Errorf("downloadSettings lost: %v", x)
	}
	// The download connection's dialer is renamed along with the helper.
	if d := get(ob, "streamSettings.xhttpSettings.downloadSettings.sockopt.dialerProxy"); d != obs[1]["tag"] || d != "chain:proxy~frag" {
		t.Errorf("download dialerProxy = %v, helper = %v", d, obs[1]["tag"])
	}
	if get(ob, "streamSettings.sockopt.tcpFastOpen") != true || get(ob, "streamSettings.finalmask.quicParams.congestion") != "bbr" {
		t.Errorf("safe options dropped: %v", get(ob, "streamSettings"))
	}
	if get(obs[1], "settings.fragment.packets") != "tlshello" {
		t.Errorf("fragment helper = %v", obs[1])
	}
}

func TestDownloadDialerMustBeImported(t *testing.T) {
	cfg := `{"outbounds": [{"tag": "proxy", "protocol": "vless",
	  "settings": {"address": "a.com", "port": 443, "id": "x"},
	  "streamSettings": {"network": "xhttp", "xhttpSettings": {"downloadSettings": {"sockopt": {"dialerProxy": "direct"}}}}}]}`
	if _, errs := ParseXrayJSON([]byte(cfg)); len(errs) != 1 || !strings.Contains(errs[0].Error(), "unknown tag") {
		t.Errorf("errs = %v", errs)
	}
}

func TestHelperCantBeProxy(t *testing.T) {
	for _, proto := range []string{"freedom", "direct", "blackhole", "block", "dns", "loopback"} {
		cfg := `{"outbounds": [
		  {"tag": "real", "protocol": "vless", "settings": {"address": "a.com", "port": 443, "id": "x"}},
		  {"tag": "proxy", "protocol": "` + proto + `", "settings": {"inboundTag": "socks"}}]}`
		_, errs := ParseXrayJSON([]byte(cfg))
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), "doesn't go through a server") {
			t.Errorf("%s tagged proxy: errs = %v", proto, errs)
		}
	}
}

func TestHelperChainRestricted(t *testing.T) {
	cfg := `{"outbounds": [
	  {"tag": "proxy", "protocol": "vless", "settings": {"address": "a.com", "port": 443, "id": "x"},
	   "streamSettings": {"sockopt": {"dialerProxy": "loop"}}},
	  {"tag": "loop", "protocol": "loopback", "settings": {"inboundTag": "dns-direct"}}]}`
	if _, errs := ParseXrayJSON([]byte(cfg)); len(errs) != 1 || !strings.Contains(errs[0].Error(), "loopback") {
		t.Errorf("errs = %v", errs)
	}
}

func TestWireGuardUserspaceOnly(t *testing.T) {
	_, ob := outbound(t, "wg://key@1.2.3.4:51820?publickey=pub")
	if get(ob, "settings.noKernelTun") != true {
		t.Errorf("link: %v", get(ob, "settings"))
	}
	cfg := `{"outbounds": [{"tag": "proxy", "protocol": "wireguard",
	  "settings": {"secretKey": "k", "noKernelTun": false, "peers": [null, {"publicKey": "p", "endpoint": "1.2.3.4:51820"}]}}]}`
	servers, errs := ParseXrayJSON([]byte(cfg))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	obs, _ := servers[0].Outbounds("proxy")
	if get(obs[0], "settings.noKernelTun") != true || len(get(obs[0], "settings.peers").([]any)) != 1 {
		t.Errorf("json: %v", obs[0]["settings"])
	}
}

// Servers saved before sanitizing existed are cleaned when used.
func TestOutboundsSanitizesStoredServers(t *testing.T) {
	s := &Server{Name: "old", Outbound: json.RawMessage(`{"protocol": "vless",
	  "settings": {"address": "a.com", "port": 443, "id": "x"},
	  "streamSettings": {"tlsSettings": {"certificates": [{"certificateFile": "/etc/shadow"}]}}}`)}
	obs, err := s.Outbounds("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(obs); strings.Contains(string(raw), "shadow") {
		t.Errorf("stored outbound not sanitized: %s", raw)
	}
	s.Outbound = json.RawMessage(`{"protocol": "freedom"}`)
	if _, err := s.Outbounds("proxy"); err == nil {
		t.Error("a stored freedom server must not be used as proxy")
	}
}

func TestLinkXHTTPExtraSanitized(t *testing.T) {
	extra := `{"downloadSettings": {"address": "b.com", "sockopt": {"mark": 7, "interface": "eth0"}}}`
	s, ob := outbound(t, "vless://id@a.com:443?type=xhttp&extra="+strings.NewReplacer("{", "%7B", "}", "%7D", `"`, "%22", " ", "").Replace(extra))
	if get(ob, "streamSettings.xhttpSettings.downloadSettings.address") != "b.com" {
		t.Errorf("download address lost: %v", get(ob, "streamSettings"))
	}
	if so := get(ob, "streamSettings.xhttpSettings.downloadSettings.sockopt"); so != nil && len(so.(map[string]any)) > 0 {
		t.Errorf("sockopt survived: %v", so)
	}
	if len(s.Warnings) != 1 {
		t.Errorf("warnings = %v", s.Warnings)
	}
}

func TestSanitizeProbe(t *testing.T) {
	p := SanitizeProbe(map[string]any{
		"destination": "http://tracker.example/x", "connectivity": "http://tracker.example/ip",
		"interval": "1ms", "timeout": "1h", "sampling": 1e9, "httpMethod": "POST",
	})
	want := map[string]any{"destination": DefaultProbeURL, "interval": "10s", "timeout": "30s", "sampling": 10}
	if len(p) != len(want) {
		t.Errorf("probe = %v", p)
	}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}
	if p := SanitizeProbe(map[string]any{"destination": "https://cp.example/204", "httpMethod": "GET"}); p["destination"] != "https://cp.example/204" || p["httpMethod"] != "GET" {
		t.Errorf("probe = %v", p)
	}
}

func TestEscapeTag(t *testing.T) {
	for in, want := range map[string]string{
		"USA": "USA", "a~b": "a%7Eb", "50%": "50%25", "#3": "%233", "x #3": "x #3",
	} {
		if got := EscapeTag(in); got != want {
			t.Errorf("EscapeTag(%q) = %q, want %q", in, got, want)
		}
	}
	// One provider's member can't look like another's.
	if MemberTag("server:a", "b~c") == MemberTag("server:a~b", "c") {
		t.Error("member tags collide")
	}
	if ChainTag("proxy", "a~b") == ChainTag("proxy~a", "b") {
		t.Error("chain tags collide")
	}
}
