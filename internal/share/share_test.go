package share

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func outbound(t *testing.T, link string) (*Server, map[string]any) {
	t.Helper()
	s, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	var ob map[string]any
	if err := json.Unmarshal(s.Outbound, &ob); err != nil {
		t.Fatal(err)
	}
	return s, ob
}

// get walks a decoded JSON object with a dotted path.
func get(m map[string]any, path string) any {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func TestVLESSRealityXHTTP(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=xhttp&security=reality" +
		"&pbk=PUBKEY&sid=ab12&sni=www.microsoft.com&fp=firefox&spx=%2Fx&path=%2Fapi&host=cdn.example.com&mode=stream-one" +
		"&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&encryption=mlkem768x25519plus.native.0rtt.KEY#%F0%9F%87%A9%F0%9F%87%AA%20Germany"
	s, ob := outbound(t, link)
	if s.Name != "🇩🇪 Germany" {
		t.Errorf("name = %q", s.Name)
	}
	checks := map[string]any{
		"settings.address":                           "example.com",
		"settings.encryption":                        "mlkem768x25519plus.native.0rtt.KEY",
		"streamSettings.network":                     "xhttp",
		"streamSettings.security":                    "reality",
		"streamSettings.realitySettings.password":    "PUBKEY",
		"streamSettings.realitySettings.shortId":     "ab12",
		"streamSettings.realitySettings.serverName":  "www.microsoft.com",
		"streamSettings.realitySettings.fingerprint": "firefox",
		"streamSettings.realitySettings.spiderX":     "/x",
		"streamSettings.xhttpSettings.path":          "/api",
		"streamSettings.xhttpSettings.host":          "cdn.example.com",
		"streamSettings.xhttpSettings.mode":          "stream-one",
		"streamSettings.xhttpSettings.xPaddingBytes": "100-1000",
	}
	for path, want := range checks {
		if got := get(ob, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
}

func TestVLESSInsecureDropped(t *testing.T) {
	s, ob := outbound(t, "vless://id@h.com:443?security=tls&allowInsecure=1&alpn=h2,http/1.1")
	if len(s.Warnings) != 1 {
		t.Errorf("warnings = %v", s.Warnings)
	}
	if _, ok := get(ob, "streamSettings.tlsSettings").(map[string]any)["allowInsecure"]; ok {
		t.Error("allowInsecure must not be emitted, Xray rejects it")
	}
	if alpn := get(ob, "streamSettings.tlsSettings.alpn").([]any); len(alpn) != 2 {
		t.Errorf("alpn = %v", alpn)
	}
}

func TestVMessGRPC(t *testing.T) {
	js := `{"v":"2","ps":"grpc node","add":"1.2.3.4","port":443,"id":"uuid","aid":"0","net":"grpc","type":"multi","path":"svc","tls":"tls","sni":"a.com"}`
	s, ob := outbound(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(js)))
	if s.Name != "grpc node" || s.Port != 443 {
		t.Errorf("server = %+v", s)
	}
	if get(ob, "streamSettings.grpcSettings.serviceName") != "svc" || get(ob, "streamSettings.grpcSettings.multiMode") != true {
		t.Errorf("grpc = %v", get(ob, "streamSettings.grpcSettings"))
	}
	if get(ob, "streamSettings.tlsSettings.serverName") != "a.com" {
		t.Errorf("tls = %v", get(ob, "streamSettings.tlsSettings"))
	}
}

func TestHysteria2PortHopping(t *testing.T) {
	_, ob := outbound(t, "hy2://pass@h.com:443?mport=20000-30000&hop-interval=30s&sni=x.com#hy")
	hop := get(ob, "streamSettings.finalmask.quicParams.udpHop").(map[string]any)
	if hop["ports"] != "20000-30000" || hop["interval"] != "30" {
		t.Errorf("udpHop = %v", hop)
	}
	if get(ob, "streamSettings.tlsSettings.serverName") != "x.com" {
		t.Error("sni not applied")
	}
}

func TestShadowsocksPluginWarns(t *testing.T) {
	s, _ := outbound(t, "ss://YWVzLTI1Ni1nY206cGFzcw@h.com:8388?plugin=obfs-local%3Bobfs%3Dhttp#n")
	if len(s.Warnings) == 0 {
		t.Error("expected a plugin warning")
	}
}

func TestWireGuardKeysWithPlus(t *testing.T) {
	_, ob := outbound(t, "wireguard://aB+c/d=@1.2.3.4:51820?publickey=x+y/z=&reserved=1,2,3&address=172.16.0.2/32,2606:4700::2/128")
	if get(ob, "settings.secretKey") != "aB+c/d=" {
		t.Errorf("secretKey = %v", get(ob, "settings.secretKey"))
	}
	peer := get(ob, "settings.peers").([]any)[0].(map[string]any)
	if peer["publicKey"] != "x+y/z=" || peer["endpoint"] != "1.2.3.4:51820" {
		t.Errorf("peer = %v", peer)
	}
	if r := get(ob, "settings.reserved").([]any); len(r) != 3 {
		t.Errorf("reserved = %v", r)
	}
}

func TestShadowsocksSlashInBase64(t *testing.T) {
	// Standard base64 of "aes-128-gcm:pass?>?" contains '/' and '+'.
	ui := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass?>?"))
	if !strings.ContainsAny(ui, "/+") {
		t.Fatalf("test data should contain / or +: %s", ui)
	}
	_, ob := outbound(t, "ss://"+ui+"@h.com:8388#n")
	if get(ob, "settings.password") != "pass?>?" || get(ob, "settings.method") != "aes-128-gcm" {
		t.Errorf("settings = %v", get(ob, "settings"))
	}
}

func TestRejectsBadLinks(t *testing.T) {
	for _, link := range []string{
		"vless://@h.com:443",       // no id
		"vless://id@h.com",         // no port
		"trojan://@h.com:443",      // no password
		"foo://bar",                // unknown scheme
		"happ://crypt/abcdef",      // encrypted happ link
		"hy2://p@h.com:443?obfs=x", // unknown obfs
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("%q: expected an error", link)
		}
	}
}

func TestParseLinksSkipsBroken(t *testing.T) {
	servers, errs := ParseLinks("vless://id@a.com:443#a\n\n# comment\nbroken://x\ntrojan://p@b.com:443#b\n")
	if len(servers) != 2 || len(errs) != 1 {
		t.Fatalf("servers=%d errs=%v", len(servers), errs)
	}
}
