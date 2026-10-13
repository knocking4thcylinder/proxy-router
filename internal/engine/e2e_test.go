package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

type testCert struct {
	certLines, keyLines []string
	sha256              string
	tlsCert             tls.Certificate
}

func newCert(t *testing.T) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return testCert{
		certLines: strings.Split(strings.TrimSpace(string(certPEM)), "\n"),
		keyLines:  strings.Split(strings.TrimSpace(string(keyPEM)), "\n"),
		sha256:    hex.EncodeToString(sum[:]),
		tlsCert:   tc,
	}
}

func (c testCert) tlsSettings(alpn ...string) map[string]any {
	s := map[string]any{"certificates": []any{map[string]any{"certificate": c.certLines, "key": c.keyLines}}}
	if len(alpn) > 0 {
		s["alpn"] = alpn
	}
	return s
}

func freePort(t *testing.T, udp bool) int {
	t.Helper()
	if udp {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func wgKeys(t *testing.T) (priv, pub string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func startServer(t *testing.T, inbound map[string]any) {
	t.Helper()
	inbound["listen"] = "127.0.0.1"
	inst, err := Start(map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
}

// tweaked turns on every Happ-style setting, to prove connections still
// work with them.
func tweaked(t *testing.T) *config.Config {
	cfg, err := config.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fragment.Enabled = true
	cfg.Noises = config.Noises{Enabled: true, Items: []config.Noise{
		{Type: "array", Rand: config.Range{From: 1, To: 512}, RandRange: config.Range{From: 0, To: 255}, Delay: config.Range{From: 10, To: 20}},
		{Type: "str", Packet: "hello", Delay: config.Range{From: 5, To: 10}},
	}}
	cfg.Mux.Enabled = true
	cfg.PreferredIP = "ipv4"
	return cfg
}

// fetchVia requests target through a client built from server s, with
// Happ-style tweaks from cfg when it's not nil.
func fetchVia(t *testing.T, s *share.Server, target string, cfg ...*config.Config) string {
	t.Helper()
	obs, err := s.Outbounds("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) > 0 && cfg[0] != nil {
		obs, _ = ApplyTweaks(obs, cfg[0])
	}
	inst, err := Start(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": obs})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer inst.Close()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := xnet.ParseDestination("tcp:" + addr)
				if err != nil {
					return nil, err
				}
				return core.Dial(ctx, inst, dest)
			},
		},
	}
	var lastErr error
	// UDP based transports may need a moment for the handshake.
	for range 3 {
		resp, err := client.Get(target)
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(body)
	}
	t.Fatalf("request through %s failed: %v", s.Protocol, lastErr)
	return ""
}

// lanTarget serves the target page on a non-loopback local address.
func lanTarget(t *testing.T) string {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	// Prefer ordinary LAN addresses over VPN/CGNAT ones (e.g. Tailscale).
	slices.SortStableFunc(addrs, func(a, b net.Addr) int {
		pa, pb := isPrivate(a), isPrivate(b)
		switch {
		case pa && !pb:
			return -1
		case pb && !pa:
			return 1
		}
		return 0
	})
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort(ipn.IP.String(), "0"))
		if err != nil {
			continue
		}
		srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello from target")
		})}}
		srv.Start()
		t.Cleanup(srv.Close)
		return srv.URL
	}
	t.Skip("no non-loopback IPv4 address to test WireGuard against")
	return ""
}

func isPrivate(a net.Addr) bool {
	ipn, ok := a.(*net.IPNet)
	return ok && ipn.IP.IsPrivate()
}

func TestEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from target")
	}))
	defer target.Close()

	cert := newCert(t)

	// A TLS 1.3 site for REALITY to borrow its handshake from.
	realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	realityTarget.Config.ErrorLog = log.New(io.Discard, "", 0) // REALITY probes look like bad handshakes
	realityTarget.TLS = &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}, MinVersion: tls.VersionTLS13}
	realityTarget.StartTLS()
	defer realityTarget.Close()
	realityKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	realityPriv := base64.RawURLEncoding.EncodeToString(realityKey.Bytes())
	realityPub := base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes())

	wgServerPriv, wgServerPub := wgKeys(t)
	wgClientPriv, wgClientPub := wgKeys(t)

	ss2022Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	vless := func(stream map[string]any, flow string) func(int) map[string]any {
		return func(port int) map[string]any {
			client := map[string]any{"id": testUUID}
			if flow != "" {
				client["flow"] = flow
			}
			in := map[string]any{"protocol": "vless", "port": port, "settings": map[string]any{
				"clients": []any{client}, "decryption": "none",
			}}
			if stream != nil {
				in["streamSettings"] = stream
			}
			return in
		}
	}

	vmessJSON, _ := json.Marshal(map[string]any{
		"v": "2", "ps": "vmess ws", "add": "127.0.0.1", "port": "%d", "id": testUUID,
		"aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "example.com", "path": "/vm", "tls": "",
	})

	cases := []struct {
		name string
		udp  bool
		// WireGuard's userspace stack drops packets to loopback addresses.
		noLoopback bool
		server     func(port int) map[string]any
		link       func(port int) string
	}{
		{
			name:   "vless raw",
			server: vless(nil, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=tcp&security=none#vless", testUUID, p)
			},
		},
		{
			name:   "vless ws",
			server: vless(map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/ws"}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=ws&path=%%2Fws&host=example.com#ws", testUUID, p)
			},
		},
		{
			name:   "vless grpc",
			server: vless(map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "svc"}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=grpc&serviceName=svc&mode=gun#grpc", testUUID, p)
			},
		},
		{
			name:   "vless httpupgrade",
			server: vless(map[string]any{"network": "httpupgrade", "httpupgradeSettings": map[string]any{"path": "/hu"}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=httpupgrade&path=%%2Fhu#hu", testUUID, p)
			},
		},
		{
			name:   "vless xhttp",
			server: vless(map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/xh"}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=xhttp&path=%%2Fxh&mode=auto#xhttp", testUUID, p)
			},
		},
		{
			name:   "vless kcp",
			udp:    true,
			server: vless(map[string]any{"network": "kcp", "kcpSettings": map[string]any{}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=kcp&headerType=none#kcp", testUUID, p)
			},
		},
		{
			name: "vless tls vision",
			server: vless(map[string]any{"network": "raw", "security": "tls", "tlsSettings": cert.tlsSettings()},
				"xtls-rprx-vision"),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=tcp&security=tls&sni=localhost&fp=chrome&flow=xtls-rprx-vision&pcs=%s#tls",
					testUUID, p, cert.sha256)
			},
		},
		{
			name: "vless reality vision",
			server: vless(map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{
				"target":      strings.TrimPrefix(realityTarget.URL, "https://"),
				"serverNames": []string{"localhost"},
				"privateKey":  realityPriv,
				"shortIds":    []string{"a1b2c3d4"},
			}}, "xtls-rprx-vision"),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=tcp&security=reality&sni=localhost&fp=chrome&pbk=%s&sid=a1b2c3d4&spx=%%2F&flow=xtls-rprx-vision#reality",
					testUUID, p, realityPub)
			},
		},
		{
			name: "vless reality xhttp",
			server: vless(map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/rx"},
				"security": "reality", "realitySettings": map[string]any{
					"target":      strings.TrimPrefix(realityTarget.URL, "https://"),
					"serverNames": []string{"localhost"},
					"privateKey":  realityPriv,
					"shortIds":    []string{""},
				}}, ""),
			link: func(p int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?type=xhttp&path=%%2Frx&security=reality&sni=localhost&fp=chrome&pbk=%s#rx",
					testUUID, p, realityPub)
			},
		},
		{
			name: "vmess ws",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "vmess", "port": p,
					"settings":       map[string]any{"clients": []any{map[string]any{"id": testUUID}}},
					"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/vm"}}}
			},
			link: func(p int) string {
				js := strings.Replace(string(vmessJSON), `"%d"`, fmt.Sprintf(`"%d"`, p), 1)
				return "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
			},
		},
		{
			name: "trojan tls",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "trojan", "port": p,
					"settings":       map[string]any{"clients": []any{map[string]any{"password": "secret pass"}}},
					"streamSettings": map[string]any{"network": "raw", "security": "tls", "tlsSettings": cert.tlsSettings()}}
			},
			link: func(p int) string {
				return fmt.Sprintf("trojan://%s@127.0.0.1:%d?security=tls&sni=localhost&pcs=%s#trojan",
					url.PathEscape("secret pass"), p, cert.sha256)
			},
		},
		{
			name: "shadowsocks aead (SIP002 base64)",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "shadowsocks", "port": p,
					"settings": map[string]any{"method": "aes-256-gcm", "password": "sspass", "network": "tcp,udp"}}
			},
			link: func(p int) string {
				ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:sspass"))
				return fmt.Sprintf("ss://%s@127.0.0.1:%d#ss", ui, p)
			},
		},
		{
			name: "shadowsocks legacy base64",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "shadowsocks", "port": p,
					"settings": map[string]any{"method": "chacha20-ietf-poly1305", "password": "sspass", "network": "tcp,udp"}}
			},
			link: func(p int) string {
				return "ss://" + base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "chacha20-ietf-poly1305:sspass@127.0.0.1:%d", p)) + "#legacy"
			},
		},
		{
			name: "shadowsocks 2022",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "shadowsocks", "port": p,
					"settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": ss2022Key, "network": "tcp,udp"}}
			},
			link: func(p int) string {
				return fmt.Sprintf("ss://2022-blake3-aes-128-gcm:%s@127.0.0.1:%d#ss2022", url.QueryEscape(ss2022Key), p)
			},
		},
		{
			name: "socks (v2rayN base64 auth)",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "socks", "port": p, "settings": map[string]any{
					"auth": "password", "accounts": []any{map[string]any{"user": "u", "pass": "p"}}}}
			},
			link: func(p int) string {
				return fmt.Sprintf("socks://%s@127.0.0.1:%d#socks", base64.StdEncoding.EncodeToString([]byte("u:p")), p)
			},
		},
		{
			name: "http proxy",
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "http", "port": p, "settings": map[string]any{
					"accounts": []any{map[string]any{"user": "u", "pass": "p"}}}}
			},
			link: func(p int) string { return fmt.Sprintf("http://u:p@127.0.0.1:%d#http", p) },
		},
		{
			name: "hysteria2 salamander",
			udp:  true,
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "hysteria", "port": p,
					"settings": map[string]any{"version": 2, "clients": []any{map[string]any{"auth": "hy2pass"}}},
					"streamSettings": map[string]any{
						"network": "hysteria", "security": "tls", "tlsSettings": cert.tlsSettings("h3"),
						"hysteriaSettings": map[string]any{"version": 2},
						"finalmask": map[string]any{"udp": []any{map[string]any{
							"type": "salamander", "settings": map[string]any{"password": "obfspass"}}}},
					}}
			},
			link: func(p int) string {
				return fmt.Sprintf("hysteria2://hy2pass@127.0.0.1:%d/?sni=localhost&obfs=salamander&obfs-password=obfspass&pinSHA256=%s#hy2",
					p, cert.sha256)
			},
		},
		{
			name:       "wireguard",
			udp:        true,
			noLoopback: true,
			server: func(p int) map[string]any {
				return map[string]any{"protocol": "wireguard", "port": p, "settings": map[string]any{
					"secretKey": wgServerPriv,
					"peers":     []any{map[string]any{"publicKey": wgClientPub, "allowedIPs": []string{"10.7.0.2/32"}}},
				}}
			},
			link: func(p int) string {
				return fmt.Sprintf("wireguard://%s@127.0.0.1:%d?publickey=%s&address=10.7.0.2/32&mtu=1420#wg",
					url.QueryEscape(wgClientPriv), p, url.QueryEscape(wgServerPub))
			},
		},
	}

	for _, tc := range cases {
		for _, mode := range []string{"plain", "tweaked"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var cfg *config.Config
				if mode == "tweaked" {
					cfg = tweaked(t)
				}
				port := freePort(t, tc.udp)
				startServer(t, tc.server(port))
				link := tc.link(port)
				s, err := share.ParseLink(link)
				if err != nil {
					t.Fatalf("parse %s: %v", link, err)
				}
				for _, w := range s.Warnings {
					t.Logf("warning: %s", w)
				}
				targetURL := target.URL
				if tc.noLoopback {
					targetURL = lanTarget(t)
				}
				if got := fetchVia(t, s, targetURL, cfg); got != "hello from target" {
					t.Fatalf("unexpected body %q", got)
				}
			})
		}
	}

	// A JSON subscription whose proxy dials through a helper outbound
	// (the "fragment" pattern), via dialerProxy.
	t.Run("xray json chain", func(t *testing.T) {
		port := freePort(t, false)
		startServer(t, vless(nil, "")(port))
		body := fmt.Sprintf(`[{
			"remarks": "chained",
			"outbounds": [
				{"tag": "proxy", "protocol": "vless",
				 "settings": {"vnext": [{"address": "127.0.0.1", "port": %d, "users": [{"id": %q, "encryption": "none"}]}]},
				 "streamSettings": {"network": "raw", "sockopt": {"dialerProxy": "fragment"}}},
				{"tag": "fragment", "protocol": "freedom",
				 "settings": {"fragment": {"packets": "1-3", "length": "10-20", "interval": "1-2"}}},
				{"tag": "direct", "protocol": "freedom"}
			]
		}]`, port, testUUID)
		res := subscription.Decode([]byte(body))
		if len(res.Errors) > 0 || len(res.Servers) != 1 {
			t.Fatalf("decode: %v servers, errors %v", len(res.Servers), res.Errors)
		}
		s := res.Servers[0]
		if s.Name != "chained" || len(s.Chain) != 1 || s.Address != "127.0.0.1" || s.Port != port {
			t.Fatalf("unexpected server %+v", s)
		}
		obs, _ := s.Outbounds("proxy")
		if dp := obs[0]["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"]; dp != "proxy~fragment" || obs[1]["tag"] != "proxy~fragment" {
			t.Fatalf("chain not renamed: %v / %v", dp, obs[1]["tag"])
		}
		if got := fetchVia(t, s, target.URL); got != "hello from target" {
			t.Fatalf("unexpected body %q", got)
		}
	})
}
