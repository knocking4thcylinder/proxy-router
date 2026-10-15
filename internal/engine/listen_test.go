package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

func TestListenNeedsLoginBeyondLoopback(t *testing.T) {
	build := func(socks, user, pass string, open bool) (map[string]any, error) {
		cfg, _ := config.Load(t.TempDir())
		cfg.Listen.Socks, cfg.Listen.HTTP = socks, ""
		cfg.Listen.User, cfg.Listen.Password, cfg.Listen.AllowOpen = user, pass, open
		xc, _, err := Build(Plan{Config: cfg, Rules: writeRules(t, "default: direct\n"), State: testState(t)})
		if err != nil {
			return nil, err
		}
		return xc["inbounds"].([]map[string]any)[0], nil
	}
	in, err := build(":10808", "", "", false)
	if err != nil || in["listen"] != "127.0.0.1" {
		t.Errorf("empty host must mean loopback: %v %v", in, err)
	}
	for _, addr := range []string{"0.0.0.0:10808", "[::]:10808", "192.168.1.2:10808", "myhost:10808"} {
		if _, err := build(addr, "", "", false); err == nil {
			t.Errorf("%s without a login must be refused", addr)
		}
		if _, err := build(addr, "", "", true); err != nil {
			t.Errorf("%s with allow_open: %v", addr, err)
		}
	}
	if _, err := build("0.0.0.0:10808", "u", "", false); err == nil {
		t.Error("a user without a password must be refused")
	}
	in, err = build("0.0.0.0:10808", "u", "p", false)
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprint(in["settings"]); !strings.Contains(s, "auth:password") || !strings.Contains(s, "pass:p") {
		t.Errorf("socks settings = %s", s)
	}
}

// TestTUNInboundNeedsLogin runs the main instance's "tun" inbound and checks
// that only the per-run login gets through.
func TestTUNInboundNeedsLogin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer target.Close()

	cfg, _ := config.Load(t.TempDir())
	cfg.Listen.Socks, cfg.Listen.HTTP = fmt.Sprintf("127.0.0.1:%d", freePort(t, false)), ""
	cfg.LogLevel = "none"
	tunAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t, false))
	login := NewAccount()
	p := Plan{Config: cfg, Rules: writeRules(t, "default: direct\n"), State: testState(t), TUNListen: tunAddr}
	if _, _, err := Build(p); err == nil {
		t.Fatal("a TUN inbound without a login must be refused")
	}
	p.TUNAccount = login
	xc, _, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	delete(xc, "dns") // no lookups needed here
	inst, err := Start(xc)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	front, err := BuildTUNFront("utun99", 1500, tunAddr, login)
	if err != nil {
		t.Fatal(err)
	}
	ob := front["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	if ob["user"] != login.User || ob["pass"] != login.Pass {
		t.Fatalf("front outbound = %v", ob)
	}

	get := func(auth *proxy.Auth) error {
		d, err := proxy.SOCKS5("tcp", tunAddr, auth, proxy.Direct)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			Dial: d.Dial, DisableKeepAlives: true,
		}}
		resp, err := client.Get(target.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "ok" {
			return fmt.Errorf("body %q", body)
		}
		return nil
	}
	if err := get(nil); err == nil {
		t.Error("connected to the tun inbound without a login")
	}
	if err := get(&proxy.Auth{User: login.User, Password: "wrong"}); err == nil {
		t.Error("connected to the tun inbound with a wrong password")
	}
	if err := get(&proxy.Auth{User: login.User, Password: login.Pass}); err != nil {
		t.Errorf("with the login: %v", err)
	}
}
