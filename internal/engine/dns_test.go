package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/tun"
)

func TestTUNDNSResponses(t *testing.T) {
	cfg, err := config.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen.Socks, cfg.Listen.HTTP = "", ""
	cfg.LogLevel = "none"
	rules := writeRules(t, "default: direct\n")
	rules.DNS = map[string]any{
		"hosts":   map[string]any{"site.example": []string{"192.0.2.10", "2001:db8::10"}},
		"servers": []string{"tcp+local://127.0.0.1:1"},
	}
	tunAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t, false))
	login := NewAccount()
	xc, _, err := Build(Plan{Config: cfg, Rules: rules, State: &config.State{}, TUNListen: tunAddr, TUNAccount: login})
	if err != nil {
		t.Fatal(err)
	}
	main, err := Start(xc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { main.Close() })

	frontConfig, err := BuildTUNFront("testtun0", 1500, tunAddr, login)
	if err != nil {
		t.Fatal(err)
	}
	// Inject the DNS packets at the front's dispatcher so the test can
	// exercise the real SOCKS hop without creating a system TUN device.
	delete(frontConfig, "inbounds")
	front, err := Start(frontConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })

	for _, tc := range []struct {
		name string
		kind dnsmessage.Type
		want int
	}{
		{"A", dnsmessage.TypeA, 1},
		{"AAAA", dnsmessage.TypeAAAA, 1},
		{"HTTPS", dnsmessage.TypeHTTPS, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dest := xnet.UDPDestination(xnet.ParseAddress(tun.DNSServer), 53)
			conn, err := core.Dial(ctx, front, dest)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			query := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: 123, RecursionDesired: true},
				Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("site.example."), Type: tc.kind, Class: dnsmessage.ClassINET}},
			}
			packet, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(packet); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			var reply dnsmessage.Message
			if err := reply.Unpack(buf[:n]); err != nil {
				t.Fatal(err)
			}
			if !reply.Response || reply.ID != query.ID || reply.RCode != dnsmessage.RCodeSuccess || len(reply.Answers) != tc.want {
				t.Fatalf("want NOERROR with %d answers, got %v", tc.want, reply)
			}
			for _, a := range reply.Answers {
				if a.Header.Class != dnsmessage.ClassINET || a.Header.Type != tc.kind {
					t.Errorf("want an IN %s record, got %v", tc.kind, a.Header)
				}
			}
		})
	}
}
