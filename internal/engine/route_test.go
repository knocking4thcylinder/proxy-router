package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
)

// testHosts is what Xray's DNS answers in routing tests; anything else
// fails right away instead of going to a real resolver.
var testHosts = map[string]any{
	"evil.example":    "10.1.2.3",    // a public name with a private address
	"blocked.example": "203.0.113.9", // a name whose address a rule blocks
	"public.example":  "203.0.113.1",
}

// router builds xc into an Xray instance (without starting it) and returns
// a function that reports where a connection would go: from inbound to
// target ("ip:port" or "name:port"), with sniffed as its TLS/HTTP name.
func router(t *testing.T, xc map[string]any) func(inbound, target, sniffed string) string {
	t.Helper()
	xc["dns"] = map[string]any{"hosts": testHosts, "servers": []any{"tcp+local://127.0.0.1:1"}}
	data, _ := json.Marshal(xc)
	pb, err := core.LoadConfig("json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("xray rejected config: %v\n%s", err, data)
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	r := inst.GetFeature(routing.RouterType()).(routing.Router)
	ohm := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	return func(inbound, target, sniffed string) string {
		dest, err := xnet.ParseDestination("tcp:" + target)
		if err != nil {
			t.Fatal(err)
		}
		ob := &session.Outbound{Target: dest}
		if sniffed != "" {
			ob.RouteTarget = xnet.TCPDestination(xnet.DomainAddress(sniffed), dest.Port)
		}
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: inbound})
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
		route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
		if err != nil {
			// No rule matched: the dispatcher uses the default handler.
			return ohm.GetDefaultHandler().Tag()
		}
		return route.GetOutboundTag()
	}
}

const localRule = `
  - name: local network
    outbound: direct
    ip: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "::1/128", "fc00::/7"]
`

func TestRouteByAddressNotSniffedName(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	for _, tc := range []struct {
		name, rules string
	}{
		{"current default", "rules:" + localRule},
		{"old default", `rules:
  - name: local network
    outbound: direct
    domain: [full:localhost, domain:local, domain:lan]
    ip: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "::1/128", "fc00::/7"]
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tun := range []bool{false, true} {
				p := Plan{Config: cfg, Rules: writeRules(t, tc.rules), State: testState(t)}
				if tun {
					p.TUNListen, p.TUNAccount = "127.0.0.1:10807", NewAccount()
				}
				xc, notes, err := Build(p)
				if err != nil {
					t.Fatal(err)
				}
				if tc.name == "old default" && !strings.Contains(strings.Join(notes, "\n"), "ignoring its domain list") {
					t.Errorf("no note about the old rule: %v", notes)
				}
				route := router(t, xc)
				in := "socks"
				if tun {
					in = "tun"
				}
				for _, c := range []struct{ target, sniffed, want string }{
					// A public address can't get itself sent direct by its
					// TLS/HTTP name...
					{"203.0.113.5:443", "x.lan", "proxy"},
					{"203.0.113.5:443", "localhost", "proxy"},
					// ...nor by a name that resolves to a private address.
					{"203.0.113.5:443", "evil.example", "proxy"},
					// ...nor by claiming a system_route name (Tailscale).
					{"203.0.113.5:443", "x.ts.net", "proxy"},
					{"192.168.1.10:443", "", "direct"},
					{"192.168.1.10:443", "public.example", "direct"},
				} {
					if got := route(in, c.target, c.sniffed); got != c.want {
						t.Errorf("%s %s (%s) -> %s, want %s", in, c.target, c.sniffed, got, c.want)
					}
				}
				// Tailscale's own range still takes the system route, except
				// what reaches us through the TUN (that would loop).
				want := "system"
				if tun {
					want = "block"
				}
				if got := route(in, "100.100.1.1:443", ""); got != want {
					t.Errorf("%s tailscale address -> %s, want %s", in, got, want)
				}
			}
		})
	}
}

func TestIPRulesApplyToNames(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	for _, def := range []string{"proxy", "direct", "block"} {
		rules := writeRules(t, "default: "+def+"\nrules:"+localRule+`
  - outbound: block
    ip: 203.0.113.9
`)
		xc, _, err := Build(Plan{Config: cfg, Rules: rules, State: testState(t)})
		if err != nil {
			t.Fatal(err)
		}
		route := router(t, xc)
		for _, c := range []struct{ target, want string }{
			// IPIfNonMatch resolves names no rule matched by name, so IP
			// rules apply to them too.
			{"blocked.example:443", "block"},
			{"evil.example:443", "direct"},
			{"public.example:443", def},
			{"203.0.113.9:443", "block"},
			// A name that doesn't resolve takes the default all the same.
			{"nowhere.invalid:443", def},
		} {
			if got := route("socks", c.target, ""); got != c.want {
				t.Errorf("default %s: %s -> %s, want %s", def, c.target, got, c.want)
			}
		}
	}
}

func TestDefaultPoolIsFirstOutbound(t *testing.T) {
	cfg, _ := config.Load(t.TempDir())
	st, _ := config.LoadState(t.TempDir())
	st.Manual = subscription.Decode([]byte(providerAuto(1001, 1002))).Servers
	st.Manual = append(st.Manual, testState(t).Manual...)
	st.Select(st.Entries()[0])
	for _, tc := range []struct{ rules, want string }{
		{"default: proxy\n", "proxy~bridge"},
		{"default: direct\n", "direct"},
		{"default: server:USA\n", "server:USA"},
		{"default: pool:p\npools:\n  p:\n    servers: [Netherlands, USA]\n", "pool:p~"},
	} {
		xc, _, err := Build(Plan{Config: cfg, Rules: writeRules(t, tc.rules), State: st})
		if err != nil {
			t.Fatalf("%s: %v", tc.rules, err)
		}
		first := xc["outbounds"].([]map[string]any)[0]["tag"].(string)
		if !strings.HasPrefix(first, tc.want) {
			t.Errorf("%s: first outbound %s, want %s", tc.rules, first, tc.want)
		}
		if got := router(t, xc)("socks", "nowhere.invalid:443", ""); got != first {
			t.Errorf("%s: unresolvable name -> %s, want %s", tc.rules, got, first)
		}
	}
}
