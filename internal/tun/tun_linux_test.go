package tun

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func fakeHost(t *testing.T, withResolved, ipv6 bool) {
	savedResolved, savedTool, savedV6, savedConf, savedWarn := resolved, tool, hasIPv6, resolvConf, warn
	resolved = func() bool { return withResolved }
	tool = func(name string) string { return "/usr/bin/" + name }
	hasIPv6 = func(string) bool { return ipv6 }
	resolvConf = func() string { return "nameserver 127.0.0.53\n" }
	warn = func(string, ...any) {}
	t.Cleanup(func() {
		resolved, tool, hasIPv6, resolvConf, warn = savedResolved, savedTool, savedV6, savedConf, savedWarn
	})
}

// commands drops stdin from recorded commands.
func commands(cmds []string) []string {
	var out []string
	for _, c := range cmds {
		c, _, _ = strings.Cut(c, " <<")
		out = append(out, c)
	}
	return out
}

func TestUpLinux(t *testing.T) {
	fakeHost(t, true, true)
	cmds := fakeTools(t, func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "ip -j") {
			return "[]", nil
		}
		return "", nil
	})
	if err := Up(NewOptions("prtun0", false, true, []string{"100.64.0.0/10"})); err != nil {
		t.Fatal(err)
	}
	got := commands(*cmds)
	want := []string{
		"ip link set dev prtun0 up",
		"nft -f -",
		"ip -j -4 route show exact 0.0.0.0/1",
		"ip -j -4 route show exact 128.0.0.0/1",
		"ip -j -6 route show exact ::/1",
		"ip -j -6 route show exact 8000::/1",
		"ip -4 route replace 0.0.0.0/1 dev prtun0 proto 112",
		"ip -4 route replace 128.0.0.0/1 dev prtun0 proto 112",
		"ip -6 route replace unreachable ::/1 proto 112",
		"ip -6 route replace unreachable 8000::/1 proto 112",
		"resolvectl dns prtun0 198.18.0.53",
		"resolvectl domain prtun0 ~.",
		"resolvectl default-route prtun0 yes",
		"resolvectl dnsovertls prtun0 no",
		"resolvectl llmnr prtun0 no",
		"resolvectl mdns prtun0 no",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	if !strings.Contains((*cmds)[1], "table inet proxy_router {") {
		t.Fatalf("nft input: %s", (*cmds)[1])
	}
}

func TestUpRefusesForeignRoutes(t *testing.T) {
	fakeHost(t, false, true)
	cmds := fakeTools(t, func(cmd string) (string, error) {
		switch cmd {
		case "ip -j -4 route show exact 0.0.0.0/1":
			// One of ours from an earlier Up, and another VPN's.
			return `[{"dst":"0.0.0.0/1","dev":"prtun0","protocol":"112","scope":"link","flags":[]},
				{"dst":"0.0.0.0/1","gateway":"10.8.0.1","dev":"tun0","flags":[]}]`, nil
		case "ip -j -6 route show exact ::/1":
			return `[{"type":"unreachable","dst":"::/1","dev":"lo","protocol":"112","metric":1024,"flags":[],"pref":"medium"}]`, nil
		}
		if strings.HasPrefix(cmd, "ip -j") {
			return "[]", nil
		}
		return "", nil
	})
	err := Up(NewOptions("prtun0", false, false, nil))
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0/1 dev tun0") || strings.Contains(err.Error(), "prtun0") || strings.Contains(err.Error(), "::/1") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range *cmds {
		if strings.Contains(c, "replace") {
			t.Fatalf("touched routes: %s", c)
		}
	}
}

func TestUpWithoutIPv6(t *testing.T) {
	fakeHost(t, false, false)
	fakeTools(t, func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "ip -j -6"):
			return "", errors.New("ip: Address family not supported")
		case strings.HasPrefix(cmd, "ip -j"):
			return "[]", nil
		case strings.HasPrefix(cmd, "ip -6"):
			return "", errors.New("RTNETLINK answers: Permission denied")
		}
		return "", nil
	})
	if err := Up(NewOptions("prtun0", false, false, nil)); err != nil {
		t.Fatalf("a host without IPv6 should be fine: %v", err)
	}
	// With IPv6 present, failing to take it over is an error.
	hasIPv6 = func(string) bool { return true }
	if err := Up(NewOptions("prtun0", false, false, nil)); err == nil {
		t.Fatal("IPv6 left uncaptured")
	}
}

func TestUpKillSwitchNeedsNft(t *testing.T) {
	fakeHost(t, false, true)
	tool = func(name string) string { return "" }
	fakeTools(t, nil)
	if err := Up(NewOptions("prtun0", false, true, nil)); err == nil || !strings.Contains(err.Error(), "nft") {
		t.Fatalf("err = %v", err)
	}
	if err := Up(NewOptions("bad name", false, false, nil)); err == nil {
		t.Fatal("bad interface name accepted")
	}
}

func TestDownLinux(t *testing.T) {
	fakeHost(t, true, true)
	cmds := fakeTools(t, nil)
	Down(NewOptions("prtun0", true, true, nil), true)
	want := []string{
		"resolvectl revert prtun0",
		"ip -4 route del 0.0.0.0/1 dev prtun0 proto 112",
		"ip -4 route del 128.0.0.0/1 dev prtun0 proto 112",
		"ip -6 route del ::/1 dev prtun0 proto 112",
		"ip -6 route del 8000::/1 dev prtun0 proto 112",
	}
	if got := commands(*cmds); !slices.Equal(got, want) {
		t.Fatalf("kept kill switch:\n%s", strings.Join(got, "\n"))
	}

	*cmds = nil
	Down(NewOptions("prtun0", false, true, nil), false)
	got := commands(*cmds)
	if got[3] != "ip -6 route del unreachable ::/1 proto 112" || got[len(got)-1] != "nft -f -" {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
}

func TestCleanupLinux(t *testing.T) {
	fakeHost(t, false, true)
	cmds := fakeTools(t, nil)
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -4 route del 0.0.0.0/1 proto 112",
		"ip -4 route del 128.0.0.0/1 proto 112",
		"ip -6 route del ::/1 proto 112",
		"ip -6 route del 8000::/1 proto 112",
		"nft -f - <<" + nftClear(),
	}
	if !slices.Equal(*cmds, want) {
		t.Fatalf("commands:\n%s", strings.Join(*cmds, "\n"))
	}
}

func TestSyncRestoresResolved(t *testing.T) {
	fakeHost(t, true, true)
	domain := "Link 5 (prtun0): ~."
	cmds := fakeTools(t, func(cmd string) (string, error) {
		if cmd == "resolvectl domain prtun0" {
			return domain, nil
		}
		return "", nil
	})
	o := NewOptions("prtun0", false, true, nil)
	if Sync(o); len(*cmds) != 1 {
		t.Fatalf("reapplied while still set: %v", *cmds)
	}
	domain = "Link 5 (prtun0):" // resolved restarted
	if Sync(o); len(*cmds) < 3 || (*cmds)[2] != "resolvectl dns prtun0 198.18.0.53" {
		t.Fatalf("commands: %v", *cmds)
	}
}

func TestLeakyResolvers(t *testing.T) {
	conf := "# generated\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver fe80::1%wlan0\nnameserver 127.0.0.1\nsearch lan\n"
	if got := leakyResolvers(conf, true); !slices.Equal(got, []string{"192.168.1.1", "fe80::1%wlan0", "127.0.0.1"}) {
		t.Fatalf("got %v", got)
	}
	// The stub only forwards into the TUN once resolved is pointed there.
	if got := leakyResolvers("nameserver 127.0.0.53\n", false); !slices.Equal(got, []string{"127.0.0.53"}) {
		t.Fatalf("got %v", got)
	}
}

func TestForeignRoutes(t *testing.T) {
	f, err := foreignRoutes(`[{"type":"unreachable","dst":"8000::/1","dev":"lo","flags":[]}]`)
	if err != nil || len(f) != 1 || f[0] != "unreachable 8000::/1 dev lo" {
		t.Fatalf("got %v %v", f, err)
	}
	if _, err := foreignRoutes("garbage"); err == nil {
		t.Fatal("garbage parsed")
	}
}
