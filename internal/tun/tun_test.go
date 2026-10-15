package tun

import (
	"strings"
	"testing"
)

func TestNewOptionsExempt(t *testing.T) {
	o := NewOptions("prtun0", false, true, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "domain:ts.net", "geoip:private", "10.1.2.3", " 192.168.5.7/16 "})
	got := []string{}
	for _, p := range o.Exempt {
		got = append(got, p.String())
	}
	want := "100.64.0.0/10 fd7a:115c:a1e0::/48 10.1.2.3/32 192.168.0.0/16"
	if strings.Join(got, " ") != want {
		t.Fatalf("exempt = %v", got)
	}
	v4, v6 := o.exempt()
	if len(v4) != 3 || len(v6) != 1 {
		t.Fatalf("v4 %v v6 %v", v4, v6)
	}
	if !o.Equal(NewOptions("prtun0", false, true, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.1.2.3", "192.168.0.0/16"})) {
		t.Fatal("same addresses should be equal")
	}
	if o.Equal(NewOptions("prtun0", true, true, nil)) {
		t.Fatal("different options are equal")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"prtun0", "utun99", "xray.0", "my-tun_1"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", `x" accept`, "tun0\nflush ruleset", "averyveryverylongname"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRoutesAlwaysCaptureIPv6(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		rs := routes(ipv6)
		if len(rs) != 4 {
			t.Fatalf("ipv6=%v: %v", ipv6, rs)
		}
		for _, r := range rs {
			if r.reject != (r.family == "inet6" && !ipv6) {
				t.Errorf("ipv6=%v: %+v", ipv6, r)
			}
		}
	}
}

// fakeTools records the commands run, answering with reply.
func fakeTools(t *testing.T, reply func(cmd string) (string, error)) *[]string {
	var cmds []string
	saved := runTool
	runTool = func(stdin, name string, args ...string) (string, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		if stdin != "" {
			cmd += " <<" + stdin
		}
		cmds = append(cmds, cmd)
		if reply == nil {
			return "", nil
		}
		return reply(cmd)
	}
	t.Cleanup(func() { runTool = saved })
	return &cmds
}
