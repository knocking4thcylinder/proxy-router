package tun

import (
	"slices"
	"strings"
	"testing"
)

func TestParseScutil(t *testing.T) {
	out := `<dictionary> {
  SearchDomains : <array> {
    0 : lan
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : fd00::1
  }
  Nested : <dictionary> {
    Inner : <array> {
      0 : x
    }
  }
  PrimaryService : 6F1B2A3C-0000-4000-8000-000000000001
}
`
	d, ok := parseScutil(out)
	if !ok {
		t.Fatal("not parsed")
	}
	if !slices.Equal(d["ServerAddresses"], []string{"192.168.1.1", "fd00::1"}) || d["PrimaryService"][0] != "6F1B2A3C-0000-4000-8000-000000000001" {
		t.Fatalf("got %v", d)
	}
	if len(d["Nested"]) != 0 || len(d["Inner"]) != 0 {
		t.Fatalf("nested values leaked: %v", d)
	}
	if _, ok := parseScutil("  No such key\n"); ok {
		t.Fatal("missing key parsed")
	}
}

func TestDNSBackupRoundTrip(t *testing.T) {
	b := dnsBackup{Service: "ABC-123", HadKey: true, Servers: []string{"192.168.1.1", "not an address\nset x", "fd00::1"}}
	script := backupScript(b)
	if strings.Contains(script, "not an address") || !strings.Contains(script, "d.add Servers * 192.168.1.1 fd00::1\n") {
		t.Fatalf("script:\n%s", script)
	}
	// What scutil prints for the dictionary the script stores.
	shown := "<dictionary> {\n  HadKey : 1\n  Servers : <array> {\n    0 : 192.168.1.1\n    1 : fd00::1\n  }\n  Service : ABC-123\n}\n"
	got, ok := parseBackup(shown)
	if !ok || got.Service != "ABC-123" || !got.HadKey || !slices.Equal(got.Servers, []string{"192.168.1.1", "fd00::1"}) {
		t.Fatalf("got %+v %v", got, ok)
	}
	if _, ok := parseBackup("<dictionary> {\n  Service : x/../y\n}\n"); ok {
		t.Fatal("bad service ID accepted")
	}
}

func TestDNSScripts(t *testing.T) {
	key := "Setup:/Network/Service/ABC/DNS"
	if got := applyDNSScript("ABC"); got != "d.init\nget "+key+"\nd.add ServerAddresses * 198.18.0.53\nset "+key+"\n" {
		t.Fatalf("apply:\n%s", got)
	}
	for _, c := range []struct {
		b    dnsBackup
		want string
	}{
		{dnsBackup{Service: "ABC"}, "remove " + key + "\n"},
		{dnsBackup{Service: "ABC", HadKey: true, Servers: []string{"1.1.1.1"}}, "d.add ServerAddresses * 1.1.1.1\nset " + key},
		{dnsBackup{Service: "ABC", HadKey: true}, "d.remove ServerAddresses\nset " + key},
	} {
		got := restoreDNSScript(c.b)
		if !strings.Contains(got, c.want) || !strings.HasSuffix(got, "remove "+dnsBackupKey+"\n") {
			t.Errorf("%+v:\n%s", c.b, got)
		}
	}
}
