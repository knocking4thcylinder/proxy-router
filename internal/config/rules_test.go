package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeoRefs(t *testing.T) {
	for _, ok := range []string{"geosite:google", "!geoip:private", "ext:custom.dat:ads", "ext-ip:my.dat:!cn", "domain:ext:x", "1.2.3.4"} {
		if err := checkGeoRef(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"ext:../../etc/shadow:x", "ext:/etc/passwd:x", "ext-domain:sub/../../x:y", "!ext-ip:..:x", "ext::x", `ext:a\b:x`, "ext:sub/x.dat:y"} {
		if err := checkGeoRef(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestRulesFileRefs(t *testing.T) {
	dir := t.TempDir()
	for name, yaml := range map[string]string{
		"domain": "rules:\n  - outbound: direct\n    domain: ext:../../x.dat:a\n",
		"ip":     "rules:\n  - outbound: direct\n    ip: [\"ext:/etc/x:a\"]\n",
		"source": "rules:\n  - outbound: direct\n    source: ext-ip:../x:a\n",
		"dns servers": `dns:
  servers:
    - address: 1.1.1.1
      domains: ["ext:../../../etc/shadow:x"]
`,
		"dns hosts": `dns:
  hosts:
    "ext:../x.dat:a": 127.0.0.1
`,
		"dns expectedIPs": `dns:
  servers:
    - address: 1.1.1.1
      expectedIPs: ["ext-ip:/x:a"]
`,
	} {
		path := filepath.Join(dir, "r.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadRules(path)
		if err == nil || !strings.Contains(err.Error(), "plain name in the assets directory") {
			t.Errorf("%s: %v", name, err)
		}
	}
	path := filepath.Join(dir, "ok.yaml")
	ok := "rules:\n  - outbound: direct\n    domain: ext:custom.dat:a\ndns:\n  servers: [\"1.1.1.1\", {address: 8.8.8.8, domains: [\"geosite:google\"]}]\n"
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err != nil {
		t.Error(err)
	}
}

func TestSystemRouteRefs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("system_route: [\"ext:../../x:y\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("system_route accepted an ext: path outside assets")
	}
}
