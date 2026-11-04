//go:build linux || (darwin && cgo)

package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestTrayFollowsSubscriptionChanges(t *testing.T) {
	dir := completionFixture(t)
	previousDir := flagDir
	flagDir = dir
	t.Cleanup(func() { flagDir = previousDir })
	// No installed service definitions: this test only reads the fixture's
	// subscription state and never controls the host's services.
	target := service.Target{Scope: service.User, User: &user.User{HomeDir: t.TempDir()}}
	controller := &tray{dir: dir, userT: target, sysT: target}
	m := controller.model()
	if m.configErr != "" {
		t.Fatal(m.configErr)
	}
	var groups []string
	for _, group := range m.groups {
		groups = append(groups, group.name)
		if group.subscription != (group.name != config.ManualGroup) {
			t.Fatalf("incorrect subscription actions for group %+v", group)
		}
	}
	if !slices.Equal(groups, []string{"My VPN", "Other", "Empty", "manual"}) || len(m.groups[2].servers) != 0 {
		t.Fatalf("subscription groups were lost: %+v", m.groups)
	}

	cmd := useCmd()
	cmd.SetArgs([]string{"--group", "Other", "Shared"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	m = controller.model()
	if m.selGroup != "Other" || m.selName != "Shared" {
		t.Fatalf("tray did not follow CLI selection: %q/%q", m.selGroup, m.selName)
	}

	state, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	state.Subscriptions[1].Servers = append(state.Subscriptions[1].Servers, &share.Server{Name: "New server"})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	m = controller.model()
	if !slices.Equal(m.groups[1].servers, []string{"Shared", "🇫🇮 Helsinki", "New server"}) || len(m.groups[0].servers) != 2 {
		t.Fatalf("tray did not refresh just the changed subscription: %+v", m.groups)
	}
}

func TestTrayIconStates(t *testing.T) {
	dir := completionFixture(t)
	previousDir := flagDir
	flagDir = dir
	t.Cleanup(func() { flagDir = previousDir })
	if _, live := readRunStatus(dir); live {
		t.Skip("a proxy-router service is running on this machine")
	}
	target := service.Target{Scope: service.User, User: &user.User{HomeDir: t.TempDir()}}
	controller := &tray{dir: dir, userT: target, sysT: target}
	m := controller.model()
	if m.icon != "off" || m.status != "Disconnected" || len(m.addrs) != 0 {
		t.Fatalf("disconnected tray shows %q / %q / %v", m.icon, m.status, m.addrs)
	}
	if tip := m.tooltip(); !strings.Contains(tip, "Disconnected") {
		t.Fatalf("tooltip %q doesn't say it's disconnected", tip)
	}
	for _, name := range []string{"on", "waiting", "off", "alert"} {
		for _, f := range []string{name + ".png", name + "-template.png"} {
			if _, err := trayIcons.ReadFile("icons/" + f); err != nil {
				t.Errorf("icon %s is missing: %v", f, err)
			}
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("listen: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m = controller.model()
	if m.icon != "alert" || m.configErr == "" {
		t.Fatalf("broken config shows %q (%q)", m.icon, m.configErr)
	}
}

func TestTrayByCountry(t *testing.T) {
	groups := []trayGroup{
		{name: "A", servers: []string{"🇨🇭 Reducto VPN | Швейцария", "🇨🇭 nVPN | Швейцария", "🇫🇮 Soda VPN | Финляндия", "🌐 Авто", "🇨🇭 Shared"}},
		{name: "B", servers: []string{"🇫🇮 Дед VPN | Финляндия", "🇨🇭 Shared", "🇩🇪 Paper"}},
	}
	if c, _ := byCountry(groups); c != nil {
		t.Fatalf("a short list was split by country: %+v", c)
	}
	for i := range 10 {
		groups[1].servers = append(groups[1].servers, fmt.Sprintf("🇸🇪 S%d | Швеция", i))
	}
	countries, other := byCountry(groups)
	var got []string
	for _, c := range countries {
		var labels []string
		for _, s := range c.servers {
			labels = append(labels, s.label)
		}
		got = append(got, fmt.Sprintf("%s %s %d %s", c.flag, c.name, len(c.servers), strings.Join(labels[:min(3, len(labels))], ",")))
	}
	want := []string{
		"🇸🇪 Швеция 10 S0,S1,S2",
		"🇨🇭 Швейцария 4 Reducto VPN,nVPN,Shared · A",
		"🇫🇮 Финляндия 2 Soda VPN,Дед VPN",
		"🇩🇪 DE 1 Paper",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("countries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(other) != 1 || other[0].name != "🌐 Авто" || other[0].group != "A" {
		t.Fatalf("other: %+v", other)
	}
	if s := countries[1].servers[3]; s.group != "B" || s.name != "🇨🇭 Shared" || s.label != "Shared · B" {
		t.Fatalf("duplicate name isn't told apart: %+v", s)
	}
}

func TestTrayFlagIcons(t *testing.T) {
	globe := flagIcon("")
	if len(globe) == 0 {
		t.Fatal("no globe icon")
	}
	for _, name := range []string{"🇨🇿 Алиса VPN | Чехия", "🇬🇧 x", "🇺🇸 y"} {
		if b := serverIcon(name); len(b) == 0 || bytes.Equal(b, globe) {
			t.Errorf("%q has no flag icon", name)
		}
	}
	for _, name := range []string{"🚀 ALL VPN Turbo Авто", "plain", "🇦"} {
		if !bytes.Equal(serverIcon(name), globe) {
			t.Errorf("%q should get the globe", name)
		}
	}
}
