//go:build linux || (darwin && cgo)

package cli

import (
	"os/user"
	"slices"
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
