package cli

import (
	"testing"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestApplyRefreshed(t *testing.T) {
	t.Cleanup(func() { serviceSubs.subs, serviceSubs.hwid = nil, "" })
	old := time.Now().Add(-24 * time.Hour)
	disk := func() *config.State {
		return &config.State{Subscriptions: []*config.Subscription{
			{Name: "a", URL: "https://a", UpdatedAt: old, Headers: map[string]string{"X": "1"},
				Servers: []*share.Server{{Name: "old"}}},
			{Name: "b", URL: "https://b", UpdatedAt: old, Servers: []*share.Server{{Name: "b1"}}},
		}}
	}

	// The service refreshes a and b; b's URL then changes on disk.
	s := disk()
	s.HWID = "hwid"
	s.Subscriptions[0].Servers = []*share.Server{{Name: "new"}}
	s.Subscriptions[0].UpdatedAt = time.Now()
	s.Subscriptions[1].UpdatedAt = time.Now()
	s.Subscriptions[1].Servers = nil
	keepRefreshed(s, s.Subscriptions)
	s.Subscriptions[0].Servers[0].Name = "mutated after keeping"

	next := disk()
	next.Subscriptions[0].Headers["X"] = "edited"
	next.Subscriptions[1].URL = "https://b2"
	applyRefreshed(next)
	a, b := next.Subscriptions[0], next.Subscriptions[1]
	if len(a.Servers) != 1 || a.Servers[0].Name != "new" {
		t.Errorf("a: %v, want the refreshed servers", a.Servers)
	}
	if a.Headers["X"] != "edited" {
		t.Errorf("a: the user's own edits were lost: %v", a.Headers)
	}
	if len(b.Servers) != 1 || b.Servers[0].Name != "b1" {
		t.Errorf("b: refreshed servers of the old URL were applied: %v", b.Servers)
	}
	if next.HWID != "hwid" {
		t.Errorf("HWID = %q", next.HWID)
	}

	// A newer refresh saved by the user wins.
	newer := disk()
	newer.Subscriptions[0].UpdatedAt = time.Now().Add(time.Hour)
	newer.Subscriptions[0].Servers = []*share.Server{{Name: "user"}}
	applyRefreshed(newer)
	if newer.Subscriptions[0].Servers[0].Name != "user" {
		t.Errorf("the user's newer refresh was overridden")
	}
}
