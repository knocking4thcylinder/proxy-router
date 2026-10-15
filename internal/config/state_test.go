package config

import (
	"strings"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func findState(groups map[string][]string) *State {
	st := &State{}
	for _, g := range []string{"A", "B"} {
		var servers []*share.Server
		for _, n := range groups[g] {
			servers = append(servers, &share.Server{Name: n})
		}
		st.Subscriptions = append(st.Subscriptions, &Subscription{Name: g, Servers: servers})
	}
	return st
}

func names(entries []Entry) string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Group+"/"+e.Server.Name)
	}
	return strings.Join(out, ",")
}

func TestFindGroupScoped(t *testing.T) {
	st := findState(map[string][]string{
		"A": {"USA East", "Germany"},
		// B tries to take over queries meant for A.
		"B": {"A/USA East", "A/USA", "USA East 2", "Germany"},
	})
	for query, want := range map[string]string{
		"A/USA East": "A/USA East",
		"A/USA":      "A/USA East", // substring, but only within A
		"B/Germany":  "B/Germany",
		"USA East":   "A/USA East", // exact beats "USA East 2"
		"2":          "A/Germany",  // index
	} {
		e, err := st.Find(query)
		if err != nil || e.Group+"/"+e.Server.Name != want {
			t.Errorf("Find(%q) = %v, %v; want %s", query, e, err, want)
		}
	}
	for _, query := range []string{"Germany", "A/Spain"} {
		if e, err := st.Find(query); err == nil {
			t.Errorf("Find(%q) = %v, want an error", query, e)
		}
	}
}

func TestFindDuplicateInGroupIsAmbiguous(t *testing.T) {
	st := findState(map[string][]string{"A": {"Same", "Same"}})
	if _, err := st.Find("A/Same"); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("err = %v", err)
	}
}

func TestFindAll(t *testing.T) {
	st := findState(map[string][]string{
		"A": {"Germany", "Germany 2", "USA"},
		"B": {"A/Germany fake", "Germany B"},
	})
	for query, want := range map[string]string{
		"A/Germany": "A/Germany", // exact name in the group wins
		"A/germ":    "A/Germany,A/Germany 2",
		"A/*":       "A/Germany,A/Germany 2,A/USA",
		"Germany":   "A/Germany,A/Germany 2,B/A/Germany fake,B/Germany B",
		"3":         "A/USA",
	} {
		if got := names(st.FindAll(query)); got != want {
			t.Errorf("FindAll(%q) = %s, want %s", query, got, want)
		}
	}
}
