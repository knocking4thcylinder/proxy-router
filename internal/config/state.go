package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
)

// ManualGroup holds servers added directly from links.
const ManualGroup = "manual"

// State is state.json, managed by the CLI.
type State struct {
	Subscriptions []*Subscription `json:"subscriptions"`
	Manual        []*share.Server `json:"manual,omitempty"`
	Selected      *Selection      `json:"selected,omitempty"`
	HWID          string          `json:"hwid,omitempty"`

	path string
}

type Subscription struct {
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	SendHWID  bool              `json:"send_hwid,omitempty"`
	UpdatedAt time.Time         `json:"updated_at,omitzero"`
	LastError string            `json:"last_error,omitempty"`
	Info      subscription.Info `json:"info"`
	Servers   []*share.Server   `json:"servers"`
}

// Selection identifies the active server by group and name so it survives
// subscription refreshes that reorder servers.
type Selection struct {
	Group string `json:"group"`
	Name  string `json:"name"`
}

// Entry is a server with its position in the combined list.
type Entry struct {
	Index  int
	Group  string
	Server *share.Server
}

func (e Entry) String() string { return fmt.Sprintf("#%d %s/%s", e.Index, e.Group, e.Server.Name) }

func LoadState(dir string) (*State, error) {
	s := &State{path: filepath.Join(dir, "state.json")}
	data, err := readFile(dir, "state.json", maxState)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("state.json: %w", err)
	}
	return s, nil
}

// ErrReadOnly is returned by Save in the TUN service, which never writes
// to the user's directory.
var ErrReadOnly = errors.New("the TUN service doesn't write state.json")

func (s *State) Save() error {
	if confined.on {
		return ErrReadOnly
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// May contain credentials, keep it private.
	return WriteFileAtomic(s.path, data, 0o600)
}

func (s *State) Subscription(name string) *Subscription {
	for _, sub := range s.Subscriptions {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

// DeviceID returns a stable random HWID, creating it on first use.
func (s *State) DeviceID() string {
	if s.HWID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		s.HWID = hex.EncodeToString(b)
	}
	return s.HWID
}

// Entries lists all servers: subscriptions in order, then manual ones.
func (s *State) Entries() []Entry {
	var out []Entry
	add := func(group string, servers []*share.Server) {
		for _, srv := range servers {
			out = append(out, Entry{Index: len(out) + 1, Group: group, Server: srv})
		}
	}
	for _, sub := range s.Subscriptions {
		add(sub.Name, sub.Servers)
	}
	add(ManualGroup, s.Manual)
	return out
}

// Current returns the selected server, if it still exists.
func (s *State) Current() (Entry, bool) {
	if s.Selected == nil {
		return Entry{}, false
	}
	for _, e := range s.Entries() {
		if e.Group == s.Selected.Group && e.Server.Name == s.Selected.Name {
			return e, true
		}
	}
	return Entry{}, false
}

func (s *State) Select(e Entry) {
	s.Selected = &Selection{Group: e.Group, Name: e.Server.Name}
}

// FindAll resolves a query to every matching server: "*" (all), an index,
// group/name, or every server whose name contains the text.
func (s *State) FindAll(query string) []Entry {
	query = strings.TrimSpace(strings.TrimPrefix(query, "#"))
	entries := s.Entries()
	if query == "*" {
		return entries
	}
	if n, err := strconv.Atoi(query); err == nil {
		if n >= 1 && n <= len(entries) {
			return []Entry{entries[n-1]}
		}
		return nil
	}
	var out []Entry
	q := strings.ToLower(query)
	for _, e := range entries {
		if e.Group+"/"+e.Server.Name == query || strings.Contains(strings.ToLower(e.Server.Name), q) {
			out = append(out, e)
		}
	}
	return out
}

// Find resolves a user query to one server. Accepted forms: list index
// ("3"), "group/name", exact name, or a unique case-insensitive substring.
func (s *State) Find(query string) (Entry, error) {
	query = strings.TrimSpace(strings.TrimPrefix(query, "#"))
	entries := s.Entries()
	if len(entries) == 0 {
		return Entry{}, fmt.Errorf("no servers yet; add a subscription with `proxy-router sub add <url>`")
	}
	if n, err := strconv.Atoi(query); err == nil {
		if n < 1 || n > len(entries) {
			return Entry{}, fmt.Errorf("no server #%d (have %d)", n, len(entries))
		}
		return entries[n-1], nil
	}
	if group, name, ok := strings.Cut(query, "/"); ok {
		for _, e := range entries {
			if e.Group == group && e.Server.Name == name {
				return e, nil
			}
		}
	}
	var exact, partial []Entry
	q := strings.ToLower(query)
	for _, e := range entries {
		switch {
		case e.Server.Name == query:
			exact = append(exact, e)
		case strings.Contains(strings.ToLower(e.Server.Name), q):
			partial = append(partial, e)
		}
	}
	for _, matches := range [][]Entry{exact, partial} {
		switch len(matches) {
		case 0:
			continue
		case 1:
			return matches[0], nil
		default:
			var names []string
			for _, m := range matches {
				names = append(names, m.String())
			}
			return Entry{}, fmt.Errorf("%q matches several servers:\n  %s", query, strings.Join(names, "\n  "))
		}
	}
	return Entry{}, fmt.Errorf("no server matches %q", query)
}
