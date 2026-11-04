//go:build linux || (darwin && cgo)

package cli

import (
	"cmp"
	"embed"
	"slices"
	"strings"
	"unicode/utf8"
)

// flags/ holds round flags, rendered from circle-flags
// (github.com/HatScripts/circle-flags, MIT) with rsvg-convert -w 32, and
// globe.png from assets/flags/globe.svg.
//
//go:embed flags/*.png
var flagIcons embed.FS

// flagIcon is the round icon for a flag emoji, or a globe when there's no
// flag or no icon for it.
func flagIcon(flag string) []byte {
	if flag != "" {
		if b, err := flagIcons.ReadFile("flags/" + strings.ToLower(flagCode(flag)) + ".png"); err == nil {
			return b
		}
	}
	b, _ := flagIcons.ReadFile("flags/globe.png")
	return b
}

// serverIcon is the icon for the flag a server's name starts with.
func serverIcon(name string) []byte {
	flag, _ := splitFlag(name)
	return flagIcon(flag)
}

// trayCountry is one country's servers across all groups, going by the
// flag emoji their names start with.
type trayCountry struct {
	flag, name string
	servers    []trayServer
}

type trayServer struct {
	group, name string
	label       string // the name without the flag or a trailing "| country"
}

// minCountryServers is how many servers it takes before the menu splits
// them by country; fewer fit in the subscriptions' own submenus.
const minCountryServers = 15

// byCountry splits the servers by country, biggest first, with those
// without a flag in other. It returns nil countries when that wouldn't
// help: a small list, or fewer than two countries.
func byCountry(groups []trayGroup) (countries []trayCountry, other []trayServer) {
	total := 0
	index := map[string]int{}
	names := map[string]map[string]int{} // flag → country name candidates
	for _, g := range groups {
		total += len(g.servers)
		for _, name := range g.servers {
			flag, rest := splitFlag(name)
			if flag == "" {
				other = append(other, trayServer{g.name, name, name})
				continue
			}
			i, ok := index[flag]
			if !ok {
				i = len(countries)
				index[flag] = i
				countries = append(countries, trayCountry{flag: flag})
				names[flag] = map[string]int{}
			}
			if _, after, ok := cutLast(rest, "|"); ok && after != "" {
				names[flag][after]++
			}
			countries[i].servers = append(countries[i].servers, trayServer{g.name, name, rest})
		}
	}
	if total < minCountryServers || len(countries) < 2 {
		return nil, nil
	}
	for i := range countries {
		c := &countries[i]
		c.name = flagCode(c.flag)
		best := 0
		for n, k := range names[c.flag] {
			if k > best || k == best && n < c.name {
				c.name, best = n, k
			}
		}
		seen := map[string]int{}
		for j := range c.servers {
			s := &c.servers[j]
			if before, after, ok := cutLast(s.label, "|"); ok && after == c.name && before != "" {
				s.label = before
			}
			seen[s.label]++
		}
		for j := range c.servers {
			if s := &c.servers[j]; seen[s.label] > 1 {
				s.label += " · " + s.group
			}
		}
	}
	slices.SortStableFunc(countries, func(a, b trayCountry) int {
		return cmp.Or(cmp.Compare(len(b.servers), len(a.servers)), cmp.Compare(a.name, b.name))
	})
	return countries, other
}

// splitFlag returns the flag emoji (two regional indicator letters) s
// starts with, and the rest of s, trimmed.
func splitFlag(s string) (flag, rest string) {
	a, n := utf8.DecodeRuneInString(s)
	b, m := utf8.DecodeRuneInString(s[n:])
	if !isRegional(a) || !isRegional(b) {
		return "", s
	}
	return s[:n+m], strings.TrimSpace(s[n+m:])
}

func isRegional(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

// flagCode turns a flag emoji back into its ISO country code.
func flagCode(flag string) string {
	var b strings.Builder
	for _, r := range flag {
		b.WriteRune('A' + r - 0x1F1E6)
	}
	return b.String()
}

// cutLast is strings.Cut at the last sep, with both halves trimmed.
func cutLast(s, sep string) (before, after string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+len(sep):]), true
}
