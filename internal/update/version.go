package update

import (
	"strconv"
	"strings"
)

// Compare compares two version strings: -1 if a is older than b, 0 if they
// are the same release (or both aren't releases), and 1 if a is newer.
//
// A release is "v1.2.3", optionally with a prerelease ("v1.2.3-rc1") and
// build metadata ("v1.2.3+abc"). Versions that don't parse ("dev-abc123",
// the commit of a local build) sort before every release, so a local build
// is always offered the latest release.
func Compare(a, b string) int {
	va, oka := parseVersion(a)
	vb, okb := parseVersion(b)
	switch {
	case !oka && !okb:
		return 0
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := range va.nums {
		switch {
		case va.nums[i] < vb.nums[i]:
			return -1
		case va.nums[i] > vb.nums[i]:
			return 1
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1
	case len(vb.pre) == 0:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		if c := compareIdentifier(va.pre[i], vb.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(va.pre) < len(vb.pre):
		return -1
	case len(va.pre) > len(vb.pre):
		return 1
	}
	return 0
}

// IsRelease reports whether v is a release version, as opposed to the
// "dev-<commit>" of a build that wasn't made from a release.
func IsRelease(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

// NormalizeTag turns "0.1.0" into "v0.1.0"; other tags are returned as is.
func NormalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if tag[0] >= '0' && tag[0] <= '9' {
		return "v" + tag
	}
	return tag
}

type version struct {
	nums [3]int
	pre  []string
}

// parseVersion accepts an optional "v", one to three numeric components
// and an optional prerelease and build metadata.
func parseVersion(v string) (version, bool) {
	var out version
	v = strings.TrimSpace(v)
	if v == "" {
		return out, false
	}
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		if i == len(v)-1 {
			return out, false
		}
		out.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
		for _, p := range out.pre {
			if p == "" {
				return out, false
			}
		}
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		if !allDigits(p) {
			return out, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out.nums[i] = n
	}
	return out, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// compareIdentifier compares two prerelease identifiers per semver: numeric
// identifiers compare as numbers, numeric sorts before alphanumeric, and
// alphanumeric ones compare as strings.
func compareIdentifier(a, b string) int {
	na, nb := allDigits(a), allDigits(b)
	switch {
	case na && nb:
		x, _ := strconv.Atoi(a)
		y, _ := strconv.Atoi(b)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case na:
		return -1
	case nb:
		return 1
	}
	return strings.Compare(a, b)
}
