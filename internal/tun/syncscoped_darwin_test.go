//go:build darwin

package tun

import (
	"errors"
	"strings"
	"testing"
)

// stubScoped points the netif lookups at canned answers and records every
// command, so the tests see what syncScoped does without touching the
// system. It returns the recorded commands and puts everything back.
func stubScoped(t *testing.T, up func(family, exclude string) (string, string, error), scoped func(family, iface string) ([]string, error)) (*[]string, func()) {
	t.Helper()
	oldUp, oldScoped, oldRun := uplink, scopedDefaults, runTool
	uplink, scopedDefaults = up, scoped
	var cmds []string
	runTool = func(stdin, name string, args ...string) (string, error) {
		cmds = append(cmds, strings.Join(append([]string{name}, args...), " "))
		return "", nil
	}
	mu.Lock()
	savedAdded := added
	added = map[string]scopedDefault{}
	mu.Unlock()
	return &cmds, func() {
		uplink, scopedDefaults, runTool = oldUp, oldScoped, oldRun
		mu.Lock()
		added = savedAdded
		mu.Unlock()
	}
}

// en0Only answers for an IPv4 uplink only, like a network without IPv6.
func en0Only(gw string) func(family, exclude string) (string, string, error) {
	return func(family, exclude string) (string, string, error) {
		if family == "inet6" {
			return "", "", errors.New("no inet6 default route")
		}
		return "en0", gw, nil
	}
}

func wantCmds(t *testing.T, cmds *[]string, want ...string) {
	t.Helper()
	if got := strings.Join(*cmds, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
}

func TestSyncScopedReaddsVanishedRoute(t *testing.T) {
	// macOS dropped the route on sleep/wake, but the in-memory record
	// still claims it's there: the Sync must notice and re-add it.
	cmds, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return nil, nil // nothing scoped to en0 anymore
	})
	defer done()
	mu.Lock()
	added["inet"] = scopedDefault{"en0", "192.168.1.10"}
	mu.Unlock()

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds, "route -q -n add -inet default 192.168.1.10 -ifscope en0")
}

func TestSyncScopedReplacesStaleGateway(t *testing.T) {
	// A crashed run left a scoped default with the old gateway: it must
	// be deleted, not trusted ("File exists" used to leave it alone).
	cmds, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return []string{"192.168.1.1"}, nil
	})
	defer done()

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"route -q -n delete -inet default 192.168.1.1 -ifscope en0",
		"route -q -n add -inet default 192.168.1.10 -ifscope en0",
	)
	mu.Lock()
	got := added["inet"]
	mu.Unlock()
	if got != (scopedDefault{"en0", "192.168.1.10"}) {
		t.Fatalf("added = %+v, want the verified route", got)
	}
}

func TestSyncScopedVerifiesWithoutReadding(t *testing.T) {
	// The route is there with the current gateway: no commands, even
	// though the memory said otherwise (a crashed run's route, taken over
	// so Down will remove it).
	cmds, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return []string{"192.168.1.10"}, nil
	})
	defer done()

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds) // nothing to do
	mu.Lock()
	_, recorded := added["inet"]
	mu.Unlock()
	if !recorded {
		t.Fatal("the verified route wasn't recorded; Down couldn't remove it")
	}
}

func TestSyncScopedFollowsInterfaceSwitch(t *testing.T) {
	// Wi-Fi <-> Ethernet: the old interface's route goes, the new one's
	// is added. (syncScoped returns after recording, so the delete of the
	// old route shows up before the new add.)
	up := func(family, exclude string) (string, string, error) {
		if family == "inet6" {
			return "", "", errors.New("no inet6 default route")
		}
		return "en1", "10.0.0.1", nil
	}
	cmds, done := stubScoped(t, up, func(family, iface string) ([]string, error) {
		return nil, nil
	})
	defer done()
	mu.Lock()
	added["inet"] = scopedDefault{"en0", "192.168.1.10"}
	mu.Unlock()

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"route -q -n delete -inet default 192.168.1.10 -ifscope en0",
		"route -q -n add -inet default 10.0.0.1 -ifscope en1",
	)
}

func TestSyncScopedKeepsIP6Uplink(t *testing.T) {
	up := func(family, exclude string) (string, string, error) {
		switch family {
		case "inet":
			return "en0", "192.168.1.10", nil
		case "inet6":
			return "en0", "fe80::1%en0", nil
		}
		return "", "", errors.New("no " + family + " default route")
	}
	scoped := func(family, iface string) ([]string, error) {
		if family == "inet6" {
			return []string{"fe80::1%en0"}, nil
		}
		return nil, nil
	}
	cmds, done := stubScoped(t, up, scoped)
	defer done()

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds, "route -q -n add -inet default 192.168.1.10 -ifscope en0")
}

func TestRemoveStaleScopedLeavesMatchingRoute(t *testing.T) {
	cmds, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return []string{"192.168.1.1", "192.168.1.10"}, nil
	})
	defer done()

	removeStaleScoped()
	wantCmds(t, cmds, "route -q -n delete -inet default 192.168.1.1 -ifscope en0")
}

func TestSyncScopedToleratesExistingRoute(t *testing.T) {
	// The netstat raced a concurrent change: nothing scoped was seen, but
	// the add reports File exists anyway. Tolerated, and recorded for
	// Down; the next Sync verifies it.
	_, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return nil, nil
	})
	defer done()
	runTool = func(stdin, name string, args ...string) (string, error) {
		err := errors.New("route: writing to routing socket: File exists")
		return err.Error(), err
	}

	if err := syncScoped("utun99"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := added["inet"]
	mu.Unlock()
	if got != (scopedDefault{"en0", "192.168.1.10"}) {
		t.Fatalf("added = %+v, want the tolerated route", got)
	}
}

func TestSyncScopedFailsLoudlyWhenNetstatFails(t *testing.T) {
	// An unread route table must not become a made-up "nothing scoped":
	// that's the silent path that kept crash leftovers invisible. Sync
	// errors, nothing is recorded, the next one retries.
	cmds, done := stubScoped(t, en0Only("192.168.1.10"), func(family, iface string) ([]string, error) {
		return nil, errors.New("netstat: sysctl failed")
	})
	defer done()

	err := syncScoped("utun99")
	if err == nil || !strings.Contains(err.Error(), "scoped to en0") {
		t.Fatalf("err = %v, want the netstat failure", err)
	}
	wantCmds(t, cmds)
	mu.Lock()
	_, recorded := added["inet"]
	mu.Unlock()
	if recorded {
		t.Fatal("nothing may be recorded from a failed verification")
	}
}
