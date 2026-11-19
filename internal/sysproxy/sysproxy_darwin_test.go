//go:build darwin

package sysproxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// stubSetup answers the get commands from canned output and records every
// set command, so the tests see what Set does without touching the system.
func stubSetup(t *testing.T, reply func(args []string) string) (*[]string, *[]string, func()) {
	t.Helper()
	oldRun, oldWarn := runSetup, warn
	var cmds, notes []string
	runSetup = func(args ...string) (string, error) {
		if strings.HasPrefix(args[0], "-set") {
			cmds = append(cmds, strings.Join(args, " "))
			return "", nil
		}
		if out := reply(args); out != "" {
			return out, nil
		}
		return "", errors.New("networksetup: unexpected " + strings.Join(args, " "))
	}
	warn = func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf(format, args...))
	}
	return &cmds, &notes, func() { runSetup, warn = oldRun, oldWarn }
}

func replyFor(services []string, pac map[string]string) func(args []string) string {
	return func(args []string) string {
		if args[0] == "-listallnetworkservices" {
			return "An asterisk (*) denotes that a network service is disabled.\n" + strings.Join(services, "\n")
		}
		svc := args[1]
		switch args[0] {
		case "-getautoproxyurl":
			if out, ok := pac[svc]; ok {
				return out
			}
			return "URL: \nEnabled: No"
		case "-getproxyautodiscovery":
			return "Auto Proxy Discovery: Off"
		default:
			return "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0"
		}
	}
}

func wantCmds(t *testing.T, cmds *[]string, want ...string) {
	t.Helper()
	if got := strings.Join(*cmds, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
}

func TestSetDisablesAndRestoresPAC(t *testing.T) {
	pac := map[string]string{"Wi-Fi": "URL: http://127.0.0.1:49899/proxy.pac\nEnabled: Yes"}
	cmds, notes, done := stubSetup(t, replyFor([]string{"Wi-Fi", "Ethernet"}, pac))
	defer done()

	restore, err := Set("", 0, "127.0.0.1", 10808)
	if err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"-setautoproxystate Wi-Fi off",
		"-setsocksfirewallproxy Wi-Fi 127.0.0.1 10808",
		"-setsocksfirewallproxy Ethernet 127.0.0.1 10808",
	)
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "Wi-Fi") {
		t.Fatalf("warnings: %v", *notes)
	}

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"-setautoproxystate Wi-Fi off",
		"-setsocksfirewallproxy Wi-Fi 127.0.0.1 10808",
		"-setsocksfirewallproxy Ethernet 127.0.0.1 10808",
		"-setsocksfirewallproxystate Wi-Fi off",
		"-setsocksfirewallproxystate Ethernet off",
		"-setautoproxyurl Wi-Fi http://127.0.0.1:49899/proxy.pac",
		"-setautoproxystate Wi-Fi on",
	)
}

func TestSetLeavesDisabledPACAlone(t *testing.T) {
	pac := map[string]string{"Wi-Fi": "URL: http://127.0.0.1:49899/proxy.pac\nEnabled: No"}
	cmds, notes, done := stubSetup(t, replyFor([]string{"Wi-Fi"}, pac))
	defer done()

	restore, err := Set("127.0.0.1", 10809, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"-setwebproxy Wi-Fi 127.0.0.1 10809",
		"-setsecurewebproxy Wi-Fi 127.0.0.1 10809",
	)
	if len(*notes) != 0 {
		t.Fatalf("nothing should have been warned about: %v", *notes)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	wantCmds(t, cmds,
		"-setwebproxy Wi-Fi 127.0.0.1 10809",
		"-setsecurewebproxy Wi-Fi 127.0.0.1 10809",
		"-setwebproxystate Wi-Fi off",
		"-setsecurewebproxystate Wi-Fi off",
	)
}

func TestDiscoveryFailureWarns(t *testing.T) {
	// An unreadable auto-discovery state must not be silent: WPAD left on
	// would keep shadowing the manual proxies, the exact failure this
	// exists to remove.
	_, notes, done := stubSetup(t, func(args []string) string {
		switch args[0] {
		case "-listallnetworkservices":
			return "legend\nWi-Fi"
		case "-getautoproxyurl":
			return "URL: \nEnabled: No"
		case "-getproxyautodiscovery":
			return "" // the stub errors on empty replies
		}
		return "Enabled: No\nServer: \nPort: 0"
	})
	defer done()

	if _, err := Set("", 0, "127.0.0.1", 10808); err != nil {
		t.Fatal(err)
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "auto-discovery") {
		t.Fatalf("warnings: %v", *notes)
	}
}

func TestCurrentPACAndDiscovery(t *testing.T) {
	p, err := currentPACFromOutput("URL: http://x/proxy.pac\nEnabled: Yes")
	if err != nil || !p.enabled || p.url != "http://x/proxy.pac" {
		t.Fatalf("got %+v, %v", p, err)
	}
	for out, want := range map[string]bool{
		"Auto Proxy Discovery: On":  true,
		"Auto Proxy Discovery: Off": false,
		"":                          false,
	} {
		if got := discoveryOn(out); got != want {
			t.Errorf("discoveryOn(%q) = %v", out, got)
		}
	}
}

// currentPACFromOutput reads a canned -getautoproxyurl reply without a
// service.
func currentPACFromOutput(out string) (pacSaved, error) {
	old := runSetup
	runSetup = func(args ...string) (string, error) { return out, nil }
	defer func() { runSetup = old }()
	return currentPAC("Wi-Fi")
}
