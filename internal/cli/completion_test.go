package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func shellCompletions(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	previousDir := flagDir
	t.Cleanup(func() { flagDir = previousDir })
	root := newRootCmd(append([]string{cobra.ShellCompRequestCmd}, args...))
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	if err := root.Execute(); err != nil {
		t.Fatalf("completion %q: %v (%s)", args, err, &stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	directiveLine := lines[len(lines)-1]
	directive, err := strconv.Atoi(strings.TrimPrefix(directiveLine, ":"))
	if !strings.HasPrefix(directiveLine, ":") || err != nil {
		t.Fatalf("completion %q returned invalid protocol: %q", args, &stdout)
	}
	var values []string
	for _, line := range lines[:len(lines)-1] {
		value, _, _ := strings.Cut(line, "\t")
		values = append(values, value)
	}
	return values, cobra.ShellCompDirective(directive)
}

func completionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PROXY_ROUTER_HOME", dir)
	state, err := config.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	state.Subscriptions = []*config.Subscription{
		{Name: "My VPN", URL: "https://example.invalid/secret", Servers: []*share.Server{
			{Name: "Germany"}, {Name: "Shared"},
		}},
		{Name: "Other", Servers: []*share.Server{{Name: "Shared"}, {Name: "🇫🇮 Helsinki"}}},
		{Name: "Empty"},
	}
	state.Manual = []*share.Server{{Name: "Local proxy"}, {Name: "bad\nname"}}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCommandFlagCompletions(t *testing.T) {
	t.Setenv("PROXY_ROUTER_HOME", t.TempDir())
	for _, tc := range []struct {
		command []string
		flags   []string
	}{
		{nil, []string{"--dir", "--help", "--version"}},
		{[]string{"run"}, []string{"--rules", "--server", "--system-proxy", "--no-update", "--verbose", "--tun", "--no-tun", "--force"}},
		{[]string{"start"}, []string{"--tun", "--no-tun", "--force", "--verbose"}},
		{[]string{"restart"}, []string{"--tun", "--no-tun", "--force", "--verbose"}},
		{[]string{"config"}, []string{"--rules", "--server", "--quiet", "--tun"}},
		{[]string{"ping"}, []string{"--group", "--parallel", "--exit", "--quiet"}},
		{[]string{"use"}, []string{"--fastest", "--group"}},
		{[]string{"list"}, []string{"--group", "--verbose"}},
		{[]string{"logs"}, []string{"--follow", "--lines"}},
		{[]string{"init"}, []string{"--force"}},
		{[]string{"sub", "add"}, []string{"--name", "--user-agent", "--header", "--hwid"}},
		{[]string{"sub", "list"}, []string{"--show-url"}},
		{[]string{"completion", "fish"}, []string{"--no-descriptions"}},
	} {
		for _, prefix := range []string{"", "--"} {
			t.Run(strings.Join(tc.command, "/")+"/"+prefix, func(t *testing.T) {
				values, directive := shellCompletions(t, append(slices.Clone(tc.command), prefix)...)
				for _, flag := range append(slices.Clone(tc.flags), "--dir") {
					if !slices.Contains(values, flag) {
						t.Errorf("missing %s in %v", flag, values)
					}
				}
				if slices.Contains(values, "--service") || directive != cobra.ShellCompDirectiveNoFileComp {
					t.Errorf("hidden flag or incorrect directive: %v, %v", values, directive)
				}
			})
		}
	}
	values, _ := shellCompletions(t, "run", "-")
	for _, short := range []string{"-r", "-s", "-v", "-h"} {
		if !slices.Contains(values, short) {
			t.Errorf("missing short flag %s in %v", short, values)
		}
	}
}

func TestContextualCompletions(t *testing.T) {
	completionFixture(t)
	for _, tc := range []struct {
		args    []string
		want    []string
		notWant []string
	}{
		{[]string{"use", ""}, []string{"1", "My VPN/Germany", "Germany", "Other/🇫🇮 Helsinki", "manual/Local proxy"}, []string{"Shared"}},
		{[]string{"use", "Ger"}, []string{"Germany"}, []string{"My VPN/Germany", "--fastest"}},
		{[]string{"use", "#"}, []string{"#1", "#5", "#6"}, []string{"1"}},
		{[]string{"use", "1", ""}, []string{"--fastest"}, []string{"Germany", "manual/Local proxy"}},
		{[]string{"use", "--fastest", ""}, []string{"--group"}, []string{"Germany", "1", "--fastest"}},
		{[]string{"ping", "Germany", ""}, []string{"My VPN/Shared", "Local proxy"}, []string{"1", "Germany", "My VPN/Germany"}},
		{[]string{"run", "--server", "My"}, []string{"My VPN/Germany", "My VPN/Shared"}, []string{"Germany", "--rules"}},
		{[]string{"config", "-s", "Loc"}, []string{"Local proxy"}, []string{"manual/Local proxy"}},
		{[]string{"run", "--server=Ger"}, []string{"Germany"}, nil},
		{[]string{"remove", ""}, []string{"5", "Local proxy", "manual/Local proxy"}, []string{"Germany", "1", "My VPN/Germany", "bad\nname"}},
		{[]string{"rm", "Loc"}, []string{"Local proxy"}, nil},
		{[]string{"remove", "5", ""}, []string{"--dir"}, []string{"Local proxy"}},
		{[]string{"sub", "remove", ""}, []string{"My VPN", "Other", "Empty"}, []string{"manual", "Germany"}},
		{[]string{"subscription", "rm", "My"}, []string{"My VPN"}, nil},
		{[]string{"sub", "remove", "Other", ""}, []string{"--dir"}, []string{"My VPN", "Other"}},
		{[]string{"sub", "update", "Other", ""}, []string{"My VPN", "Empty"}, []string{"Other"}},
		{[]string{"ping", "-g", ""}, []string{"My VPN", "Other", "Empty", "manual"}, []string{"Germany"}},
		{[]string{"use", "--group=My"}, []string{"My VPN"}, []string{"Other"}},
		{[]string{"ls", "--group", "man"}, []string{"manual"}, nil},
		{[]string{"run", "--tun", ""}, []string{"--rules"}, []string{"--tun", "--no-tun"}},
		{[]string{"start", "--no-tun", "--"}, []string{"--verbose"}, []string{"--tun", "--no-tun"}},
		{[]string{"sub", "add", "--header", "A: b", ""}, []string{"--header", "-H"}, nil},
		{[]string{"sub", "add", "--header", "--", ""}, []string{"--header", "--hwid"}, nil},
		{[]string{"run", "-v", ""}, []string{"--verbose", "-v"}, nil},
		{[]string{"run", "--", ""}, nil, []string{"--rules", "--dir", "-r"}},
	} {
		t.Run(strings.Join(tc.args, "/"), func(t *testing.T) {
			values, directive := shellCompletions(t, tc.args...)
			for _, want := range tc.want {
				if !slices.Contains(values, want) {
					t.Errorf("missing %q in %v", want, values)
				}
			}
			for _, notWant := range tc.notWant {
				if slices.Contains(values, notWant) {
					t.Errorf("unexpected %q in %v", notWant, values)
				}
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Errorf("directive = %v, want no files", directive)
			}
		})
	}
}

func TestCompletionFileDirectives(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want cobra.ShellCompDirective
	}{
		{[]string{"--dir", ""}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace},
		{[]string{"run", "--dir", ""}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace},
		{[]string{"run", "--rules", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"config", "-r", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"logs", "--lines", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"ping", "-j", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"sub", "add", "--name", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"sub", "add", "--header", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"sub", "add", "--user-agent", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"add", "vless://"}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"sub", "add", "https://"}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"status", ""}, cobra.ShellCompDirectiveNoFileComp},
	} {
		t.Run(strings.Join(tc.args, "/"), func(t *testing.T) {
			_, got := shellCompletions(t, tc.args...)
			if got != tc.want {
				t.Errorf("directive = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDirectoryCompletions(t *testing.T) {
	dir := t.TempDir()
	sep := string(filepath.Separator)
	wantDirs := []string{"config", "config with spaces"}
	for _, name := range []string{"config", "config with spaces", ".hidden"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "config"), filepath.Join(dir, "config-link")); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
	} else {
		wantDirs = append(wantDirs, "config-link")
	}
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	for _, prefix := range []string{dir + sep, "~" + sep} {
		values, directive := shellCompletions(t, "run", "--dir", prefix)
		for _, name := range wantDirs {
			if !slices.Contains(values, prefix+name+sep) {
				t.Errorf("missing %q in %v", prefix+name+sep, values)
			}
		}
		if len(values) != len(wantDirs) || directive != cobra.ShellCompDirectiveNoFileComp|cobra.ShellCompDirectiveNoSpace {
			t.Errorf("directory completion = %v, %v", values, directive)
		}
	}
	values, _ := shellCompletions(t, "--dir", dir+sep+".h")
	if !slices.Equal(values, []string{dir + sep + ".hidden" + sep}) {
		t.Errorf("hidden directory completion = %v", values)
	}
	values, _ = shellCompletions(t, "--dir="+dir+sep+"config with")
	if !slices.Equal(values, []string{dir + sep + "config with spaces" + sep}) {
		t.Errorf("equal-form directory completion = %v", values)
	}
	values, directive := shellCompletions(t, "--dir", filepath.Join(dir, "missing")+sep)
	if len(values) != 0 || directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Errorf("missing directory completion = %v, %v", values, directive)
	}
}

func TestFishDirectoryCompletionWithEquals(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("requires Fish and a POSIX shell")
	}
	dir := t.TempDir()
	// Feed the generated adapter a single directory result, the case in which
	// Fish must preserve the trailing slash without treating --dir= as an option.
	program := "#!/bin/sh\nprintf '%s\\n' \"$TEST_COMPLETION_DIRECTORY/config/\" ':6'\n"
	if err := os.WriteFile(filepath.Join(dir, "proxy-router"), []byte(program), 0o755); err != nil {
		t.Fatal(err)
	}
	previousDir := flagDir
	t.Cleanup(func() { flagDir = previousDir })
	root := newRootCmd([]string{"completion", "fish"})
	var script bytes.Buffer
	root.SetOut(&script)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "completion.fish")
	if err := os.WriteFile(path, script.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(fish, "--no-config", "-c", `source "$TEST_COMPLETION_SCRIPT"; complete -C "proxy-router --dir=$TEST_COMPLETION_DIRECTORY/co"`)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "TEST_COMPLETION_SCRIPT="+path, "TEST_COMPLETION_DIRECTORY="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Fish completion failed: %v\n%s", err, out)
	}
	value, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if value != "--dir="+dir+"/config/" {
		t.Fatalf("Fish directory completion = %q", out)
	}
}

func TestCompletionUsesSelectedConfigDirectoryWithoutWriting(t *testing.T) {
	dir := completionFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_ROUTER_HOME", filepath.Join(t.TempDir(), "missing"))
	values, _ := shellCompletions(t, "--dir", dir, "use", "Ger")
	if !slices.Contains(values, "Germany") {
		t.Fatalf("--dir did not select cached state: %v", values)
	}
	values, _ = shellCompletions(t, "run", "--dir", dir, "--server", "Ger")
	if !slices.Contains(values, "Germany") {
		t.Fatalf("trailing --dir did not select cached state: %v", values)
	}
	after, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("completion changed state: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "state.json" {
		t.Fatalf("completion created files: %v (%v)", files, err)
	}
	for _, args := range [][]string{{"use", ""}, {"ping", "--group", ""}, {"sub", "update", ""}} {
		_, directive := shellCompletions(t, args...)
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Fatalf("missing state fell back to files: %v", directive)
		}
	}
	if _, err := os.Stat(os.Getenv("PROXY_ROUTER_HOME")); !os.IsNotExist(err) {
		t.Fatalf("completion initialized config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, directive := shellCompletions(t, "--dir", dir, "use", "Ger")
	if len(values) != 0 || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("bad state completion = %v, %v", values, directive)
	}
}
