package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

func TestServerListSections(t *testing.T) {
	entries := []config.Entry{
		{Index: 1, Group: "First", Server: &share.Server{Name: "One"}},
		{Index: 2, Group: "Second", Server: &share.Server{Name: "Two", Warnings: []string{"warning text"}}},
	}
	var out bytes.Buffer
	if err := writeServerList(&out, entries, 2, true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.HasPrefix(text, "First (1 servers)\n") || !strings.Contains(text, "\n\nSecond (1 servers)\n") || !strings.Contains(text, "*  2") || !strings.Contains(text, "warning text") {
		t.Fatalf("unexpected list:\n%s", text)
	}
}

func TestScopedServerCompletion(t *testing.T) {
	dir := completionFixture(t)
	for _, command := range []string{"use", "ping"} {
		values, _ := shellCompletions(t, "--dir", dir, command, "--group", "Other", "")
		joined := strings.Join(values, "\n")
		if strings.Contains(joined, "My VPN/") || strings.Contains(joined, "Local proxy") || !strings.Contains(joined, "Other/Shared") {
			t.Fatalf("%s completions: %v", command, values)
		}
	}
}
