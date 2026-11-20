package engine

import (
	"testing"

	xlog "github.com/xtls/xray-core/common/log"
)

type recordLog []xlog.Message

func (r *recordLog) Handle(m xlog.Message) { *r = append(*r, m) }

func TestWarningsOnly(t *testing.T) {
	var got recordLog
	h := warningsOnly{&got}
	for _, s := range []xlog.Severity{xlog.Severity_Debug, xlog.Severity_Info, xlog.Severity_Warning, xlog.Severity_Error, xlog.Severity_Unknown} {
		h.Handle(&xlog.GeneralMessage{Severity: s, Content: "x"})
	}
	h.Handle(&xlog.AccessMessage{})
	if len(got) != 2 {
		t.Fatalf("passed %d messages, want the warning and the error: %v", len(got), got)
	}
}

func TestDemoteTunNoise(t *testing.T) {
	var got recordLog
	h := demoteTunNoise{&got}
	// An app giving up on its own connection through the TUN logs this at
	// Error once per aborted connection; a dead tunnel turns it into a
	// flood. It must not reach the log at Error severity.
	h.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Error, Content: "connection was refused"})
	m := got[0].(*xlog.GeneralMessage)
	if m.Severity != xlog.Severity_Info {
		t.Errorf("gVisor abort kept %v severity", m.Severity)
	}
	// Everything else is untouched, including real errors and access.
	got = nil
	for _, c := range []any{"failed to dial tcp 1.2.3.4:443", 42} {
		h.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Error, Content: c})
	}
	h.Handle(&xlog.AccessMessage{})
	if len(got) != 3 {
		t.Fatalf("forwarded %d messages, want all three: %v", len(got), got)
	}
	if m, ok := got[0].(*xlog.GeneralMessage); !ok || m.Content != "failed to dial tcp 1.2.3.4:443" {
		t.Errorf("first message not the dial error: %v", got[0])
	}
	if m, ok := got[1].(*xlog.GeneralMessage); !ok || m.Content != 42 {
		t.Errorf("second message not the non-string error: %v", got[1])
	}
	if _, ok := got[2].(*xlog.AccessMessage); !ok {
		t.Errorf("third message not the access record: %v", got[2])
	}
}
