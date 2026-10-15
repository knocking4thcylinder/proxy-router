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
