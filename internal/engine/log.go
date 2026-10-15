package engine

import xlog "github.com/xtls/xray-core/common/log"

// Xray's default log handler writes every message, debug included, to
// stdout until an instance installs the log settings from its config.
// Before that (pinning server names, building configs) only warnings and
// errors are worth showing, and stdout is where "config" prints the
// generated config, so they go to stderr.
func init() {
	xlog.RegisterHandler(warningsOnly{xlog.NewLogger(xlog.CreateStderrLogWriter())})
}

// warningsOnly passes general messages of Warning severity or worse to next
// and drops the rest (debug, info, access).
type warningsOnly struct{ next xlog.Handler }

func (h warningsOnly) Handle(msg xlog.Message) {
	if m, ok := msg.(*xlog.GeneralMessage); ok && m.Severity != xlog.Severity_Unknown && m.Severity <= xlog.Severity_Warning {
		h.next.Handle(msg)
	}
}
