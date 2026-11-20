package engine

import (
	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

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

// demoteTunNoise re-files gVisor's TUN handshake aborts at Info: a client
// that gives up on its own connection (an app retrying through a tunnel
// whose server just died) logs "connection was refused" once per aborted
// connection, which drowns the messages that matter — the server dial
// failures themselves. At Info, the usual log levels drop them again.
type demoteTunNoise struct{ next xlog.Handler }

func (h demoteTunNoise) Handle(msg xlog.Message) {
	if m, ok := msg.(*xlog.GeneralMessage); ok && m.Severity == xlog.Severity_Error {
		if s, ok := m.Content.(string); ok && s == "connection was refused" {
			m.Severity = xlog.Severity_Info
		}
	}
	h.next.Handle(msg)
}

// demoteNoise wraps the instance's own log handler, which app/log installs
// globally on every start, displacing whatever was registered before —
// including a previous wrap. So it is re-applied after each start; between
// an instance closing and the next one starting, the stale wrap points at
// an inactive handler and messages drop, exactly as they would have.
func demoteNoise(inst *core.Instance) {
	if l, ok := inst.GetFeature((*applog.Instance)(nil)).(xlog.Handler); ok {
		xlog.RegisterHandler(demoteTunNoise{l})
	}
}
