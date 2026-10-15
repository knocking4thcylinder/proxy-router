package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/safetext"
)

// pingWithProgress owns all terminal writes, including the timer, so concurrent
// probes cannot interleave lines. The final table goes to stdout separately.
func pingWithProgress(ctx context.Context, entries []config.Entry, opts engine.PingOptions, out io.Writer, exit bool) []engine.PingResult {
	updates := make(chan engine.PingProgress)
	finished := make(chan []engine.PingResult, 1)
	opts.OnProgress = func(p engine.PingProgress) { updates <- p }
	p := pingDisplay{out: out, total: len(entries), exit: exit, start: time.Now()}
	if os.Getenv("TERM") != "dumb" {
		p.width = pingTerminalWidth(out)
	}
	fmt.Fprintf(out, "Testing %d servers (HTTP request through each proxy)", len(entries))
	if exit {
		fmt.Fprint(out, "; checking exit countries")
	}
	fmt.Fprintln(out, "...")
	p.draw()
	go func() { finished <- engine.Ping(ctx, entries, opts) }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case update := <-updates:
			p.update(update)
		case <-ticker.C:
			p.draw()
		case results := <-finished:
			p.clear()
			fmt.Fprintf(out, "Done in %.1fs: %d reachable, %d failed.\n\n", time.Since(p.start).Seconds(), p.ok, p.failed)
			return results
		}
	}
}

type pingDisplay struct {
	out                            io.Writer
	width, total, done, ok, failed int
	completed, probes              int
	exit                           bool
	start                          time.Time
}

func (p *pingDisplay) update(u engine.PingProgress) {
	p.completed, p.probes = u.Completed, u.Total
	if u.EntryDone {
		p.done++
		status := "OK"
		if u.Result.Err == nil {
			p.ok++
		} else {
			p.failed++
			status = "FAIL"
		}
		p.clear()
		r := u.Result
		fmt.Fprintf(p.out, "[%d/%d] %-4s #%d %s | %s", p.done, p.total, status, r.Entry.Index, pingText(r.Entry.Server.Name), pingLatency(r))
		if r.Members > 0 {
			fmt.Fprintf(p.out, " | %d/%d alive", r.Alive, r.Members)
		}
		if p.exit {
			fmt.Fprintf(p.out, " | exit: %s", pingExit(r))
		}
		fmt.Fprintln(p.out)
	}
	p.draw()
}

func (p *pingDisplay) clear() {
	if p.width > 0 {
		fmt.Fprint(p.out, "\r\x1b[2K")
	}
}

func (p *pingDisplay) draw() {
	if p.width <= 0 {
		return
	}
	elapsed := time.Since(p.start)
	spinner := "|/-\\"[int(elapsed/(100*time.Millisecond))%4]
	status := fmt.Sprintf("%c %d/%d servers | %d reachable, %d failed | %.1fs", spinner, p.done, p.total, p.ok, p.failed, elapsed.Seconds())
	if p.probes > p.total {
		status += fmt.Sprintf(" | %d/%d probes", p.completed, p.probes)
	}
	// Leave the last column unused so the status never wraps onto another line.
	if len(status) >= p.width {
		status = fmt.Sprintf("%c %d/%d servers | %.1fs", spinner, p.done, p.total, elapsed.Seconds())
		if len(status) >= p.width {
			status = status[:p.width-1]
		}
	}
	p.clear()
	fmt.Fprint(p.out, status)
}

func writePingResults(out io.Writer, results []engine.PingResult, current int, exit bool) error {
	slices.SortStableFunc(results, func(a, b engine.PingResult) int {
		switch {
		case a.Err != nil && b.Err != nil:
			return a.Entry.Index - b.Entry.Index
		case a.Err != nil:
			return 1
		case b.Err != nil:
			return -1
		}
		return cmp.Compare(a.Latency, b.Latency)
	})
	pool := slices.ContainsFunc(results, func(r engine.PingResult) bool { return r.Members > 0 })
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Results (fastest first; * selected)")
	header := "\t#\tNAME\tGROUP\tLATENCY"
	if pool {
		header += "\tPOOL"
	}
	if exit {
		header += "\tEXIT COUNTRY"
	}
	fmt.Fprintln(tw, header)
	for _, r := range results {
		mark := ""
		if r.Entry.Index == current {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s", mark, r.Entry.Index, pingText(r.Entry.Server.Name), pingText(r.Entry.Group), pingLatency(r))
		if pool {
			members := "-"
			if r.Members > 0 {
				members = fmt.Sprintf("%d/%d alive", r.Alive, r.Members)
			}
			fmt.Fprintf(tw, "\t%s", members)
		}
		if exit {
			fmt.Fprintf(tw, "\t%s", pingExit(r))
		}
		fmt.Fprintln(tw)
	}
	if pool {
		fmt.Fprintln(tw, "\nPools show the latency and exit of their fastest responding member.")
	}
	return tw.Flush()
}

func pingLatency(r engine.PingResult) string {
	if r.Err != nil {
		return "failed: " + pingText(shortErr(r.Err))
	}
	return r.Latency.Round(time.Millisecond).String()
}

func pingExit(r engine.PingResult) string {
	if r.Err != nil {
		return "-"
	}
	code := strings.ToUpper(strings.TrimSpace(r.Exit))
	if len(code) == 2 {
		if region, err := language.ParseRegion(code); err == nil && region.IsCountry() {
			return fmt.Sprintf("%s (%s)", display.English.Regions().Name(region), code)
		}
	}
	return "unknown (lookup failed)"
}

// Subscription labels and remote error text must stay on one terminal line.
func pingText(s string) string { return safetext.Clean(s, 0) }
