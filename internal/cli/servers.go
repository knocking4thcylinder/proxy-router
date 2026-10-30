package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/engine"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
	"github.com/knocking4thcylinder/proxy-router/internal/tun"
)

func addCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <link>... | -",
		Short: "Add servers from share links (vless://, vmess://, ss://, ...); '-' reads stdin",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			text := strings.Join(args, "\n")
			if len(args) == 1 && args[0] == "-" {
				data, err := io.ReadAll(bufio.NewReader(os.Stdin))
				if err != nil {
					return err
				}
				text = string(data)
			}
			servers, errs := share.ParseLinks(text)
			if strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "[") {
				servers, errs = share.ParseXrayJSON([]byte(text))
			}
			subscription.CleanServers(servers)
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "skipped: %s\n", clean(err.Error()))
			}
			if len(servers) == 0 {
				return fmt.Errorf("no servers added")
			}
			for _, s := range servers {
				s.Name = uniqueName(e.state.Manual, s.Name)
				e.state.Manual = append(e.state.Manual, s)
				for _, w := range s.Warnings {
					fmt.Fprintf(os.Stderr, "warning: %s: %s\n", s.Name, w)
				}
			}
			if _, ok := e.state.Current(); !ok {
				for _, entry := range e.state.Entries() {
					if entry.Group == config.ManualGroup {
						e.state.Select(entry)
						break
					}
				}
			}
			if err := e.state.Save(); err != nil {
				return err
			}
			fmt.Printf("added %d server(s)\n", len(servers))
			return nil
		},
	}
}

func uniqueName(existing []*share.Server, name string) string {
	taken := func(n string) bool {
		return slices.ContainsFunc(existing, func(s *share.Server) bool { return s.Name == n })
	}
	out := name
	for i := 2; taken(out); i++ {
		out = fmt.Sprintf("%s (%d)", name, i)
	}
	return out
}

func removeCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "remove <server>",
		Aliases:           []string{"rm"},
		Short:             "Remove a manually added server (use `sub remove` for subscriptions)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeManualServer,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			entry, err := e.state.Find(args[0])
			if err != nil {
				return err
			}
			if entry.Group != config.ManualGroup {
				return fmt.Errorf("%s comes from subscription %q; remove the subscription instead", entry, entry.Group)
			}
			if cur, ok := e.state.Current(); ok && cur.Group == entry.Group && cur.Server == entry.Server {
				e.state.Selected = nil
			}
			e.state.Manual = slices.DeleteFunc(e.state.Manual, func(s *share.Server) bool { return s == entry.Server })
			if err := e.state.Save(); err != nil {
				return err
			}
			fmt.Printf("removed %s\n", clean(entry.String()))
			return nil
		},
	}
}

func listCmd() *cobra.Command {
	var group string
	var verbose bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "servers"},
		Short:   "List servers (* marks the selected one)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			entries, err := e.state.GroupEntries(group)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("no servers; add a subscription with `proxy-router sub add <url>` or a link with `proxy-router add <link>`")
				return nil
			}
			cur, _ := e.state.Current()
			return writeServerList(cmd.OutOrStdout(), entries, cur.Index, verbose)
		},
	}
	cmd.Flags().StringVarP(&group, "group", "g", "", "only list this subscription (or manual)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show server warnings")
	_ = cmd.RegisterFlagCompletionFunc("group", completeGroups)
	return cmd
}

func writeServerList(w io.Writer, entries []config.Entry, current int, verbose bool) error {
	for start := 0; start < len(entries); {
		end := start + 1
		for end < len(entries) && entries[end].Group == entries[start].Group {
			end++
		}
		if start > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s (%d servers)\n", clean(entries[start].Group), end-start)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\t#\tNAME\tPROTOCOL\tADDRESS")
		for _, en := range entries[start:end] {
			mark := ""
			if en.Index == current {
				mark = "*"
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", mark, en.Index, clean(en.Server.Name), clean(describe(en.Server)), clean(address(en.Server)))
			if verbose {
				for _, warning := range en.Server.Warnings {
					fmt.Fprintf(tw, "\t\t  ! %s\n", clean(warning))
				}
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// describe summarises protocol/transport/security, e.g. "vless+xhttp+reality".
func describe(s *share.Server) string {
	if s.Pool != nil {
		return fmt.Sprintf("pool of %d", len(s.Pool.Members))
	}
	parts := []string{s.Protocol}
	var ob struct {
		StreamSettings struct {
			Network  string `json:"network"`
			Security string `json:"security"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(s.Outbound, &ob); err == nil {
		if n := ob.StreamSettings.Network; n != "" && n != "raw" && n != "tcp" && n != "hysteria" {
			parts = append(parts, n)
		}
		if sec := ob.StreamSettings.Security; sec != "" && sec != "none" && s.Protocol != "hysteria" {
			parts = append(parts, sec)
		}
	}
	return strings.Join(parts, "+")
}

func address(s *share.Server) string {
	if s.Port == 0 {
		return s.Address
	}
	if strings.Contains(s.Address, ":") {
		return fmt.Sprintf("[%s]:%d", s.Address, s.Port)
	}
	return fmt.Sprintf("%s:%d", s.Address, s.Port)
}

func useCmd() *cobra.Command {
	var fastest bool
	var group string
	cmd := &cobra.Command{
		Use:   "use <server> | --fastest",
		Short: "Select the server used by the \"proxy\" outbound (index, name, or group/name)",
		Long: `Select the server used by the "proxy" outbound.

<server> can be the index from "list", the exact name, "group/name", or a
unique part of the name. A running "proxy-router run" switches automatically.

--fastest downloads a test file through every server (ping.download_url)
and picks the one it arrives fastest through. A running proxy-router then
watches its connections to that server (auto_switch in config.yaml): when
they show trouble, such as data stopping mid-transfer, it checks the server
and moves to the fastest working one, within --group if given, if it
stopped carrying traffic. Selecting a server by name turns this off.`,
		ValidArgsFunction: completeSelectedServer,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			var entry config.Entry
			switch {
			case fastest:
				if len(args) > 0 {
					return fmt.Errorf("--fastest takes no server argument")
				}
				entries, err := e.state.GroupEntries(group)
				if err != nil {
					return err
				}
				if len(entries) == 0 {
					return fmt.Errorf("no servers to test")
				}
				fmt.Fprintf(os.Stderr, "testing %d servers...\n", len(entries))
				opts, note := e.pingOptions(16)
				if note != "" {
					fmt.Fprintln(os.Stderr, note)
				}
				results := engine.Ping(cmd.Context(), entries, opts)
				best, ok := pickFastest(results)
				if !ok {
					return fmt.Errorf("no server responded")
				}
				entry = best.Entry
				fmt.Printf("fastest: %s (%s)\n", clean(entry.String()), pingSummary(best))
			case len(args) == 1:
				if entry, err = e.state.FindInGroup(args[0], group); err != nil {
					return err
				}
			default:
				return fmt.Errorf("give a server or --fastest")
			}
			if fastest {
				e.state.SelectAuto(entry, group)
			} else {
				e.state.Select(entry)
			}
			if err := e.state.Save(); err != nil {
				return err
			}
			fmt.Printf("using %s\n", clean(entry.String()))
			if fastest && e.cfg.AutoSwitch.Enabled && e.cfg.Ping.DownloadURL != "" && entry.Server.Pool == nil {
				fmt.Printf("while running, proxy-router checks it %s and switches to the fastest working server if it fails\n", howChecked(e.cfg, entry.Server))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fastest, "fastest", false, "test all servers, pick the fastest, and switch automatically when it fails")
	cmd.Flags().StringVarP(&group, "group", "g", "", "only select from this subscription (or manual)")
	_ = cmd.RegisterFlagCompletionFunc("group", completeGroups)
	return cmd
}

func pingCmd() *cobra.Command {
	var (
		group    string
		parallel int
		exit     bool
		quiet    bool
	)
	cmd := &cobra.Command{
		Use:               "ping [server...]",
		Short:             "Measure real latency and download speed through servers; all by default",
		ValidArgsFunction: completeServers,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			entries, err := e.state.GroupEntries(group)
			if err != nil {
				return err
			}
			if len(args) > 0 {
				entries = nil
			}
			for _, a := range args {
				en, err := e.state.FindInGroup(a, group)
				if err != nil {
					return err
				}
				entries = append(entries, en)
			}
			if len(entries) == 0 {
				return fmt.Errorf("no servers to test")
			}
			opts, note := e.pingOptions(parallel)
			if note != "" {
				fmt.Fprintln(os.Stderr, note)
			}
			if exit {
				opts.ExitURL = "https://ipinfo.io/country"
			}
			var results []engine.PingResult
			if quiet {
				results = engine.Ping(cmd.Context(), entries, opts)
			} else {
				results = pingWithProgress(cmd.Context(), entries, opts, cmd.ErrOrStderr(), exit)
			}
			cur, hasCur := e.state.Current()
			current := 0
			if hasCur {
				current = cur.Index
			}
			return writePingResults(cmd.OutOrStdout(), results, current, exit)
		},
	}
	cmd.Flags().StringVarP(&group, "group", "g", "", "only test this subscription")
	cmd.Flags().IntVarP(&parallel, "parallel", "j", 16, "servers to test at once")
	cmd.Flags().BoolVar(&exit, "exit", false, "also show the country traffic really exits in (via ipinfo.io)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only print the final sorted results")
	_ = cmd.RegisterFlagCompletionFunc("group", completeGroups)
	return cmd
}

// pingOptions sets up testing servers, plus a note on how they're reached.
// They're tested directly, never through proxy-router's own TUN, which
// would measure the server it uses too: the TUN service hands out sockets
// that leave around it (see tun.ServeOutside).
func (e *env) pingOptions(parallel int) (engine.PingOptions, string) {
	o := engine.PingOptions{
		URL:         e.cfg.Ping.URL,
		Timeout:     e.cfg.Ping.Timeout.D(),
		Parallel:    parallel,
		PerEndpoint: e.cfg.Ping.PerEndpoint,
		DownloadURL: e.cfg.Ping.DownloadURL,
		Config:      e.cfg,
	}
	if own := e.ownTUN(); own != "" {
		path := outsidePath()
		err := tun.CheckOutside(path)
		if err == nil {
			err = engine.ControlSockets(tun.OutsideControl(path))
		}
		if err != nil {
			o.Resolve = e.resolverIf("")
			return o, fmt.Sprintf("TUN mode is on (%s), but its service can't let ping around it (%v); "+
				"servers are tested through it, and so through the server it uses", own, err)
		}
		// Server names are looked up around the TUN too (DoH dials through
		// Xray's dialer).
		o.Resolve = e.resolver("", 0)
		return o, fmt.Sprintf("TUN mode is on (%s); testing servers around it", own)
	}
	iface, note := e.outboundInterface()
	o.Interface, o.Resolve = iface, e.resolverIf(iface)
	return o, note
}

// pickFastest picks the best working result: the fastest download, else (no
// download measured) the lowest latency. A pool only if no single server
// works: its health check is a short request, which can't see a member
// that connects and then stalls, so it may keep using one.
func pickFastest(results []engine.PingResult) (engine.PingResult, bool) {
	best, found := engine.PingResult{}, false
	for _, r := range results {
		if r.Err == nil && (!found || better(r, best)) {
			best, found = r, true
		}
	}
	return best, found
}

// better reports whether a should be picked over b (both working).
func better(a, b engine.PingResult) bool {
	if ap, bp := a.Entry.Server.Pool != nil, b.Entry.Server.Pool != nil; ap != bp {
		return bp
	}
	if (a.Speed > 0) != (b.Speed > 0) {
		return a.Speed > 0
	}
	if a.Speed > 0 && a.Speed != b.Speed {
		return a.Speed > b.Speed
	}
	return a.Latency < b.Latency
}

// pingSummary is "4.2 Mbit/s, 120ms", or just the latency.
func pingSummary(r engine.PingResult) string {
	lat := r.Latency.Round(time.Millisecond).String()
	if r.Speed > 0 {
		return speedText(r.Speed) + ", " + lat
	}
	return lat
}

// speedText formats bytes per second as megabits, like speed tests do.
func speedText(bps float64) string {
	mbit := bps * 8 / 1e6
	if mbit < 10 {
		return fmt.Sprintf("%.1f Mbit/s", mbit)
	}
	return fmt.Sprintf("%.0f Mbit/s", mbit)
}

func (e *env) resolverIf(iface string) engine.Resolver {
	if iface == "" && !e.cfg.ResolveLocally {
		return nil
	}
	return e.resolver(iface, 0)
}

func shortErr(err error) string {
	s := clean(err.Error())
	if strings.Contains(s, "Client.Timeout") || strings.Contains(s, "deadline exceeded") {
		return "timeout"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
