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
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "skipped: %v\n", err)
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
		Use:     "remove <server>",
		Aliases: []string{"rm"},
		Short:   "Remove a manually added server (use `sub remove` for subscriptions)",
		Args:    cobra.ExactArgs(1),
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
			fmt.Printf("removed %s\n", entry)
			return nil
		},
	}
}

func listCmd() *cobra.Command {
	var group string
	var verbose bool
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "servers"},
		Short:   "List servers (* marks the selected one)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			entries := filterGroup(e.state.Entries(), group)
			if len(entries) == 0 {
				fmt.Println("no servers; add a subscription with `proxy-router sub add <url>` or a link with `proxy-router add <link>`")
				return nil
			}
			cur, hasCur := e.state.Current()
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "\t#\tNAME\tGROUP\tPROTOCOL\tADDRESS")
			for _, en := range entries {
				mark := ""
				if hasCur && en.Index == cur.Index {
					mark = "*"
				}
				fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", mark, en.Index, en.Server.Name, en.Group, describe(en.Server), address(en.Server))
				if verbose {
					for _, w := range en.Server.Warnings {
						fmt.Fprintf(tw, "\t\t  ! %s\t\t\t\n", w)
					}
				}
			}
			return tw.Flush()
		},
	}
}

func filterGroup(entries []config.Entry, group string) []config.Entry {
	if group == "" {
		return entries
	}
	return slices.DeleteFunc(entries, func(e config.Entry) bool { return e.Group != group })
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
unique part of the name. A running "proxy-router run" switches automatically.`,
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
				entries := filterGroup(e.state.Entries(), group)
				if len(entries) == 0 {
					return fmt.Errorf("no servers to test")
				}
				fmt.Fprintf(os.Stderr, "testing %d servers...\n", len(entries))
				iface, note := e.outboundInterface()
				if note != "" {
					fmt.Fprintln(os.Stderr, note)
				}
				results := engine.Ping(cmd.Context(), entries, e.pingOptions(16, iface))
				best := -1
				for i, r := range results {
					if r.Err == nil && (best < 0 || r.Latency < results[best].Latency) {
						best = i
					}
				}
				if best < 0 {
					return fmt.Errorf("no server responded")
				}
				entry = results[best].Entry
				fmt.Printf("fastest: %s (%s)\n", entry, results[best].Latency.Round(time.Millisecond))
			case len(args) == 1:
				if entry, err = e.state.Find(args[0]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("give a server or --fastest")
			}
			e.state.Select(entry)
			if err := e.state.Save(); err != nil {
				return err
			}
			fmt.Printf("using %s\n", entry)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fastest, "fastest", false, "ping all servers and pick the fastest")
	cmd.Flags().StringVarP(&group, "group", "g", "", "with --fastest, only consider this subscription")
	return cmd
}

func pingCmd() *cobra.Command {
	var (
		group    string
		parallel int
		exit     bool
	)
	cmd := &cobra.Command{
		Use:   "ping [server...]",
		Short: "Measure real latency (full HTTP request) through servers; all by default",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			var entries []config.Entry
			if len(args) == 0 {
				entries = filterGroup(e.state.Entries(), group)
			}
			for _, a := range args {
				en, err := e.state.Find(a)
				if err != nil {
					return err
				}
				entries = append(entries, en)
			}
			if len(entries) == 0 {
				return fmt.Errorf("no servers to test")
			}
			iface, note := e.outboundInterface()
			if note != "" {
				fmt.Fprintln(os.Stderr, note)
			}
			opts := e.pingOptions(parallel, iface)
			if exit {
				opts.ExitURL = "https://ipinfo.io/country"
			}
			results := engine.Ping(cmd.Context(), entries, opts)
			slices.SortStableFunc(results, func(a, b engine.PingResult) int {
				switch {
				case a.Err != nil && b.Err != nil:
					return a.Entry.Index - b.Entry.Index
				case a.Err != nil:
					return 1
				case b.Err != nil:
					return -1
				}
				return int(a.Latency - b.Latency)
			})
			cur, hasCur := e.state.Current()
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			header := "\t#\tNAME\tGROUP\tLATENCY"
			if exit {
				header += "\tEXIT"
			}
			fmt.Fprintln(tw, header)
			for _, r := range results {
				mark := ""
				if hasCur && r.Entry.Index == cur.Index {
					mark = "*"
				}
				lat := r.Latency.Round(time.Millisecond).String()
				if r.Err != nil {
					lat = "failed: " + shortErr(r.Err)
				}
				if r.Members > 0 {
					lat = fmt.Sprintf("%s (%d/%d alive)", lat, r.Alive, r.Members)
				}
				line := fmt.Sprintf("%s\t%d\t%s\t%s\t%s", mark, r.Entry.Index, r.Entry.Server.Name, r.Entry.Group, lat)
				if exit {
					line += "\t" + r.Exit
				}
				fmt.Fprintln(tw, line)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&group, "group", "g", "", "only test this subscription")
	cmd.Flags().IntVarP(&parallel, "parallel", "j", 16, "servers to test at once")
	cmd.Flags().BoolVar(&exit, "exit", false, "also show the country traffic really exits in (via ipinfo.io)")
	return cmd
}

func (e *env) pingOptions(parallel int, iface string) engine.PingOptions {
	return engine.PingOptions{
		URL:         e.cfg.Ping.URL,
		Timeout:     e.cfg.Ping.Timeout.D(),
		Parallel:    parallel,
		PerEndpoint: e.cfg.Ping.PerEndpoint,
		Interface:   iface,
		Config:      e.cfg,
		Resolve:     e.resolverIf(iface),
	}
}

func (e *env) resolverIf(iface string) engine.Resolver {
	if iface == "" && !e.cfg.ResolveLocally {
		return nil
	}
	return e.resolver(iface)
}

func shortErr(err error) string {
	s := err.Error()
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
