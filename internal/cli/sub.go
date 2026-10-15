package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/safetext"
	"github.com/knocking4thcylinder/proxy-router/internal/subscription"
)

func subCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sub",
		Aliases: []string{"subs", "subscription"},
		Short:   "Manage subscriptions",
	}
	cmd.AddCommand(subAddCmd(), subListCmd(), subUpdateCmd(), subRemoveCmd())
	return cmd
}

func subAddCmd() *cobra.Command {
	var (
		name, ua        string
		headers         []string
		hwid, allowHTTP bool
	)
	cmd := &cobra.Command{
		Use:   "add <url>",
		Short: "Add a subscription URL and fetch its servers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			sub := &config.Subscription{URL: args[0], UserAgent: ua, SendHWID: hwid, AllowHTTP: allowHTTP}
			for _, h := range headers {
				k, v, ok := strings.Cut(h, ":")
				if !ok {
					return fmt.Errorf("--header %q: expected Name: value", h)
				}
				if sub.Headers == nil {
					sub.Headers = map[string]string{}
				}
				sub.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
			if err := e.updateSubscription(cmd.Context(), sub); err != nil {
				return err
			}
			sub.Name = name
			if sub.Name == "" {
				sub.Name = defaultSubName(sub, e.state)
			}
			if e.state.Subscription(sub.Name) != nil {
				return fmt.Errorf("a subscription named %q already exists; pass --name", sub.Name)
			}
			e.state.Subscriptions = append(e.state.Subscriptions, sub)
			selected := false
			if _, ok := e.state.Current(); !ok {
				for _, entry := range e.state.Entries() {
					if entry.Group == sub.Name {
						e.state.Select(entry)
						selected = true
						break
					}
				}
			}
			if err := e.state.Save(); err != nil {
				return err
			}
			fmt.Printf("added subscription %q with %d servers\n", sub.Name, len(sub.Servers))
			if selected {
				cur, _ := e.state.Current()
				fmt.Printf("selected %s (change with `proxy-router use`)\n", clean(cur.String()))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "name for the subscription (default: provider title or host)")
	cmd.Flags().StringVar(&ua, "user-agent", "", "User-Agent to send (default from config.yaml)")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, `extra request header, e.g. -H "Authorization: Bearer x" (repeatable)`)
	cmd.Flags().BoolVar(&hwid, "hwid", false, "send a device ID (x-hwid) for panels with device limits")
	cmd.Flags().BoolVar(&allowHTTP, "allow-http", false, "accept a plain http:// URL (anyone on the network can then change your servers)")
	return cmd
}

func defaultSubName(sub *config.Subscription, state *config.State) string {
	base := sub.Info.Title
	if base == "" {
		if u, err := url.Parse(sub.URL); err == nil {
			base = u.Hostname()
		}
	}
	base = strings.ReplaceAll(strings.TrimSpace(base), "/", "-")
	if base == "" || base == config.ManualGroup {
		base = "sub"
	}
	name := base
	for i := 2; state.Subscription(name) != nil; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// updateSubscription fetches sub and replaces its servers on success.
func (e *env) updateSubscription(ctx context.Context, sub *config.Subscription) error {
	req := subscription.Request{URL: sub.URL, UserAgent: sub.UserAgent, Headers: sub.Headers, AllowHTTP: sub.AllowHTTP}
	if req.UserAgent == "" {
		req.UserAgent = e.cfg.UserAgent
	}
	if sub.SendHWID {
		req.HWID = e.state.DeviceID()
	}
	if sub.AllowHTTP && strings.HasPrefix(strings.ToLower(sub.URL), "http:") {
		fmt.Fprintf(os.Stderr, "warning: %s is fetched over plain http; anyone on the network can change its servers\n", nameOr(sub))
	}
	res, err := subscription.Fetch(ctx, req)
	if errors.Is(err, subscription.ErrInsecureURL) {
		hint := "proxy-router sub add --allow-http <url>"
		if sub.Name != "" {
			hint = "proxy-router sub update --allow-http " + sub.Name
		}
		err = fmt.Errorf("%w; use https, or accept the risk with `%s`", err, hint)
	}
	if err != nil {
		// Fetch errors leave out the URL's token; this keeps them to one
		// clean line in state.json, the log and the tray.
		sub.LastError = safetext.Clean(err.Error(), 300)
		return fmt.Errorf("fetch %s: %s", subscription.Redact(sub.URL), sub.LastError)
	}
	sub.LastError = ""
	sub.Info = res.Info
	sub.Servers = res.Servers
	sub.UpdatedAt = time.Now()
	for _, perr := range res.Errors {
		fmt.Fprintf(os.Stderr, "warning: %s: skipped entry: %v\n", nameOr(sub), perr)
	}
	return nil
}

func nameOr(sub *config.Subscription) string {
	if sub.Name != "" {
		return clean(sub.Name)
	}
	return subscription.Redact(sub.URL)
}

// clean makes provider-controlled text safe to print. It's applied again
// on output because state.json may predate sanitizing at fetch time.
func clean(s string) string { return safetext.Clean(s, 0) }

func subListCmd() *cobra.Command {
	var showURL bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List subscriptions with traffic and expiry info",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			if len(e.state.Subscriptions) == 0 {
				fmt.Println("no subscriptions; add one with `proxy-router sub add <url>`")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSERVERS\tUPDATED\tTRAFFIC\tEXPIRES\tURL")
			for _, s := range e.state.Subscriptions {
				traffic := "-"
				if used := s.Info.Upload + s.Info.Download; used > 0 || s.Info.Total > 0 {
					total := "∞"
					if s.Info.Total > 0 {
						total = humanBytes(s.Info.Total)
					}
					traffic = humanBytes(used) + " / " + total
				}
				expires := "-"
				if !s.Info.Expire.IsZero() {
					expires = s.Info.Expire.Format("2006-01-02")
					if time.Now().After(s.Info.Expire) {
						expires += " (expired)"
					}
				}
				u := subscription.Redact(s.URL)
				if showURL {
					u = s.URL
				}
				updated := ago(s.UpdatedAt)
				if s.LastError != "" {
					updated += " (last update failed)"
				}
				fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", clean(s.Name), len(s.Servers), updated, traffic, expires, u)
			}
			tw.Flush()
			for _, s := range e.state.Subscriptions {
				if s.LastError != "" {
					// Older versions stored errors with the full URL.
					lastErr := strings.ReplaceAll(s.LastError, s.URL, subscription.Redact(s.URL))
					fmt.Printf("\n%s: last error: %s", clean(s.Name), clean(lastErr))
				}
				if s.Info.Announce != "" {
					fmt.Printf("\n%s: %s", clean(s.Name), clean(s.Info.Announce))
				}
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().BoolVar(&showURL, "show-url", false, "show full subscription URLs, including tokens")
	return cmd
}

func subUpdateCmd() *cobra.Command {
	var allowHTTP bool
	cmd := &cobra.Command{
		Use:               "update [name...]",
		Short:             "Re-fetch subscriptions (all by default)",
		ValidArgsFunction: completeSubscriptions,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			if allowHTTP && len(args) == 0 {
				return fmt.Errorf("--allow-http needs the names of the subscriptions to allow it for")
			}
			subs, err := e.pickSubs(args)
			if err != nil {
				return err
			}
			for _, s := range subs {
				s.AllowHTTP = s.AllowHTTP || allowHTTP
			}
			failed := e.updateAll(cmd.Context(), subs)
			if err := e.state.Save(); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d subscriptions failed to update", failed, len(subs))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowHTTP, "allow-http", false, "from now on accept plain http:// URLs for the named subscriptions (anyone on the network can then change their servers)")
	return cmd
}

func (e *env) pickSubs(names []string) ([]*config.Subscription, error) {
	if len(names) == 0 {
		return e.state.Subscriptions, nil
	}
	var subs []*config.Subscription
	for _, n := range names {
		s := e.state.Subscription(n)
		if s == nil {
			return nil, fmt.Errorf("no subscription named %q", n)
		}
		subs = append(subs, s)
	}
	return subs, nil
}

// updateAll refreshes subs, printing progress; returns the failure count.
func (e *env) updateAll(ctx context.Context, subs []*config.Subscription) int {
	failed := 0
	for _, s := range subs {
		before := len(s.Servers)
		if err := e.updateSubscription(ctx, s); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v (keeping %d cached servers)\n", clean(s.Name), err, before)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "%s: %d servers\n", clean(s.Name), len(s.Servers))
	}
	if _, ok := e.state.Current(); !ok && e.state.Selected != nil {
		fmt.Fprintf(os.Stderr, "warning: selected server %q is gone after the update; pick another with `proxy-router use`\n", clean(e.state.Selected.Name))
	}
	return failed
}

func subRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "remove <name>",
		Aliases:           []string{"rm"},
		Short:             "Remove a subscription and its servers",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSubscription,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := load()
			if err != nil {
				return err
			}
			subs := e.state.Subscriptions
			for i, s := range subs {
				if s.Name == args[0] {
					e.state.Subscriptions = append(subs[:i:i], subs[i+1:]...)
					if e.state.Selected != nil && e.state.Selected.Group == s.Name {
						e.state.Selected = nil
					}
					if err := e.state.Save(); err != nil {
						return err
					}
					fmt.Printf("removed subscription %q\n", s.Name)
					return nil
				}
			}
			return fmt.Errorf("no subscription named %q", args[0])
		},
	}
}
