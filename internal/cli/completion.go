package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

func configureFishCompletion(root *cobra.Command) {
	fish, _, _ := root.Find([]string{"completion", "fish"})
	fish.RunE = func(cmd *cobra.Command, _ []string) error {
		noDescriptions, _ := cmd.Flags().GetBool("no-descriptions")
		var script bytes.Buffer
		if err := root.GenFishCompletion(&script, !noDescriptions); err != nil {
			return err
		}
		// Cobra 1.10.2 omits the option terminator here. A single nospace
		// completion such as --dir=path/ is otherwise parsed as a Fish option.
		fixed := strings.ReplaceAll(script.String(), `string split --max 1 \t `, `string split --max 1 \t -- `)
		_, err := io.WriteString(cmd.OutOrStdout(), fixed)
		return err
	}
}

// configureCompletions keeps suggestions in sync with the command tree. Cobra
// handles flag prefixes itself; also offer flags at an empty word so commands
// such as "run <TAB>" are discoverable without first typing a dash.
func configureCompletions(cmd *cobra.Command, requestArgs []string) {
	completeArgs := cmd.ValidArgsFunction
	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var completions []string
		directive := cobra.ShellCompDirectiveNoFileComp
		if completeArgs != nil {
			completions, directive = completeArgs(cmd, args, toComplete)
		}
		if toComplete == "" && !completionAfterDash(cmd, requestArgs) {
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				if flag.Hidden || flag.Deprecated != "" {
					return
				}
				_, repeatable := flag.Value.(pflag.SliceValue)
				if flag.Changed && !repeatable && flag.Value.Type() != "count" {
					return
				}
				completions = append(completions, cobra.CompletionWithDesc("--"+flag.Name, flag.Usage))
				if flag.Shorthand != "" && flag.ShorthandDeprecated == "" {
					completions = append(completions, cobra.CompletionWithDesc("-"+flag.Shorthand, flag.Usage))
				}
			})
		}
		return completions, directive
	}

	// Only path flags should fall back to file completion. Free text, numeric,
	// and boolean flag values have no useful candidates on the filesystem.
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := cmd.GetFlagCompletionFunc(flag.Name); ok {
			return
		}
		if _, ok := flag.Annotations[cobra.BashCompFilenameExt]; ok {
			return
		}
		if _, ok := flag.Annotations[cobra.BashCompSubdirsInDir]; ok {
			return
		}
		_ = cmd.RegisterFlagCompletionFunc(flag.Name, cobra.NoFileCompletions)
	})
	for _, child := range cmd.Commands() {
		configureCompletions(child, requestArgs)
	}
}

func completionAfterDash(cmd *cobra.Command, requestArgs []string) bool {
	// Cobra parses a synthetic "--" before calling completion hooks, leaving
	// ArgsLenAtDash set even when the user did not type it. Parse the original
	// request without setting any flag values to find the actual separator.
	flags := pflag.NewFlagSet("completion", pflag.ContinueOnError)
	flags.AddFlagSet(cmd.Flags())
	_ = flags.ParseAll(requestArgs[:max(0, len(requestArgs)-1)], func(*pflag.Flag, string) error { return nil })
	return flags.ArgsLenAtDash() >= 0
}

func completeFiles(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveDefault
}

func completeDirectories(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	const directive = cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	// Fish's Cobra script does not implement FilterDirs, so enumerate directories
	// here rather than falling back to unfiltered shell file completion.
	if toComplete == "~" {
		return []string{"~/"}, directive
	}
	dir, prefix := filepath.Split(toComplete)
	searchDir := dir
	if strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, directive
		}
		searchDir = filepath.Join(home, dir[2:])
	}
	if searchDir == "" {
		searchDir = "."
	}
	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return nil, directive
	}
	var completions []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(prefix, ".") {
			continue
		}
		isDir := entry.IsDir()
		if entry.Type()&os.ModeSymlink != 0 {
			info, err := os.Stat(filepath.Join(searchDir, entry.Name()))
			isDir = err == nil && info.IsDir()
		}
		if isDir {
			completions = appendCompletion(completions, dir+entry.Name()+string(filepath.Separator), "directory", toComplete)
		}
	}
	return completions, directive
}

// Completion reads only cached state: pressing Tab must not initialize config,
// fetch subscriptions, start Xray, or otherwise change the user's files.
func completionState() *config.State {
	dir, err := configDir()
	if err != nil {
		return nil
	}
	state, err := config.LoadState(dir)
	if err != nil {
		return nil
	}
	return state
}

func completeServers(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return completeServerEntries(args, toComplete, false)
}

func completeSelectedServer(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	fastest, _ := cmd.Flags().GetBool("fastest")
	if len(args) > 0 || fastest {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeServers(cmd, nil, toComplete)
}

func completeManualServer(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeServerEntries(nil, toComplete, true)
}

func completeServerEntries(args []string, toComplete string, manualOnly bool) ([]string, cobra.ShellCompDirective) {
	state := completionState()
	if state == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	entries := state.Entries()
	names := make(map[string]int)
	for _, entry := range entries {
		names[entry.Server.Name]++
	}
	used := make(map[int]bool)
	for _, arg := range args {
		if entry, err := state.Find(arg); err == nil {
			used[entry.Index] = true
		}
	}
	var completions []string
	for _, entry := range entries {
		if used[entry.Index] || manualOnly && entry.Group != config.ManualGroup {
			continue
		}
		index := strconv.Itoa(entry.Index)
		if strings.HasPrefix(toComplete, "#") {
			index = "#" + index
		}
		fullName := entry.Group + "/" + entry.Server.Name
		completions = appendCompletion(completions, index, fullName, toComplete)
		completions = appendCompletion(completions, fullName, "#"+strconv.Itoa(entry.Index), toComplete)
		if names[entry.Server.Name] == 1 {
			// Numeric names resolve as indices, not names.
			if _, err := strconv.Atoi(entry.Server.Name); err != nil {
				completions = appendCompletion(completions, entry.Server.Name, entry.Group, toComplete)
			}
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeGroups(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	state := completionState()
	if state == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, sub := range state.Subscriptions {
		completions = appendCompletion(completions, sub.Name, "subscription", toComplete)
	}
	if len(state.Manual) > 0 {
		completions = appendCompletion(completions, config.ManualGroup, "manually added servers", toComplete)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeSubscription(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeSubscriptions(cmd, args, toComplete)
}

func completeSubscriptions(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	state := completionState()
	if state == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, sub := range state.Subscriptions {
		if !slices.Contains(args, sub.Name) {
			completions = appendCompletion(completions, sub.Name, "subscription", toComplete)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func appendCompletion(completions []string, value, description, prefix string) []string {
	// Tabs/newlines are delimiters in Cobra's shell protocol. Such names are
	// still selectable by their numeric index, without corrupting the reply.
	if value == "" || !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, "\t\r\n") {
		return completions
	}
	description = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(description)
	return append(completions, cobra.CompletionWithDesc(value, description))
}
