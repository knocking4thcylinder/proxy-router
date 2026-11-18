package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

func updateCmd() *cobra.Command {
	var check, force bool
	var channel string
	cmd := &cobra.Command{
		Use:   "update [version|channel]",
		Short: "Update proxy-router to the latest release, a nightly build, or a version",
		Long: `Check GitHub for a proxy-router release, download it, verify its
SHA-256 and update this binary and installed background service copies.
Running services are restarted. Updating the TUN copy asks for your password.

With no argument, the release channel this build came from is followed:
stable builds get the latest release, nightly builds the latest nightly.
"proxy-router update nightly" switches to the nightly channel and
"proxy-router update stable" switches back. A version such as v0.2.0 pins
that release.

--check only reports; --force reinstalls the same version (or allows a
downgrade).

The background service and the tray also do this by themselves; see
auto_update in config.yaml.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var want string
			if len(args) == 1 {
				want = args[0]
			}
			return runUpdate(want, channel, check, force, update.NewClient())
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only check for a newer release")
	cmd.Flags().BoolVar(&force, "force", false, "install even if the version is the same or older")
	cmd.Flags().StringVar(&channel, "channel", "", `release channel to follow: "stable" or "nightly"`)
	passwordDialogFlag(cmd)
	return cmd
}

func runUpdate(want, channelFlag string, check, force bool, client *update.Client) error {
	if channelFlag != "" && channelFlag != update.StableChannel && channelFlag != update.NightlyChannel {
		return fmt.Errorf("unknown channel %q; use stable or nightly", channelFlag)
	}
	keyword := want == update.NightlyChannel || want == update.StableChannel
	if keyword && channelFlag != "" && channelFlag != want {
		return fmt.Errorf("conflicting channels %q and %q", want, channelFlag)
	}
	if !keyword && want != "" && channelFlag != "" {
		return errors.New("--channel can't be combined with a version")
	}

	channel := buildChannel()
	explicitChannel := false
	pinned := want != "" && !keyword
	switch {
	case channelFlag != "":
		channel = channelFlag
		explicitChannel = true
	case keyword:
		channel = want
		want = ""
		explicitChannel = true
	}

	current := version()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		rel *update.Release
		err error
	)
	switch {
	case pinned:
		rel, err = client.ByTag(ctx, want)
	case channel == update.NightlyChannel:
		rel, err = client.Nightly(ctx)
	default:
		rel, err = client.Latest(ctx)
	}
	if err != nil {
		return err
	}
	target := rel.Version()
	if target == "" {
		return fmt.Errorf("release %s has no version", rel.Tag)
	}

	label := "latest"
	switch {
	case pinned:
		label = "target"
	case channel == update.NightlyChannel:
		label = "nightly"
	}
	allowDowngrade := force || explicitChannel
	cmp := update.Compare(target, current)
	switch {
	case check:
		fmt.Printf("current: %s\n%s:  %s\n", current, label, target)
		switch {
		case cmp > 0:
			fmt.Println("update available")
		case cmp < 0:
			fmt.Println("this build is newer than the release")
		default:
			fmt.Println("up to date")
		}
		return nil
	case cmp < 0 && !allowDowngrade:
		return fmt.Errorf("%s is older than this build (%s); use --force to downgrade", target, current)
	case cmp == 0 && !force && !explicitChannel:
		if pinned {
			fmt.Printf("already at %s\n", current)
		} else {
			fmt.Printf("proxy-router %s is up to date\n", current)
		}
		return nil
	}

	fmt.Printf("current: %s\n%s:  %s\n", current, label, target)
	err = update.Install(ctx, client, rel, update.InstallOptions{
		Log: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
		BeforeReplace: func(source string) error {
			return manualRelease{target, source, allowDowngrade}.updateServices(rel.Tag)
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("updated to %s\n", target)
	return nil
}

type manualRelease struct {
	version, source string
	allowDowngrade  bool
}

const applyServiceUpdate = "apply-service-update"

func (r manualRelease) updateServices(tag string) error {
	userT, sysT, err := targets()
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return r.updateInstalledService(sysT)
	}
	if path := service.DefinitionPath(sysT); path != "" {
		if _, err := os.Stat(path); err == nil {
			// Elevate the current CLI before replacing it. The downloaded
			// release may predate this command and its version checks.
			args := []string{applyServiceUpdate, tag, r.version}
			if r.allowDowngrade {
				args = append(args, "--allow-downgrade")
			}
			if err := asRoot("updating the TUN service binary needs root", manualUpgradeBinary, args...); err != nil {
				return fmt.Errorf("the TUN service update failed before replacing the CLI. Rerun the update to retry: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check for the TUN service: %w", err)
		}
	}
	return r.updateInstalledService(userT)
}

func applyServiceUpdateCmd() *cobra.Command {
	var rel manualRelease
	cmd := &cobra.Command{
		Use:    applyServiceUpdate + " tag version",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return errors.New("updating the TUN service binary needs root")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			client := update.NewClient()
			release, err := serviceRelease(ctx, client, args[0], args[1])
			if err != nil {
				return err
			}
			// Verify and unpack the archive again in root's own directory.
			// The initiating user's staged executable never crosses into root.
			installed, err := service.RootBinary()
			if err != nil {
				return fmt.Errorf("check the installed TUN service: %w", err)
			}
			tmp, err := os.MkdirTemp(filepath.Dir(installed), ".release-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmp)
			rel.version = release.Version()
			rel.source, err = update.DownloadBinary(ctx, client, release, tmp)
			if err != nil {
				return err
			}
			return rel.updateInstalledService(service.Target{Scope: service.System})
		},
	}
	cmd.Flags().BoolVar(&rel.allowDowngrade, "allow-downgrade", false, "allow installing an older release")
	return cmd
}

func serviceRelease(ctx context.Context, client *update.Client, tag, version string) (*update.Release, error) {
	if !update.IsRelease(version) || (tag != update.NightlyTag && tag != version) {
		return nil, errors.New("invalid service release")
	}
	release, err := client.ByTag(ctx, tag)
	if err != nil {
		return nil, err
	}
	if release.Tag != tag || release.Version() != version {
		return nil, fmt.Errorf("release %s changed while updating; retry the update", tag)
	}
	return release, nil
}

func (r manualRelease) updateInstalledService(t service.Target) error {
	st, err := service.Query(t)
	if errors.Is(err, service.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Installed {
		return nil
	}
	path := service.BinaryPath(t)
	if t.Scope == service.System {
		// Only probe the protected root-owned binary.
		path, err = service.RootBinary()
		if err != nil {
			return fmt.Errorf("check the TUN service binary: %w", err)
		}
	}
	var v string
	if !r.allowDowngrade {
		v, _ = binaryVersion(path)
	}
	return r.apply(t, st, v, service.UpdateBinary, service.RestartRunning)
}

func (r manualRelease) apply(t service.Target, st service.Status, installedVersion string, copyBinary func(service.Target, string) error, restart func(service.Target) error) error {
	if !r.allowDowngrade && update.Compare(installedVersion, r.version) > 0 {
		fmt.Printf("the %s already has a newer build (%s). Use --force to replace it.\n", t, installedVersion)
		return nil
	}
	if err := copyBinary(t, r.source); err != nil {
		return fmt.Errorf("install the %s binary: %w", t, err)
	}
	if st.Running {
		fmt.Printf("restarting the %s with %s...\n", t, r.version)
		if err := restart(t); err != nil {
			return fmt.Errorf("restart the %s: %w", t, err)
		}
	} else {
		fmt.Printf("updated the %s binary to %s. The service is stopped.\n", t, r.version)
	}
	return nil
}

// errRestartForUpdate asks main to exit with a failure status, so systemd
// (Restart=on-failure) and launchd (KeepAlive SuccessfulExit=false) start
// the new build. It is not an error to show the user.
var errRestartForUpdate = errors.New("restarting to apply an update")

// IsRestartForUpdate reports whether err is the service asking to be
// restarted after installing an update.
func IsRestartForUpdate(err error) bool { return errors.Is(err, errRestartForUpdate) }
