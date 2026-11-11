package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

func updateCmd() *cobra.Command {
	var check, force bool
	cmd := &cobra.Command{
		Use:   "update [version]",
		Short: "Update proxy-router to the latest release (or a specific version)",
		Long: `Check GitHub for a newer proxy-router release, download it, verify its
SHA-256 and replace this binary. If the background service is running, it
is restarted with the new build; in TUN mode that asks for your password.

With no version, the latest published release is used. --check only reports;
--force reinstalls the same version (or allows a downgrade).

The background service and the tray also do this by themselves; see
auto_update in config.yaml.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var want string
			if len(args) == 1 {
				want = args[0]
			}
			return runUpdate(want, check, force)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only check for a newer release")
	cmd.Flags().BoolVar(&force, "force", false, "install even if the version is the same or older")
	passwordDialogFlag(cmd)
	return cmd
}

func runUpdate(want string, check, force bool) error {
	current := version()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := update.NewClient()
	var (
		rel *update.Release
		err error
	)
	if want != "" {
		rel, err = client.ByTag(ctx, want)
	} else {
		rel, err = client.Latest(ctx)
	}
	if err != nil {
		return err
	}

	label := "latest"
	if want != "" {
		label = "target"
	}
	switch {
	case check:
		fmt.Printf("current: %s\n%s:  %s\n", current, label, rel.Tag)
		switch cmp := update.Compare(rel.Tag, current); {
		case cmp > 0:
			fmt.Println("update available")
		case cmp < 0:
			fmt.Printf("this build is newer than the latest release\n")
		default:
			fmt.Println("up to date")
		}
		return nil
	case update.Compare(rel.Tag, current) < 0 && !force:
		return fmt.Errorf("%s is older than this build (%s); use --force to downgrade", rel.Tag, current)
	case update.Compare(rel.Tag, current) == 0 && !force:
		if want != "" {
			fmt.Printf("already at %s\n", current)
		} else {
			fmt.Printf("proxy-router %s is up to date\n", current)
		}
		return nil
	}

	fmt.Printf("current: %s\n%s:  %s\n", current, label, rel.Tag)
	err = update.Install(ctx, client, rel, update.InstallOptions{
		Log: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("updated to %s\n", rel.Tag)
	restartAfterUpdate()
	return nil
}

// restartAfterUpdate applies a new build to a running background service.
// A stopped service picks the new build up when it next starts.
func restartAfterUpdate() {
	userT, sysT, err := targets()
	if err != nil {
		return
	}
	us, _ := service.Query(userT)
	ss, _ := service.Query(sysT)
	if !us.Running && !ss.Running {
		if us.Installed || ss.Installed {
			fmt.Println("the background service isn't running; it will use the new build when it next starts")
		}
		return
	}
	fmt.Println("restarting the background service...")
	if err := startService(startOptions{}, true); err != nil {
		fmt.Fprintf(os.Stderr, "note: updated, but the service couldn't be restarted: %v\n", err)
		fmt.Fprintln(os.Stderr, `run "proxy-router restart" to apply it`)
	}
}

// errRestartForUpdate asks main to exit with a failure status, so systemd
// (Restart=on-failure) and launchd (KeepAlive SuccessfulExit=false) start
// the new build. It is not an error to show the user.
var errRestartForUpdate = errors.New("restarting to apply an update")

// IsRestartForUpdate reports whether err is the service asking to be
// restarted after installing an update.
func IsRestartForUpdate(err error) bool { return errors.Is(err, errRestartForUpdate) }
