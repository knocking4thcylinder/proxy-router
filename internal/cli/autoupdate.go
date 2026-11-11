package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

// autoUpdateLoop checks for a new release while the background service
// runs and, when there is one, installs it into the service's own binary.
// The caller restarts the service so the new build is used.
func autoUpdateLoop(ctx context.Context, ready chan<- string) {
	// Let the tunnel (and, in TUN mode, the network wait) settle first.
	if !sleepContext(ctx, 2*time.Minute) {
		return
	}
	for {
		delay := 15 * time.Minute
		if e, err := load(); err != nil {
			fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
		} else if a := e.cfg.AutoUpdate; a.Enabled && a.Interval.D() > 0 {
			delay = a.Interval.D()
			tag, err := autoUpdateOnce(ctx)
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
				// Try again sooner than a whole interval after a failure
				// (network down at startup, GitHub rate limit).
				if delay > time.Hour {
					delay = time.Hour
				}
			case tag != "":
				ready <- tag
				return
			}
		}
		if !sleepContext(ctx, delay) {
			return
		}
	}
}

// autoUpdateOnce installs the latest release over the service's binary and
// returns its tag, or "" when it is already current. A newer file that
// this process isn't running yet (another updater replaced it) is reported
// as well, so the caller restarts into it without downloading it again.
func autoUpdateOnce(ctx context.Context) (string, error) {
	// Local builds aren't releases; replacing them would make debugging
	// confusing.
	if !update.IsRelease(version()) {
		return "", nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	client := update.NewClient()
	rel, err := client.Latest(ctx)
	if err != nil {
		return "", err
	}
	if update.Compare(rel.Tag, version()) <= 0 {
		return "", nil
	}
	if v, ok := binaryVersion(exe); ok && update.Compare(rel.Tag, v) <= 0 {
		fmt.Fprintf(os.Stderr, "%s auto-update: %s is already installed; restarting into it\n", time.Now().Format(time.TimeOnly), v)
		return v, nil
	}
	fmt.Fprintf(os.Stderr, "%s auto-update: installing %s\n", time.Now().Format(time.TimeOnly), rel.Tag)
	err = update.Install(ctx, client, rel, update.InstallOptions{
		Target: exe,
		Log: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err != nil {
		return "", err
	}
	return rel.Tag, nil
}

// sleepContext waits for d, returning false if ctx was cancelled first.
func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
