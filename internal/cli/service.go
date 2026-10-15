package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/secpath"
	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

type startOptions struct {
	tun, noTUN, force bool
	verbose           int
}

func (o *startOptions) flags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.tun, "tun", false, "capture all traffic with TUN (system service, needs sudo)")
	cmd.Flags().BoolVar(&o.noTUN, "no-tun", false, "local SOCKS5/HTTP proxy only (user service)")
	cmd.Flags().BoolVar(&o.force, "force", false, "start TUN mode even though another VPN owns the default route")
	cmd.Flags().CountVarP(&o.verbose, "verbose", "v", "log every connection; -vv also logs why connections fail")
	cmd.MarkFlagsMutuallyExclusive("tun", "no-tun")
	passwordDialogFlag(cmd)
}

// args are the start / restart arguments for the root half of starting
// in TUN mode.
func (o startOptions) args(restart bool) []string {
	args := []string{"start", "--tun"}
	if restart {
		args[0] = "restart"
	}
	if o.force {
		args = append(args, "--force")
	}
	if o.verbose > 0 {
		args = append(args, "-"+strings.Repeat("v", o.verbose))
	}
	return args
}

// passwordDialog is --password-dialog: ask for the password in the
// desktop's dialog (polkit, or the macOS one) instead of with sudo.
var passwordDialog bool

func passwordDialogFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&passwordDialog, "password-dialog", false, "ask for the password in the desktop's dialog instead of with sudo (used by the tray)")
	_ = cmd.Flags().MarkHidden("password-dialog")
}

// systemOnlyFlag is stop / uninstall --system: only the TUN-mode system
// service. It's what they run as root.
func systemOnlyFlag(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "system", false, "only the TUN-mode system service")
	_ = cmd.Flags().MarkHidden("system")
}

func startCmd() *cobra.Command {
	var o startOptions
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the background service and enable it at login (or boot, in TUN mode)",
		Long: `Start proxy-router in the background and have it start automatically.

TUN mode needs root, so it runs as a system service that starts at boot;
start asks for sudo. Proxy-only mode runs as your user and starts at login.
The mode is --tun / --no-tun, else the installed service's, else
tun.enabled in config.yaml.

The service follows changes by itself: "use", "sub update", and edits to
config.yaml or the rules file apply without a restart.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return startService(o, false)
		},
	}
	o.flags(cmd)
	return cmd
}

func restartCmd() *cobra.Command {
	var o startOptions
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the background service (also picks up a rebuilt binary)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return startService(o, true)
		},
	}
	o.flags(cmd)
	return cmd
}

func stopCmd() *cobra.Command {
	var systemOnly bool
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the background service; it won't start at login/boot until \"start\"",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopService(false, systemOnly)
		},
	}
	systemOnlyFlag(cmd, &systemOnly)
	passwordDialogFlag(cmd)
	return cmd
}

func uninstallCmd() *cobra.Command {
	var systemOnly bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop the background service and remove it (config and servers are kept)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopService(true, systemOnly)
		},
	}
	systemOnlyFlag(cmd, &systemOnly)
	passwordDialogFlag(cmd)
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether proxy-router is running, and how",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showStatus()
		},
	}
}

func logsCmd() *cobra.Command {
	var follow bool
	var lines int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the background service's log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := configDir()
			if err != nil {
				return err
			}
			return tailFile(logPath(dir), lines, follow)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new lines")
	cmd.Flags().IntVarP(&lines, "lines", "n", 40, "number of lines to show")
	return cmd
}

// targets returns the user and system service definitions for the user
// running proxy-router (as root, the user it works for: --uid, or the one
// sudo or pkexec reports).
func targets() (userT, sysT service.Target, err error) {
	u, err := config.TargetUser()
	if err == nil && u == nil {
		u, err = user.Current()
	}
	if err != nil {
		return userT, sysT, err
	}
	return service.Target{Scope: service.User, User: u}, service.Target{Scope: service.System, User: u}, nil
}

// rootBinary says which executable asRoot runs as root.
type rootBinary int

const (
	// The TUN service's copy if it's installed; this executable only
	// when there's none (stop, uninstall).
	installedBinary rootBinary = iota
	// The TUN service's copy if it's installed, else this executable,
	// which then installs itself (start).
	installBinary
	// This executable, which installs itself, unless the TUN service's
	// copy is the same build (restart, which picks up a new build).
	upgradeBinary
)

// asRoot runs proxy-router as root with args, asking for the password with
// sudo, or the desktop's dialog with --password-dialog. It returns when
// that's done, or exits with its status if it failed. Only root's half of
// the work goes there; the caller does the user's half as the user.
//
// What runs as root is the TUN service's own copy of proxy-router when
// it's installed and only root can change it, rather than this executable,
// which the user (or anything running as them) can replace. This
// executable runs as root only to install itself as that copy: the first
// TUN-mode start, and restarts that update the service to a new build.
func asRoot(why string, which rootBinary, args ...string) error {
	exe, err := rootExecutable(which)
	if err != nil {
		return err
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	// Root refuses a config directory other users could change
	// (config.CheckDir); say so before asking for a password.
	if _, err := secpath.Check(dir, os.Getuid()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("config directory: %w", err)
	}
	// Who root works for goes as a flag: sudo and pkexec check it against
	// the uid they report, and nothing is taken from the environment.
	argv := append([]string{exe, "--dir", dir, "--uid", strconv.Itoa(os.Getuid())}, args...)
	var c *exec.Cmd
	if passwordDialog {
		if c = elevated(argv); c == nil {
			return errors.New("this build can't show a password dialog; run proxy-router in a terminal")
		}
		fmt.Fprintf(os.Stderr, "%s; asking for the password\n", why)
	} else {
		fmt.Fprintf(os.Stderr, "%s; running with sudo\n", why)
		c = exec.Command("sudo", argv...)
	}
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if _, sysT, terr := targets(); terr == nil && exe == service.BinaryPath(sysT) && service.Outdated(sysT) {
			fmt.Fprintln(os.Stderr, `note: the TUN service has a different build of proxy-router; "proxy-router restart" updates it`)
		}
		os.Exit(ee.ExitCode())
	}
	return err
}

// takesUID reports whether the proxy-router at path knows --uid (run as
// the user, which is harmless).
func takesUID(path string) bool {
	return exec.Command(path, "--uid", strconv.Itoa(os.Getuid()), "--version").Run() == nil
}

// rootExecutable picks what asRoot runs; see rootBinary.
func rootExecutable(which rootBinary) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return "", err
	}
	installed, err := service.RootBinary()
	switch {
	case err == nil && !takesUID(installed):
		// Installed before --uid existed; it's root's, so this can't be
		// faked. Such an install already trusts this executable, until
		// it's updated.
		fmt.Fprintln(os.Stderr, "the TUN service has an older build of proxy-router; using this one")
	case err == nil:
		_, sysT, terr := targets()
		if which != upgradeBinary || (terr == nil && !service.Outdated(sysT)) {
			return installed, nil
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		// Not root's alone any more: don't run it, and don't hide that.
		fmt.Fprintf(os.Stderr, "warning: not running the TUN service's binary as root: %v\n", err)
	}
	if which != installedBinary {
		fmt.Fprintf(os.Stderr, "installing this build (%s) as the TUN service's binary, which runs as root\n", self)
	}
	return self, nil
}

func modeName(t service.Target) string {
	if t.Scope == service.System {
		return "TUN"
	}
	return "proxy"
}

func autostart(t service.Target) string {
	if t.Scope == service.System {
		return "starts at boot"
	}
	return "starts at login"
}

func startService(o startOptions, restart bool) error {
	e, err := load()
	if err != nil {
		return err
	}
	dir := e.cfg.Dir()
	userT, sysT, err := targets()
	if err != nil {
		return err
	}
	us, err := service.Query(userT)
	if errors.Is(err, service.ErrUnsupported) {
		return err
	}
	ss, _ := service.Query(sysT)
	if restart && !us.Installed && !ss.Installed {
		return errors.New(`no background service is installed; use "proxy-router start"`)
	}
	if st, ok := readRunStatus(dir); ok && !st.Service {
		return fmt.Errorf("proxy-router is already running in the foreground (pid %d); stop it first", st.PID)
	}

	var useTUN bool
	switch {
	case o.tun:
		useTUN = true
	case o.noTUN:
	case ss.Installed:
		useTUN = true
	case us.Installed:
	default:
		useTUN = e.cfg.TUN.Enabled
	}
	// Root only ever handles the system service, and the user only the
	// user service: root doesn't write in the user's directories.
	switch root := os.Geteuid() == 0; {
	case !useTUN && root:
		return errors.New("proxy mode runs as your user, not root: run it without sudo (or pass --tun)")
	case useTUN && !root:
		which := installBinary
		if restart {
			which = upgradeBinary
		}
		if err := asRoot("TUN mode runs as a system service", which, o.args(restart)...); err != nil {
			return err
		}
		// Root stopped the proxy-mode service; its files are the user's
		// to remove.
		if us.Installed {
			if err := service.Remove(userT); err != nil {
				return err
			}
			fmt.Printf("removed the proxy-mode %s\n", userT)
		}
		return nil
	case !useTUN && ss.Installed:
		if err := asRoot("the TUN service has to be removed first", installedBinary, "uninstall", "--system"); err != nil {
			return err
		}
	}

	want := userT
	args := []string{"--dir", dir, "run", "--service"}
	if useTUN {
		// The service is told whose files it works with; it doesn't guess
		// from the directory or the environment.
		want = sysT
		args = []string{"--dir", dir, "--uid", userT.User.Uid, "run", "--service", "--tun"}
	} else {
		args = append(args, "--no-tun")
	}
	if o.force {
		args = append(args, "--force")
	}
	if o.verbose > 0 {
		args = append(args, "-"+strings.Repeat("v", o.verbose))
	}
	spec := service.Spec{Target: want, Binary: service.BinaryPath(want), Args: args}
	if cur, _ := service.Query(want); cur.Running && !restart && service.UpToDate(spec) {
		fmt.Println("already running")
		return showStatus()
	}
	if useTUN && us.Installed {
		// Through the user's service manager; no files are touched.
		if err := service.Stop(userT); err != nil {
			return err
		}
		fmt.Printf("stopped the proxy-mode %s\n", userT)
	}
	if _, err := service.InstallBinary(want); err != nil {
		return fmt.Errorf("install the service binary: %w", err)
	}
	begin := time.Now()
	if err := service.Install(spec); err != nil {
		return err
	}
	fmt.Printf("started in %s mode (%s, %s)\n", modeName(want), want, autostart(want))
	return waitStarted(dir, begin)
}

// waitStarted waits for the new service process to report in.
func waitStarted(dir string, begin time.Time) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := readRunStatus(dir); ok && st.Service && !st.Started.Before(begin.Add(-time.Second)) {
			printRunStatus(st)
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "the service hasn't come up; last log lines:")
	_ = tailFile(logPath(dir), 15, false)
	return errors.New(`the service didn't start; see "proxy-router logs"`)
}

func stopService(remove, systemOnly bool) error {
	userT, sysT, err := targets()
	if err != nil {
		return err
	}
	found := false
	for _, t := range []service.Target{sysT, userT} {
		if systemOnly && t.Scope == service.User {
			continue
		}
		st, err := service.Query(t)
		if err != nil || !st.Installed {
			continue
		}
		found = true
		if !remove && !st.Running && !st.Enabled {
			continue
		}
		// Root handles the system service and the user their own, as in
		// startService.
		switch root := os.Geteuid() == 0; {
		case t.Scope == service.System && !root:
			args := []string{"stop", "--system"}
			if remove {
				args[0] = "uninstall"
			}
			if err := asRoot("the TUN service runs as root", installedBinary, args...); err != nil {
				return err
			}
			continue
		case t.Scope == service.User && root:
			fmt.Printf("left the proxy-mode %s alone: it's yours, run this without sudo for it\n", t)
			continue
		}
		if remove {
			err = service.Remove(t)
		} else {
			err = service.Stop(t)
		}
		if err != nil {
			return err
		}
		if remove {
			fmt.Printf("removed the %s-mode %s\n", modeName(t), t)
		} else {
			fmt.Printf("stopped the %s-mode %s; it won't start automatically until \"proxy-router start\"\n", modeName(t), t)
		}
	}
	if !found {
		fmt.Println("no background service is installed")
		if dir, err := configDir(); err == nil {
			if st, ok := readRunStatus(dir); ok && !st.Service {
				fmt.Printf("(proxy-router run is active in the foreground, pid %d)\n", st.PID)
			}
		}
	}
	return nil
}

func showStatus() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	userT, sysT, err := targets()
	if err != nil {
		return err
	}
	st, live := readRunStatus(dir)
	shown := false
	for _, t := range []service.Target{sysT, userT} {
		q, err := service.Query(t)
		if err != nil || !q.Installed {
			continue
		}
		shown = true
		// launchctl may not show a root service to a normal user; the
		// status file covers that.
		running := q.Running || (live && st.Service && st.Mode == strings.ToLower(modeName(t)))
		state := "stopped"
		if running {
			state = "running"
		}
		auto := autostart(t)
		if !q.Enabled {
			auto = "won't start automatically"
		}
		fmt.Printf("service: %s (%s mode, %s, %s)\n", state, modeName(t), t, auto)
		if service.Outdated(t) {
			fmt.Println(`note:    the service runs a different build than this one; "proxy-router restart" updates it`)
		}
	}
	if !shown {
		fmt.Println(`service: not installed ("proxy-router start" installs it)`)
	}
	if live {
		if !st.Service {
			fmt.Printf("foreground: proxy-router run (pid %d)\n", st.PID)
		}
		printRunStatus(st)
	}
	fmt.Printf("log:     %s\n", logPath(dir))
	return nil
}

func printRunStatus(st runStatus) {
	fmt.Printf("pid:     %d, up %s\n", st.PID, time.Since(st.Started).Round(time.Second))
	if st.State == "waiting" {
		fmt.Printf("waiting: %s\n", st.Waiting)
		return
	}
	fmt.Printf("server:  %s\n", st.Server)
	switch {
	case st.TUN != "":
		fmt.Printf("tun:     %s (all traffic; own connections via %s)\n", st.TUN, st.Via)
	case st.Note != "":
		fmt.Printf("note:    %s\n", st.Note)
	case st.Via != "":
		fmt.Printf("via:     %s\n", st.Via)
	}
	if st.Socks != "" {
		fmt.Printf("socks5:  %s\n", st.Socks)
	}
	if st.HTTP != "" {
		fmt.Printf("http:    %s\n", st.HTTP)
	}
}

// tailFile prints the last n lines of path, then optionally follows it.
func tailFile(path string, n int, follow bool) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no log yet (%s)", path)
		}
		return err
	}
	defer f.Close()
	var ring []string
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			ring = append(ring, line)
			if len(ring) > n {
				ring = ring[1:]
			}
		}
		if err != nil {
			break
		}
	}
	for _, l := range ring {
		fmt.Print(l)
	}
	if !follow {
		return nil
	}
	off, _ := f.Seek(0, io.SeekCurrent)
	buf := make([]byte, 32<<10)
	for {
		time.Sleep(300 * time.Millisecond)
		if fi, err := f.Stat(); err == nil && fi.Size() < off {
			off = 0 // the log was cleared
		}
		for {
			k, err := f.ReadAt(buf, off)
			if k > 0 {
				os.Stdout.Write(buf[:k])
				off += int64(k)
			}
			if err != nil || k == 0 {
				break
			}
		}
	}
}
