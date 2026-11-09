package main

import (
	"fmt"
	"os"

	"github.com/knocking4thcylinder/proxy-router/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// The background service installed an update and wants its service
		// manager to start the new build. A failing exit is how systemd
		// (Restart=on-failure) and launchd (KeepAlive SuccessfulExit=false)
		// are asked to do that, without printing an error.
		if cli.IsRestartForUpdate(err) {
			os.Exit(75)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
