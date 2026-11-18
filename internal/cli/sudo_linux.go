package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
)

// allowInstalledSudo runs after a TUN start or restart authorized by polkit. Older
// installed builds keep using polkit until a build with this lifecycle is
// installed. A failed rule write can be retried on a later start.
func allowInstalledSudo(t service.Target, dir string) {
	if t.Scope != service.System || t.User == nil || t.User.Uid == "0" || os.Getenv("PKEXEC_UID") != t.User.Uid {
		return
	}
	// configDir resolves symlinks for root, but sudo matches the spelling
	// that the caller passes in --dir.
	if flagDir != "" {
		if abs, err := filepath.Abs(flagDir); err == nil {
			dir = abs
		}
	}
	args := sudoArgLists(dir, t.User.Uid)
	if service.SudoersPossible(args) {
		if err := service.AllowSudo(t.User, args); err != nil {
			fmt.Fprintf(os.Stderr, "note: could not enable passwordless TUN connect and disconnect: %v\n", err)
		}
	}
}
