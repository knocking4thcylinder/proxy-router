package service

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	sudoersUser = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	// sudo matches a command's arguments joined with spaces, so they can't
	// contain any, nor anything sudoers or its wildcards treat specially.
	sudoersArg = regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`)
)

// sudoersRule lets user run bin as root without a password, with exactly
// the given argument lists.
func sudoersRule(user, bin string, argLists [][]string) (string, error) {
	if !sudoersUser.MatchString(user) {
		return "", fmt.Errorf("can't write a sudoers rule for the user %q", user)
	}
	// The path may contain spaces, escaped; arguments can't.
	if !sudoersArg.MatchString(strings.ReplaceAll(bin, " ", "")) {
		return "", fmt.Errorf("can't write a sudoers rule for %q", bin)
	}
	var cmds []string
	for _, args := range argLists {
		words := []string{strings.ReplaceAll(bin, " ", `\ `)}
		for _, a := range args {
			if !sudoersArg.MatchString(a) {
				return "", fmt.Errorf("can't write a sudoers rule with the argument %q", a)
			}
			words = append(words, a)
		}
		cmds = append(cmds, "\t"+strings.Join(words, " "))
	}
	return fmt.Sprintf(`# Written by proxy-router: lets %s start and stop the TUN service
# without a password. Removed with the service ("proxy-router uninstall").
%s ALL = (root) NOPASSWD: \
%s
`, user, user, strings.Join(cmds, ", \\\n")), nil
}
