package cli

import "errors"

var errNoService = errors.New("the background service isn't supported on Windows")

func serviceOutput(dir string) error { return errNoService }

func systemLogName() string { return "" }

func tailSystemLog(n int, follow bool) error { return errNoService }

func systemRunDirOK() bool { return false }
