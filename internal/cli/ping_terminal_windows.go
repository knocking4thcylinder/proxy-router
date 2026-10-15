package cli

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func pingTerminalWidth(out io.Writer) int {
	f, ok := out.(*os.File)
	if !ok {
		return 0
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil || mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		return 0
	}
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(h, &info) != nil {
		return 0
	}
	return int(info.Window.Right-info.Window.Left) + 1
}
