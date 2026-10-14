package cli

import "errors"

func redirectOutput(path string) error {
	return errors.New("the background service isn't supported on Windows")
}
