//go:build !windows

package config

import (
	"os"
	"syscall"
)

type ids struct{ uid, gid int }

func statOwner(path string) (ids, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return ids{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ids{}, false
	}
	return ids{int(st.Uid), int(st.Gid)}, true
}
