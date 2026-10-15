//go:build !windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// readConfined reads dir/name for a process running as root without
// letting the user who owns dir redirect it: every directory on the way
// must belong to uid and be writable only by it, nothing past dir may be
// a symlink, and the file must be a regular file owned by uid of at most
// max bytes.
func readConfined(dir, name string, uid int, max int64) ([]byte, error) {
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("%s: must be inside %s", name, dir)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer func() { unix.Close(dfd) }()
	path := dir
	if err := checkOwned(dfd, path, uid); err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(name)), "/")
	for _, p := range parts[:len(parts)-1] {
		path = filepath.Join(path, p)
		next, err := unix.Openat(dfd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		unix.Close(dfd)
		dfd = next
		if err := checkOwned(dfd, path, uid); err != nil {
			return nil, err
		}
	}
	path = filepath.Join(path, parts[len(parts)-1])
	// O_NONBLOCK: a FIFO must not hang the service.
	fd, err := unix.Openat(dfd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err == unix.ELOOP {
		return nil, fmt.Errorf("%s is a symlink; the TUN service only reads regular files", path)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s isn't a regular file", path)
	}
	if err := checkStat(&st, path, uid); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d MB", path, max>>20)
	}
	return data, nil
}

func checkOwned(fd int, path string, uid int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return checkStat(&st, path, uid)
}

func checkStat(st *unix.Stat_t, path string, uid int) error {
	if int(st.Uid) != uid {
		return fmt.Errorf("%s belongs to uid %d, not %d; the TUN service only reads its user's files", path, st.Uid, uid)
	}
	if uint32(st.Mode)&0o022 != 0 {
		return fmt.Errorf("%s is writable by other users; fix it with chmod go-w", path)
	}
	return nil
}

// writeAtomic writes r to path through a temp file in the same directory.
// Everything after opening the directory goes through its descriptor, so
// the directory being swapped for a symlink midway can't redirect the
// temp file, the chown or the rename.
func writeAtomic(path string, r io.Reader, perm os.FileMode, owner *ids) (int64, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(dfd)
	var tmp string
	var fd int
	for range 100 {
		tmp = "." + name + "." + randomSuffix()
		fd, err = unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != unix.EEXIST {
			break
		}
	}
	if err != nil {
		return 0, &os.PathError{Op: "create", Path: filepath.Join(dir, tmp), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, tmp))
	done := false
	defer func() {
		if !done {
			f.Close()
			_ = unix.Unlinkat(dfd, tmp, 0)
		}
	}()
	n, err := io.Copy(f, r)
	if err != nil {
		return 0, err
	}
	if err := f.Chmod(perm); err != nil {
		return 0, err
	}
	if owner != nil {
		if err := f.Chown(owner.uid, owner.gid); err != nil {
			return 0, err
		}
	}
	if err := f.Close(); err != nil {
		done = true
		_ = unix.Unlinkat(dfd, tmp, 0)
		return 0, err
	}
	done = true
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return 0, &os.LinkError{Op: "rename", Old: tmp, New: path, Err: err}
	}
	return n, nil
}
