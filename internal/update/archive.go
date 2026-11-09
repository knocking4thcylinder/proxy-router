package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// checksumFor returns the SHA-256 that sums lists for name.
func checksumFor(sums, name string) (string, error) {
	data, err := os.ReadFile(sums)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		sum, file := fields[0], strings.TrimPrefix(fields[1], "*")
		if filepath.Base(file) != name {
			continue
		}
		if len(sum) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(sum); err != nil {
			continue
		}
		return strings.ToLower(sum), nil
	}
	return "", fmt.Errorf("SHA256SUMS has no checksum for %s", name)
}

// verifySHA256 compares the file's digest with want (hex).
func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filepath.Base(path), want, got)
	}
	return nil
}

// extract writes binary from archive into dir and returns its path.
func extract(archive, dir, binary string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, binary)
	switch {
	case strings.HasSuffix(archive, ".tar.gz"), strings.HasSuffix(archive, ".tgz"):
		if err := extractTarGz(archive, dst, binary); err != nil {
			return "", err
		}
	case strings.HasSuffix(archive, ".zip"):
		if err := extractZip(archive, dst, binary); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("don't know how to unpack %s", filepath.Base(archive))
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return "", err
	}
	return dst, nil
}

func extractTarGz(archive, dst, binary string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != binary || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if found {
			return fmt.Errorf("%s is in the archive more than once", binary)
		}
		if hdr.Size < 0 || hdr.Size > maxBinary {
			return fmt.Errorf("%s: bad size in the archive", binary)
		}
		if err := writeLimited(dst, tr, hdr.Size); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%s isn't in the archive", binary)
	}
	return nil
}

func extractZip(archive, dst, binary string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	found := false
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binary || !f.FileInfo().Mode().IsRegular() {
			continue
		}
		if found {
			return fmt.Errorf("%s is in the archive more than once", binary)
		}
		if f.UncompressedSize64 > maxBinary {
			return fmt.Errorf("%s: bad size in the archive", binary)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeLimited(dst, rc, int64(f.UncompressedSize64))
		if cerr := rc.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%s isn't in the archive", binary)
	}
	return nil
}

// writeLimited creates dst and copies at most n bytes into it, so a bad
// archive can't fill the disk.
func writeLimited(dst string, r io.Reader, n int64) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	written, err := io.Copy(f, io.LimitReader(r, n+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if written > n {
		return fmt.Errorf("%s: the archive has more data than it says", filepath.Base(dst))
	}
	return nil
}
