package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.1.0", 0},
		{"v0.1.0", "v0.1.1", -1},
		{"v0.1.1", "v0.1.0", 1},
		{"v0.9.0", "v0.10.0", -1},
		{"v1.0.0", "v1.0.0-rc1", 1},
		{"v1.0.0-rc1", "v1.0.0-rc2", -1},
		{"v1.0.0-rc.2", "v1.0.0-rc.10", -1},
		{"v1.0.0-alpha", "v1.0.0-alpha.1", -1},
		{"v1.0.0-1", "v1.0.0-alpha", -1},
		{"v0.1.0+build", "v0.1.0", 0},
		{"0.1.0", "v0.1.0", 0},
		{"dev-abc123", "dev-def456", 0},
		{"dev-abc123", "v0.1.0", -1},
		{"v0.1.0", "dev-abc123", 1},
		{"", "v0.1.0", -1},
		{"v1", "v1.0.0", 0},
		{"v1.2.3.4", "v1.2.3.0", 0}, // both unparseable
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsRelease(t *testing.T) {
	for _, v := range []string{"v0.1.0", "0.1.0", "v1.2.3-rc1", "v1.2.3+build"} {
		if !IsRelease(v) {
			t.Errorf("IsRelease(%q) = false", v)
		}
	}
	for _, v := range []string{"dev", "dev-abc123", "", "version", "v1.2.3.4"} {
		if IsRelease(v) {
			t.Errorf("IsRelease(%q) = true", v)
		}
	}
}

func TestAssetName(t *testing.T) {
	tests := []struct {
		goos, goarch string
		archive      string
		ok           bool
	}{
		{"linux", "amd64", "proxy-router-linux-amd64.tar.gz", true},
		{"linux", "arm64", "proxy-router-linux-arm64.tar.gz", true},
		{"darwin", "arm64", "proxy-router-macos-arm64.tar.gz", true},
		{"darwin", "amd64", "", false},
		{"windows", "amd64", "proxy-router-windows-amd64.zip", true},
		{"windows", "arm64", "proxy-router-windows-arm64.zip", true},
		{"freebsd", "amd64", "", false},
	}
	for _, tt := range tests {
		archive, _, ok := AssetName(tt.goos, tt.goarch)
		if ok != tt.ok || archive != tt.archive {
			t.Errorf("AssetName(%q, %q) = %q, %v; want %q, %v", tt.goos, tt.goarch, archive, ok, tt.archive, tt.ok)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SHA256SUMS")
	sum := strings.Repeat("a", 64)
	data := "not a checksum line\n" +
		sum + "  proxy-router-linux-amd64.tar.gz\n" +
		strings.Repeat("b", 64) + " *proxy-router-windows-amd64.zip\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := checksumFor(path, "proxy-router-linux-amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != sum {
		t.Errorf("got %q, want %q", got, sum)
	}
	got, err = checksumFor(path, "proxy-router-windows-amd64.zip")
	if err != nil || got != strings.Repeat("b", 64) {
		t.Errorf("binary-mode line: got %q, %v", got, err)
	}
	if _, err := checksumFor(path, "missing"); err == nil {
		t.Error("missing checksum didn't fail")
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, archive, map[string]string{
		"proxy-router": "new binary",
		"README.md":    "notes",
	})
	out, err := extract(archive, filepath.Join(dir, "out"), "proxy-router")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new binary" {
		t.Errorf("contents = %q", data)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", fi.Mode().Perm())
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	writeZip(t, archive, map[string]string{
		"proxy-router.exe": "new exe",
		"README.md":        "notes",
	})
	out, err := extract(archive, filepath.Join(dir, "out"), "proxy-router.exe")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new exe" {
		t.Errorf("contents = %q", data)
	}
}

func TestExtractMissing(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, archive, map[string]string{"other": "x"})
	if _, err := extract(archive, filepath.Join(dir, "out"), "proxy-router"); err == nil {
		t.Error("extracting a missing binary didn't fail")
	}
}

// releaseServer serves one release and its files, and returns its URL and
// the archive it built.
func releaseServer(t *testing.T, archiveName, binary string, contents []byte) (*httptest.Server, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if strings.HasSuffix(archiveName, ".zip") {
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(binary)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(contents); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: binary, Mode: 0o755, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(contents); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	sums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archiveName)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repo + "/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v9.9.9",
				"assets": []map[string]any{
					{"name": archiveName, "browser_download_url": srv.URL + "/download/" + archiveName, "size": buf.Len()},
					{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/download/SHA256SUMS", "size": len(sums)},
				},
			})
		case "/download/" + archiveName:
			_, _ = w.Write(buf.Bytes())
		case "/download/SHA256SUMS":
			_, _ = io.WriteString(w, sums)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, buf.Bytes()
}

func TestInstall(t *testing.T) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	archiveName, binary, ok := AssetName(goos, goarch)
	if !ok {
		t.Skipf("unsupported test platform %s/%s", goos, goarch)
	}
	srv, _ := releaseServer(t, archiveName, binary, []byte("new binary"))
	dir := t.TempDir()
	target := filepath.Join(dir, "proxy-router")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := &Client{API: srv.URL}
	rel, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(t.Context(), client, rel, InstallOptions{Target: target}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new binary" {
		t.Errorf("target = %q, want the new binary", data)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", fi.Mode().Perm())
	}
}

func TestInstallChecksumMismatch(t *testing.T) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	archiveName, binary, ok := AssetName(goos, goarch)
	if !ok {
		t.Skipf("unsupported test platform %s/%s", goos, goarch)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: binary, Mode: 0o755, Size: 3})
	_, _ = tw.Write([]byte("new"))
	_ = tw.Close()
	_ = gz.Close()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repo + "/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v9.9.9",
				"assets": []map[string]any{
					{"name": archiveName, "browser_download_url": srv.URL + "/a", "size": buf.Len()},
					{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/sums", "size": 0},
				},
			})
		case "/a":
			_, _ = w.Write(buf.Bytes())
		case "/sums":
			_, _ = fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), archiveName)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "proxy-router")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := &Client{API: srv.URL}
	rel, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = Install(t.Context(), client, rel, InstallOptions{Target: target})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Install error = %v, want a checksum mismatch", err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "old" {
		t.Errorf("target changed despite the bad checksum: %q", data)
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, contents := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, contents := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
