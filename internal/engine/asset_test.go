package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadAsset(t *testing.T) {
	old := maxAsset
	maxAsset = 1000
	t.Cleanup(func() { maxAsset = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(strings.Repeat("x", 1000)))
		case "/declared":
			w.Header().Set("Content-Length", "5000")
			w.Write([]byte(strings.Repeat("x", 5000)))
		case "/streamed":
			// No Content-Length: only the copy can catch it.
			for range 10 {
				w.Write([]byte(strings.Repeat("x", 300)))
				w.(http.Flusher).Flush()
			}
		case "/empty":
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "assets")

	if n, err := DownloadAsset(context.Background(), srv.URL+"/ok", dir, "geoip.dat"); err != nil || n != 1000 {
		t.Fatalf("ok: %d, %v", n, err)
	}
	for _, path := range []string{"/declared", "/streamed", "/empty"} {
		if _, err := DownloadAsset(context.Background(), srv.URL+path, dir, "geosite.dat"); err == nil {
			t.Errorf("%s: no error", path)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "geoip.dat" {
		t.Errorf("assets: %v, want only geoip.dat", entries)
	}
}

func TestOpenInDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.dat")); err != nil {
		t.Fatal(err)
	}
	f, err := openInDir(dir, filepath.Join(dir, "geoip.dat"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, path := range []string{outside, filepath.Join(dir, "..", "x"), filepath.Join(dir, "link.dat"), "/usr/share/xray/geoip.dat"} {
		if f, err := openInDir(dir, path); err == nil {
			f.Close()
			t.Errorf("%s: opened", path)
		}
	}
}
