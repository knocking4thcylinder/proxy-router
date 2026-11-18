// Package update installs new proxy-router releases from GitHub.
//
// A release archive is downloaded over HTTPS and checked against the
// SHA256SUMS file published with it. The checksum catches corruption and
// tampering in transit; it isn't a signature, so it comes from the same
// place as the archive.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are published from.
const Repo = "knocking4thcylinder/proxy-router"

// Release channels. Stable is the default; nightly follows the rolling
// prerelease that is rebuilt from master.
const (
	StableChannel  = "stable"
	NightlyChannel = "nightly"
	// NightlyTag is the fixed tag of the rolling nightly release. A release
	// tag can't change, so the version is carried in the release name
	// instead; see Release.Version.
	NightlyTag = "nightly"
)

const (
	// apiTimeout bounds the release metadata requests.
	apiTimeout = 30 * time.Second
	// maxMetadata caps the release JSON and SHA256SUMS downloads.
	maxMetadata = 1 << 20
	// maxArchive caps a release archive.
	maxArchive = 200 << 20
	// maxBinary caps the unpacked executable.
	maxBinary = 300 << 20
)

// Asset is one file attached to a release.
type Asset struct {
	Name   string
	URL    string
	Size   int64
	Digest string
}

// Release is a GitHub release and its downloadable files.
type Release struct {
	Tag    string
	Name   string
	Assets map[string]Asset
}

// Version is the release's version: its tag for a normal release, or its
// name for the rolling nightly, whose tag stays "nightly". It returns ""
// when neither is a version.
func (r *Release) Version() string {
	if r == nil {
		return ""
	}
	if r.Tag == NightlyTag && IsRelease(r.Name) {
		return NormalizeTag(r.Name)
	}
	if IsRelease(r.Tag) {
		return NormalizeTag(r.Tag)
	}
	return ""
}

// Asset returns the named asset.
func (r *Release) Asset(name string) (Asset, bool) {
	a, ok := r.Assets[name]
	return a, ok
}

// Client reads releases from GitHub. The zero value uses the public API;
// tests point API at a local server.
type Client struct {
	HTTP *http.Client
	API  string
}

// NewClient returns a client for the public GitHub API.
func NewClient() *Client { return &Client{} }

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (c *Client) api() string {
	if c != nil && c.API != "" {
		return strings.TrimSuffix(c.API, "/")
	}
	return "https://api.github.com"
}

// Latest returns the latest published release. GitHub leaves drafts and
// prereleases out of this.
func (c *Client) Latest(ctx context.Context) (*Release, error) {
	return c.release(ctx, "latest")
}

// Nightly returns the rolling nightly release. It is published as a
// prerelease, so Latest never sees it, and its name holds the version of
// the build.
func (c *Client) Nightly(ctx context.Context) (*Release, error) {
	return c.ByTag(ctx, NightlyTag)
}

// ByTag returns a release by tag ("v0.1.0" or "0.1.0").
func (c *Client) ByTag(ctx context.Context, tag string) (*Release, error) {
	tag = NormalizeTag(tag)
	if tag == "" {
		return nil, errors.New("no version given")
	}
	return c.release(ctx, "tags/"+url.PathEscape(tag))
}

func (c *Client) release(ctx context.Context, path string) (*Release, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	u := c.api() + "/repos/" + Repo + "/releases/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "proxy-router-updater")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("check GitHub: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("release not found: %s", strings.TrimPrefix(path, "tags/"))
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("check GitHub: %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
		} `json:"assets"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxMetadata))
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("read the GitHub release: %w", err)
	}
	if body.TagName == "" {
		return nil, errors.New("the latest GitHub release has no tag")
	}
	rel := &Release{Tag: NormalizeTag(body.TagName), Name: body.Name, Assets: map[string]Asset{}}
	for _, a := range body.Assets {
		if a.Name == "" || a.BrowserDownloadURL == "" {
			continue
		}
		rel.Assets[a.Name] = Asset{Name: a.Name, URL: a.BrowserDownloadURL, Size: a.Size, Digest: a.Digest}
	}
	return rel, nil
}

// AssetName returns the release archive and executable name for goos and
// goarch.
func AssetName(goos, goarch string) (archive, binary string, ok bool) {
	switch goos {
	case "linux":
		archive, binary = "linux", "proxy-router"
	case "darwin":
		if goarch != "arm64" {
			return "", "", false
		}
		archive, binary = "macos", "proxy-router"
	case "windows":
		archive, binary = "windows", "proxy-router.exe"
	default:
		return "", "", false
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", "", false
	}
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("proxy-router-%s-%s%s", archive, goarch, ext), binary, true
}

// InstallOptions controls Install.
type InstallOptions struct {
	// Target is the executable to replace; defaults to the running one.
	Target string
	// GOOS and GOARCH select the archive; they default to this build's.
	GOOS, GOARCH string
	// Log, if set, reports progress.
	Log func(format string, args ...any)
	// BeforeReplace, if set, receives the verified executable after the
	// replacement has been prepared, while the original target still exists.
	// Returning an error cancels the replacement.
	BeforeReplace func(source string) error
}

// Install downloads rel's archive for this platform, verifies its SHA-256
// against the release's SHA256SUMS and atomically replaces the target.
func Install(ctx context.Context, c *Client, rel *Release, o InstallOptions) error {
	if o.Target == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		o.Target = exe
	}
	tmp, err := os.MkdirTemp("", "proxy-router-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	source, err := downloadBinary(ctx, c, rel, tmp, o.GOOS, o.GOARCH, o.Log)
	if err != nil {
		return err
	}
	if err := replaceBinary(o.Target, source, o.BeforeReplace); err != nil {
		return err
	}
	if o.Log != nil {
		o.Log("installed %s", filepath.Clean(o.Target))
	}
	return nil
}

// DownloadBinary verifies and extracts the current platform's release in a
// private temporary directory supplied by the caller.
func DownloadBinary(ctx context.Context, c *Client, rel *Release, dir string) (string, error) {
	return downloadBinary(ctx, c, rel, dir, "", "", nil)
}

func downloadBinary(ctx context.Context, c *Client, rel *Release, tmp, goos, goarch string, logf func(string, ...any)) (string, error) {
	if rel == nil {
		return "", errors.New("no release to install")
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	archiveName, binaryName, ok := AssetName(goos, goarch)
	if !ok {
		return "", fmt.Errorf("there are no releases for %s/%s", goos, goarch)
	}
	archive, ok := rel.Asset(archiveName)
	if !ok {
		return "", fmt.Errorf("release %s doesn't include %s", rel.Tag, archiveName)
	}
	sums, ok := rel.Asset("SHA256SUMS")
	if !ok {
		return "", fmt.Errorf("release %s doesn't include SHA256SUMS", rel.Tag)
	}

	archivePath := filepath.Join(tmp, archiveName)
	logf("downloading %s (%.1f MiB)", archiveName, float64(archive.Size)/(1<<20))
	if err := download(ctx, c.httpClient(), archive.URL, archivePath, maxArchive); err != nil {
		return "", err
	}
	sumsPath := filepath.Join(tmp, "SHA256SUMS")
	if err := download(ctx, c.httpClient(), sums.URL, sumsPath, maxMetadata); err != nil {
		return "", err
	}
	want, err := checksumFor(sumsPath, archiveName)
	if err != nil {
		return "", err
	}
	// A rolling nightly can be replaced between reading the release metadata
	// and downloading its archive and manifest.
	if archive.Digest != "" && !strings.EqualFold(archive.Digest, "sha256:"+want) {
		return "", errors.New("release archive changed after the update check; retry the update")
	}
	logf("verifying SHA-256")
	if err := verifySHA256(archivePath, want); err != nil {
		return "", err
	}

	return extract(archivePath, filepath.Join(tmp, "unpacked"), binaryName)
}

// download fetches url into path, refusing to read more than limit bytes.
func download(ctx context.Context, client *http.Client, url, path string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "proxy-router-updater")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", path, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > limit {
		return fmt.Errorf("download %s: file is larger than %d bytes", filepath.Base(path), limit)
	}
	return nil
}
