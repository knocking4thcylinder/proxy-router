// Package subscription downloads and decodes proxy subscriptions.
package subscription

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// Request describes how to fetch a subscription.
type Request struct {
	URL       string
	UserAgent string
	Headers   map[string]string
	// HWID, when set, is sent as x-hwid along with device headers, which
	// panels with device limits (e.g. Remnawave) require.
	HWID string
}

// Info is metadata providers send in response headers.
type Info struct {
	Title          string    `json:"title,omitempty"`
	Upload         int64     `json:"upload,omitempty"`
	Download       int64     `json:"download,omitempty"`
	Total          int64     `json:"total,omitempty"`
	Expire         time.Time `json:"expire,omitzero"`
	UpdateInterval int       `json:"update_interval_hours,omitempty"`
	SupportURL     string    `json:"support_url,omitempty"`
	WebPageURL     string    `json:"web_page_url,omitempty"`
	Announce       string    `json:"announce,omitempty"`
}

// Result is a fetched and decoded subscription.
type Result struct {
	Info    Info
	Servers []*share.Server
	// Errors are entries that couldn't be parsed; the rest are still usable.
	Errors []error
}

const DefaultUserAgent = "proxy-router/1.0"

// Fetch downloads and decodes a subscription.
func Fetch(ctx context.Context, req Request) (*Result, error) {
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("subscription URL must be http(s): %q", req.URL)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, err
	}
	ua := req.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	hreq.Header.Set("User-Agent", ua)
	hreq.Header.Set("Accept", "*/*")
	if req.HWID != "" {
		hreq.Header.Set("x-hwid", req.HWID)
		hreq.Header.Set("x-device-os", deviceOS())
		hreq.Header.Set("x-device-model", "proxy-router")
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, snippet(body))
	}

	res := Decode(body)
	res.Info = parseInfo(resp.Header)
	if len(res.Servers) == 0 {
		msg := "subscription contains no usable servers"
		if len(res.Errors) > 0 {
			msg += fmt.Sprintf(" (first error: %v)", res.Errors[0])
		} else if len(body) > 0 {
			msg += fmt.Sprintf(" (body starts with %q)", snippet(body))
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return res, nil
}

// Decode turns a subscription body into servers. It accepts Xray JSON
// (object or array), base64 encoded link lists and plain link lists.
func Decode(body []byte) *Result {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\uFEFF"))
	res := &Result{}
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		res.Servers, res.Errors = share.ParseXrayJSON([]byte(text))
		return res
	}
	if !strings.Contains(text, "://") {
		if dec, err := share.DecodeBase64(text); err == nil {
			text = strings.TrimSpace(string(dec))
			if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
				res.Servers, res.Errors = share.ParseXrayJSON([]byte(text))
				return res
			}
		}
	}
	res.Servers, res.Errors = share.ParseLinks(text)
	return res
}

func parseInfo(h http.Header) Info {
	var info Info
	info.Title = decodeMaybeBase64(h.Get("profile-title"))
	if info.Title == "" {
		if _, params, ok := strings.Cut(h.Get("content-disposition"), "filename="); ok {
			info.Title = strings.Trim(params, `"' `)
		}
	}
	for _, part := range strings.Split(h.Get("subscription-userinfo"), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.TrimSpace(k) {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			if n > 0 {
				info.Expire = time.Unix(n, 0)
			}
		}
	}
	info.UpdateInterval, _ = strconv.Atoi(strings.TrimSpace(h.Get("profile-update-interval")))
	info.SupportURL = h.Get("support-url")
	info.WebPageURL = h.Get("profile-web-page-url")
	info.Announce = decodeMaybeBase64(h.Get("announce"))
	return info
}

// Headers like profile-title may be "base64:<data>".
func decodeMaybeBase64(v string) string {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		if dec, err := share.DecodeBase64(rest); err == nil {
			return strings.TrimSpace(string(dec))
		}
	}
	return v
}

func deviceOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return runtime.GOOS
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
