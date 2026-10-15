// Package subscription downloads and decodes proxy subscriptions.
package subscription

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/knocking4thcylinder/proxy-router/internal/safetext"
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
	// AllowHTTP accepts a plain http:// URL, which anyone on the path can
	// tamper with.
	AllowHTTP bool
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

// DefaultUserAgent is Happ's: panels pick the format by User-Agent and give
// Happ full Xray JSON configs, including balanced "Auto" entries that plain
// link lists leave out.
const DefaultUserAgent = "Happ/3.24.1"

// Lengths provider text is cut to.
const (
	maxName  = 128
	maxText  = 1024
	maxError = 300
)

// Fetch downloads and decodes a subscription. Errors never contain the
// URL's path or query, which usually hold the access token.
func Fetch(ctx context.Context, req Request) (*Result, error) {
	return defaultPolicy.fetch(ctx, req)
}

func (p policy) fetch(ctx context.Context, req Request) (*Result, error) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("subscription URL must be https: %s", Redact(req.URL))
	}
	if u.Scheme == "http" && !req.AllowHTTP {
		return nil, ErrInsecureURL
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("subscription URL %s: bad request", Redact(req.URL))
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

	client := p.client(u, p.local(ctx, u), req.AllowHTTP, req.Headers)
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, redactErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", safetext.Clean(resp.Status, 80))
	}
	// The transport has already undone any gzip, so this caps the real size.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", redactErr(err))
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("subscription is larger than %d MiB", maxBody>>20)
	}

	res := Decode(body)
	res.Info = parseInfo(resp.Header)
	if len(res.Servers) == 0 {
		msg := "subscription contains no usable servers"
		if len(res.Errors) > 0 {
			msg += fmt.Sprintf(" (first error: %v)", res.Errors[0])
		} else if len(body) > 0 {
			msg += fmt.Sprintf(" (%d bytes in no format it understands)", len(body))
		}
		return nil, errors.New(msg)
	}
	return res, nil
}

// Decode turns a subscription body into servers. It accepts Xray JSON
// (object or array), base64 encoded link lists and plain link lists.
// Names, warnings and errors come back safe to print.
func Decode(body []byte) *Result {
	res := decode(body)
	CleanServers(res.Servers)
	for i, err := range res.Errors {
		res.Errors[i] = errors.New(safetext.Clean(err.Error(), maxError))
	}
	return res
}

func decode(body []byte) *Result {
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

// CleanServers strips control characters and escape sequences from the
// provider-controlled names and warnings of servers.
func CleanServers(servers []*share.Server) {
	for _, s := range servers {
		s.Name = safetext.Clean(s.Name, maxName)
		if s.Name == "" {
			s.Name = safetext.Clean(fmt.Sprintf("%s:%d", s.Address, s.Port), maxName)
		}
		for i, w := range s.Warnings {
			s.Warnings[i] = safetext.Clean(w, maxError)
		}
	}
}

func parseInfo(h http.Header) Info {
	var info Info
	info.Title = safetext.Clean(decodeMaybeBase64(h.Get("profile-title")), maxName)
	if info.Title == "" {
		if _, params, ok := strings.Cut(h.Get("content-disposition"), "filename="); ok {
			info.Title = safetext.Clean(strings.Trim(params, `"' `), maxName)
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
	info.SupportURL = safetext.Clean(h.Get("support-url"), maxText)
	info.WebPageURL = safetext.Clean(h.Get("profile-web-page-url"), maxText)
	info.Announce = safetext.Clean(decodeMaybeBase64(h.Get("announce")), maxText)
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
