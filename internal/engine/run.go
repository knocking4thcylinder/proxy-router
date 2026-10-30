package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"

	// Registers every Xray protocol, transport and the JSON config loader.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/safetext"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// SetAssetDir tells Xray where geoip.dat / geosite.dat live. In the TUN
// service (config.Confined) it also stops Xray from reading any file
// outside that root-owned directory: certificate files from imported
// outbounds, or its fallbacks under /usr/share/xray.
func SetAssetDir(dir string) {
	os.Setenv("XRAY_LOCATION_ASSET", dir)
	if config.Confined() {
		// Once: reloads call this while Xray may be reading, and the
		// directory doesn't change.
		confineReads.Do(func() {
			filesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
				return openInDir(dir, path)
			}
		})
	}
}

var confineReads sync.Once

// openInDir opens path if it's inside dir, without following symlinks
// out of it.
func openInDir(dir, path string) (*os.File, error) {
	rel, err := filepath.Rel(dir, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("%s: only files in %s can be read here", path, dir)
	}
	return os.OpenInRoot(dir, rel)
}

// Start builds and starts an Xray instance from a JSON-able config.
func Start(cfg map[string]any) (inst *core.Instance, err error) {
	defer recoverXray(&err)
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	inst, err = core.StartInstance("json", data)
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	return inst, nil
}

// recoverXray turns a panic in Xray's config builder (it has a few on
// malformed input) into an error, so a bad subscription can't crash-loop
// the service.
func recoverXray(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("xray: invalid config: %v", r)
	}
}

// Validate checks that Xray accepts the config (including geo lookups)
// without starting it.
func Validate(cfg map[string]any) (err error) {
	defer recoverXray(&err)
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	pb, err := core.LoadConfig("json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	return inst.Close()
}

// PingOptions configures Ping.
type PingOptions struct {
	URL      string
	Timeout  time.Duration
	Parallel int
	// Max simultaneous tests per server IP (0 = no limit).
	PerEndpoint int
	// Interface to bind to ("" = system routing).
	Interface string
	// Config whose Happ-style tweaks (fragment, mux, ...) apply to tests.
	Config *config.Config
	// Resolve, when set, pins server addresses like Plan.Resolve.
	Resolve Resolver
	// Mark is the socket mark for outgoing connections, see MarkSockets.
	Mark int
	// ExitURL, when set, is fetched through each server after the latency
	// test; its body (e.g. a country code) is reported as Exit.
	ExitURL string
	// DownloadURL, when set, is downloaded through each server after the
	// latency test. A server whose transfer stalls fails, and Speed is
	// how fast it arrived.
	DownloadURL string
	// OnProgress is called after each server (or pool member) finishes.
	// Calls are serialized; the callback should return promptly.
	OnProgress func(PingProgress)
}

// PingProgress contains a snapshot of an entry and overall probe progress.
type PingProgress struct {
	Result           PingResult
	Completed, Total int
	// EntryDone means all members of this entry have finished testing.
	EntryDone bool
}

// PingResult is the outcome of a latency test.
type PingResult struct {
	Entry   config.Entry
	Latency time.Duration
	Err     error
	// Exit is what ExitURL returned through the server, e.g. "DE".
	Exit string
	// Speed is how fast DownloadURL arrived, in bytes per second; 0 when
	// it wasn't measured.
	Speed float64
	// For pools: how many members answered, out of how many.
	Alive, Members int
}

// Ping measures a full HTTP request through each server ("real delay":
// includes the proxy handshake), testing up to `parallel` at once.
// It silences Xray's global logger, so don't use it next to a running proxy.
func Ping(ctx context.Context, entries []config.Entry, o PingOptions) []PingResult {
	// Config warnings (e.g. deprecated ciphers) would repeat for every server.
	xlog.RegisterHandler(discardLog{})
	results := make([]PingResult, len(entries))

	// One semaphore per resolved server IP.
	var mu sync.Mutex
	endpoints := map[string]chan struct{}{}
	endpointSem := func(addr string) chan struct{} {
		key := addr
		switch {
		case isIPOrCIDR(addr):
		case o.Resolve != nil:
			// Same lookups as pinning, so server names stay off plain DNS.
			if ip, err := o.Resolve(addr); err == nil {
				key = ip
			}
		default:
			if ips, err := net.DefaultResolver.LookupHost(ctx, addr); err == nil && len(ips) > 0 {
				key = ips[0]
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if endpoints[key] == nil {
			endpoints[key] = make(chan struct{}, o.PerEndpoint)
		}
		return endpoints[key]
	}

	// Pools are tested member by member; each job is one server.
	type job struct {
		result int
		server *share.Server
	}
	var jobs []job
	remaining := make([]int, len(entries))
	for i, e := range entries {
		results[i] = PingResult{Entry: e}
		if members := e.Server.Members(); members != nil {
			results[i].Members = len(members)
			for _, m := range members {
				jobs = append(jobs, job{i, m})
			}
			remaining[i] = len(members)
			continue
		}
		jobs = append(jobs, job{i, e.Server})
		remaining[i] = 1
	}

	completed := 0
	run := func(j job) {
		if o.PerEndpoint > 0 {
			ep := endpointSem(j.server.Address)
			ep <- struct{}{}
			defer func() { <-ep }()
		}
		d, exit, speed, err := pingOne(ctx, j.server, o)

		mu.Lock()
		defer mu.Unlock()
		r := &results[j.result]
		if err == nil {
			r.Alive++
			if r.Err != nil || r.Latency == 0 || d < r.Latency {
				r.Latency, r.Exit, r.Speed, r.Err = d, exit, speed, nil
			}
		} else if r.Latency == 0 {
			r.Err = err
		}
		completed++
		remaining[j.result]--
		if o.OnProgress != nil {
			o.OnProgress(PingProgress{
				Result: *r, Completed: completed, Total: len(jobs),
				EntryDone: remaining[j.result] == 0,
			})
		}
	}
	// A fixed set of workers: a provider's pool can have any number of
	// members, and each test starts an Xray instance.
	queue := make(chan job)
	var wg sync.WaitGroup
	for range min(max(o.Parallel, 1), maxPingParallel, max(len(jobs), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				run(j)
			}
		}()
	}
	for _, j := range jobs {
		queue <- j
	}
	close(queue)
	wg.Wait()
	return results
}

// ControlSockets runs ctl on every socket Xray opens in this process,
// before it connects or binds. It can't be undone, so it's only for
// one-shot commands like ping.
func ControlSockets(ctl func(network, address string, c syscall.RawConn) error) error {
	return internet.RegisterDialerController(ctl)
}

// maxPingParallel caps how many servers Ping tests at once.
const maxPingParallel = 64

type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}

func pingOne(ctx context.Context, s *share.Server, o PingOptions) (time.Duration, string, float64, error) {
	url, timeout := o.URL, o.Timeout
	inst, transport, err := startThrough(s, o, url)
	if err != nil {
		return 0, "", 0, err
	}
	defer inst.Close()

	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, "", 0, fmt.Errorf("HTTP %s", resp.Status)
	}
	latency := time.Since(start)

	var speed float64
	if o.DownloadURL != "" {
		// A stall is a few timeouts without data; the whole download gets
		// more, so a slow but working server still finishes.
		dl, err := Download(ctx, &http.Client{Transport: transport}, o.DownloadURL, timeout, 4*timeout)
		if err != nil {
			return 0, "", 0, err
		}
		speed = dl.Speed()
	}

	exit := ""
	if o.ExitURL != "" {
		exit = "?"
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.ExitURL, nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
				resp.Body.Close()
				if v := safetext.Clean(string(b), 0); resp.StatusCode == http.StatusOK && v != "" && len(v) < 40 {
					exit = v
				}
			}
		}
	}
	return latency, exit, speed, nil
}

// Downloaded is the outcome of Download.
type Downloaded struct {
	Bytes int64
	Took  time.Duration
	// Unmeasured: the URL didn't answer 200 (the test site refusing, not
	// the server failing), so nothing was measured.
	Unmeasured bool
}

// Speed is in bytes per second.
func (d Downloaded) Speed() float64 {
	if d.Unmeasured || d.Took <= 0 {
		return 0
	}
	return float64(d.Bytes) / d.Took.Seconds()
}

// ErrStalled is returned by Download when data stops arriving.
var ErrStalled = errors.New("stalled")

// Download fetches url with client and times it. Censors often let a
// connection to a proxy start and then cut it after ~16 KB, which a short
// request like the latency test never notices: Download fails with
// ErrStalled when nothing arrives for stall, and with a timeout when the
// whole transfer takes longer than limit. Its size is the url's to say
// (e.g. speed.cloudflare.com/__down?bytes=...), capped at 64 MB.
func Download(ctx context.Context, client *http.Client, url string, stall, limit time.Duration) (Downloaded, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, limit, errDownloadSlow)
	defer cancel()
	stalled := false
	var mu sync.Mutex
	timer := time.AfterFunc(stall, func() {
		mu.Lock()
		stalled = true
		mu.Unlock()
		cancel()
	})
	defer timer.Stop()
	var d Downloaded
	fail := func(err error) (Downloaded, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case stalled:
			return d, fmt.Errorf("download %w after %s (connection cut, likely blocked)", ErrStalled, kb(d.Bytes))
		case errors.Is(context.Cause(ctx), errDownloadSlow):
			return d, fmt.Errorf("download too slow: %s in %s", kb(d.Bytes), limit)
		}
		return d, fmt.Errorf("download: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return d, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Downloaded{Unmeasured: true}, nil
	}
	buf := make([]byte, 32<<10)
	body := io.LimitReader(resp.Body, 64<<20)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			d.Bytes += int64(n)
			timer.Reset(stall)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
	}
	d.Took = time.Since(start)
	return d, nil
}

var errDownloadSlow = errors.New("download took too long")

func kb(n int64) string { return fmt.Sprintf("%d KB", (n+512)/1024) }

// CheckOutbound downloads url through the outbound tagged tag of a
// running instance, as Download does, to see whether the server it uses
// still carries traffic.
func CheckOutbound(ctx context.Context, inst *core.Instance, tag, url string, stall, limit time.Duration) (Downloaded, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination("tcp:" + addr)
			if err != nil {
				return nil, err
			}
			return core.Dial(session.SetForcedOutboundTagToContext(ctx, tag), inst, dest)
		},
	}
	defer transport.CloseIdleConnections()
	return Download(ctx, &http.Client{Transport: transport}, url, stall, limit)
}

// ProxyClient returns an HTTP client whose connections go through s, set
// up like the running proxy's outbound (o's tweaks, pinning, interface and
// mark), and a func that stops it. url is what will be fetched: with
// resolve_locally its host is resolved outside the tunnel. A pool goes
// through its first member.
func ProxyClient(s *share.Server, o PingOptions, url string) (*http.Client, func(), error) {
	inst, transport, err := startThrough(s, o, url)
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{Transport: transport}, func() {
		transport.CloseIdleConnections()
		inst.Close()
	}, nil
}

// startThrough starts an Xray instance with only s's outbounds, and returns
// a transport whose connections go through it.
func startThrough(s *share.Server, o PingOptions, url string) (*core.Instance, *http.Transport, error) {
	obs, err := s.Outbounds("proxy")
	if err != nil {
		return nil, nil, err
	}
	if o.Config != nil {
		obs, _ = ApplyTweaks(obs, o.Config)
	}
	if o.Resolve != nil {
		PinAddresses(obs, o.Resolve)
	}
	obs = BindInterface(obs, o.Interface)
	xc := map[string]any{
		"log":       map[string]any{"loglevel": "none", "access": "none"},
		"outbounds": obs,
	}
	if o.Config != nil && o.Config.ResolveLocally {
		hosts := hostnames(obs)
		if u, err := neturl.Parse(url); err == nil {
			hosts = append(hosts, u.Hostname())
		}
		xc["dns"] = o.Config.LocalDNS(hosts)
		// The server's name and the test host resolve outside the tunnel.
		xc["outbounds"] = append(obs, BindInterface([]map[string]any{{"tag": "direct", "protocol": "freedom"}}, o.Interface)...)
		xc["routing"] = map[string]any{"rules": []any{
			map[string]any{"inboundTag": []string{config.DirectDNSTag}, "outboundTag": "direct"},
			map[string]any{"network": "tcp,udp", "outboundTag": "proxy"},
		}}
	}
	MarkSockets(xc, o.Mark)
	inst, err := Start(xc)
	if err != nil {
		return nil, nil, err
	}
	return inst, &http.Transport{
		DisableKeepAlives: true,
		// core.Dial returns a logical connection before the proxy has
		// connected. Bound the TLS handshake and response wait so a dead
		// pool member doesn't consume the whole asset download timeout.
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination("tcp:" + addr)
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}, nil
}

// maxAsset caps geo file downloads (geoip.dat is around 20 MB).
var maxAsset int64 = 256 << 20

// DownloadAsset fetches url into dir/name atomically, with client (nil:
// http.DefaultClient).
func DownloadAsset(ctx context.Context, client *http.Client, url, dir, name string) (int64, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: %s", url, resp.Status)
	}
	if resp.ContentLength > maxAsset {
		return 0, fmt.Errorf("%s: larger than %d MB", url, maxAsset>>20)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	config.GiveBack(dir)
	n, err := config.WriteReaderAtomic(filepath.Join(dir, name), &assetReader{r: resp.Body, left: maxAsset}, 0o644)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", url, err)
	}
	return n, nil
}

// assetReader fails a download that is empty or larger than left, so
// it's never renamed into place.
type assetReader struct {
	r    io.Reader
	left int64
	read bool
}

func (a *assetReader) Read(p []byte) (int, error) {
	if int64(len(p)) > a.left+1 {
		p = p[:a.left+1]
	}
	n, err := a.r.Read(p)
	a.left -= int64(n)
	a.read = a.read || n > 0
	switch {
	case a.left < 0:
		return 0, fmt.Errorf("larger than %d MB", maxAsset>>20)
	case err == io.EOF && !a.read:
		return 0, errors.New("empty file")
	}
	return n, err
}

// splitHostPort splits a listen address. An empty host means loopback:
// listening on every interface has to be asked for (0.0.0.0, [::]).
func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%q: expected host:port", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%q: bad port", addr)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port, nil
}
