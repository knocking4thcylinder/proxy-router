package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"

	// Registers every Xray protocol, transport and the JSON config loader.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
	"github.com/knocking4thcylinder/proxy-router/internal/share"
)

// SetAssetDir tells Xray where geoip.dat / geosite.dat live.
func SetAssetDir(dir string) {
	os.Setenv("XRAY_LOCATION_ASSET", dir)
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
	// ExitURL, when set, is fetched through each server after the latency
	// test; its body (e.g. a country code) is reported as Exit.
	ExitURL string
}

// PingResult is the outcome of a latency test.
type PingResult struct {
	Entry   config.Entry
	Latency time.Duration
	Err     error
	// Exit is what ExitURL returned through the server, e.g. "DE".
	Exit string
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
		if ips, err := net.DefaultResolver.LookupHost(ctx, addr); err == nil && len(ips) > 0 {
			key = ips[0]
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
	for i, e := range entries {
		results[i] = PingResult{Entry: e}
		if members := e.Server.Members(); members != nil {
			results[i].Members = len(members)
			for _, m := range members {
				jobs = append(jobs, job{i, m})
			}
			continue
		}
		jobs = append(jobs, job{i, e.Server})
	}

	run := func(j job) {
		if o.PerEndpoint > 0 {
			ep := endpointSem(j.server.Address)
			ep <- struct{}{}
			defer func() { <-ep }()
		}
		d, exit, err := pingOne(ctx, j.server, o)

		mu.Lock()
		defer mu.Unlock()
		r := &results[j.result]
		if err == nil {
			r.Alive++
			if r.Err != nil || r.Latency == 0 || d < r.Latency {
				r.Latency, r.Exit, r.Err = d, exit, nil
			}
		} else if r.Latency == 0 {
			r.Err = err
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

// maxPingParallel caps how many servers Ping tests at once.
const maxPingParallel = 64

type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}

func pingOne(ctx context.Context, s *share.Server, o PingOptions) (time.Duration, string, error) {
	url, timeout := o.URL, o.Timeout
	obs, err := s.Outbounds("proxy")
	if err != nil {
		return 0, "", err
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
	inst, err := Start(xc)
	if err != nil {
		return 0, "", err
	}
	defer inst.Close()

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := xnet.ParseDestination("tcp:" + addr)
				if err != nil {
					return nil, err
				}
				return core.Dial(ctx, inst, dest)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, "", fmt.Errorf("HTTP %s", resp.Status)
	}
	latency := time.Since(start)

	exit := ""
	if o.ExitURL != "" {
		exit = "?"
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.ExitURL, nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
				resp.Body.Close()
				if v := strings.TrimSpace(string(b)); resp.StatusCode == http.StatusOK && v != "" && len(v) < 40 {
					exit = v
				}
			}
		}
	}
	return latency, exit, nil
}

// DownloadAsset fetches url into dir/name atomically.
func DownloadAsset(ctx context.Context, url, dir, name string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: %s", url, resp.Status)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	config.GiveBack(dir)
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, resp.Body)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	config.GiveBack(tmp.Name())
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("%s: empty file", url)
	}
	return n, os.Rename(tmp.Name(), filepath.Join(dir, name))
}

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
		host = "0.0.0.0"
	}
	return host, port, nil
}
