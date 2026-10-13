package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
func Start(cfg map[string]any) (*core.Instance, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	inst, err := core.StartInstance("json", data)
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	return inst, nil
}

// Validate checks that Xray accepts the config (including geo lookups)
// without starting it. With a TUN inbound, creating the instance would
// create the interface (and need root), so only the config is checked.
func Validate(cfg map[string]any) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	pb, err := core.LoadConfig("json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	if hasTUN(cfg) {
		return nil
	}
	inst, err := core.New(pb)
	if err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	return inst.Close()
}

func hasTUN(cfg map[string]any) bool {
	ins, _ := cfg["inbounds"].([]map[string]any)
	for _, in := range ins {
		if in["protocol"] == "tun" {
			return true
		}
	}
	return false
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
}

// PingResult is the outcome of a latency test.
type PingResult struct {
	Entry   config.Entry
	Latency time.Duration
	Err     error
}

// Ping measures a full HTTP request through each server ("real delay":
// includes the proxy handshake), testing up to `parallel` at once.
// It silences Xray's global logger, so don't use it next to a running proxy.
func Ping(ctx context.Context, entries []config.Entry, o PingOptions) []PingResult {
	// Config warnings (e.g. deprecated ciphers) would repeat for every server.
	xlog.RegisterHandler(discardLog{})
	results := make([]PingResult, len(entries))
	sem := make(chan struct{}, max(o.Parallel, 1))

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

	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o.PerEndpoint > 0 {
				ep := endpointSem(e.Server.Address)
				ep <- struct{}{}
				defer func() { <-ep }()
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := pingOne(ctx, e.Server, o)
			results[i] = PingResult{Entry: e, Latency: d, Err: err}
		}()
	}
	wg.Wait()
	return results
}

type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}

func pingOne(ctx context.Context, s *share.Server, o PingOptions) (time.Duration, error) {
	url, timeout := o.URL, o.Timeout
	obs, err := s.Outbounds("proxy")
	if err != nil {
		return 0, err
	}
	if o.Config != nil {
		obs, _ = ApplyTweaks(obs, o.Config)
	}
	obs = BindInterface(obs, o.Interface)
	inst, err := Start(map[string]any{
		"log":       map[string]any{"loglevel": "none", "access": "none"},
		"outbounds": obs,
	})
	if err != nil {
		return 0, err
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
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %s", resp.Status)
	}
	return time.Since(start), nil
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
