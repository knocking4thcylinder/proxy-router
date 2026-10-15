package share

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Outbounds come from subscription providers, and in TUN mode Xray runs as
// root, so they are rebuilt from the fields below instead of being passed
// through. Anything else is dropped: options that read local files
// (certificates, key logs), touch the host's network stack (sockopt marks
// and interfaces, kernel WireGuard), open reverse tunnels or only make
// sense on a server. Null values are dropped too; Xray's config builder
// crashes on some of them.

// Protocols a server can use.
var proxyProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"socks": true, "http": true, "hysteria": true, "wireguard": true,
}

// cleaner collects the paths it drops.
type cleaner struct {
	dropped []string
}

func (c *cleaner) drop(path string) {
	if !slices.Contains(c.dropped, path) {
		c.dropped = append(c.dropped, path)
	}
}

// A rule returns the cleaned value, or false to drop it.
type rule func(c *cleaner, path string, v any) (any, bool)

type fields map[string]rule

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func object(f fields) rule {
	return func(c *cleaner, path string, v any) (any, bool) {
		m, ok := v.(map[string]any)
		if !ok {
			c.drop(path)
			return nil, false
		}
		out := map[string]any{}
		for k, val := range m {
			r, ok := f[k]
			if !ok {
				c.drop(join(path, k))
				continue
			}
			if val == nil {
				continue
			}
			if nv, ok := r(c, join(path, k), val); ok {
				out[k] = nv
			}
		}
		return out, true
	}
}

// list keeps the elements of an array that pass r, skipping nulls.
func list(r rule) rule {
	return func(c *cleaner, path string, v any) (any, bool) {
		items, ok := v.([]any)
		if !ok {
			c.drop(path)
			return nil, false
		}
		out := []any{}
		for _, item := range items {
			if item == nil {
				continue
			}
			if nv, ok := r(c, path+"[]", item); ok {
				out = append(out, nv)
			}
		}
		return out, true
	}
}

func scalar(c *cleaner, path string, v any) (any, bool) {
	switch v.(type) {
	case string, float64, bool:
		return v, true
	}
	c.drop(path)
	return nil, false
}

// scalars is a value or a list of values (Xray's StringList).
func scalars(c *cleaner, path string, v any) (any, bool) {
	if _, ok := v.([]any); ok {
		return list(scalar)(c, path, v)
	}
	return scalar(c, path, v)
}

func stringMap(c *cleaner, path string, v any) (any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		c.drop(path)
		return nil, false
	}
	out := map[string]any{}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		} else if val != nil {
			c.drop(join(path, k))
		}
	}
	return out, true
}

// data is plain data Xray parses without side effects (headers, ranges,
// mask settings); it's copied without nulls.
func data(_ *cleaner, _ string, v any) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			if val != nil {
				out[k], _ = data(nil, "", val)
			}
		}
		return out, true
	case []any:
		out := []any{}
		for _, val := range x {
			if val != nil {
				nv, _ := data(nil, "", val)
				out = append(out, nv)
			}
		}
		return out, true
	}
	return v, true
}

// masks keeps finalmask entries of the given types.
func masks(types ...string) rule {
	entry := object(fields{"type": scalar, "settings": data})
	return list(func(c *cleaner, path string, v any) (any, bool) {
		m, _ := v.(map[string]any)
		t, _ := m["type"].(string)
		if !slices.Contains(types, t) {
			c.drop(fmt.Sprintf("%s(%s)", path, t))
			return nil, false
		}
		return entry(c, path, v)
	})
}

func fieldsOf(names ...string) fields {
	f := fields{}
	for _, n := range names {
		f[n] = scalars
	}
	return f
}

func with(f fields, extra fields) fields {
	out := fields{}
	for k, v := range f {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var (
	tlsRule = object(fieldsOf(
		"serverName", "alpn", "fingerprint", "minVersion", "maxVersion", "cipherSuites",
		"curvePreferences", "enableSessionResumption", "pinnedPeerCertSha256",
		"verifyPeerCertByName", "verifyPeerCertInNames", "echConfigList", "echForceQuery",
	))
	realityRule = object(fieldsOf(
		"serverName", "fingerprint", "password", "publicKey", "shortId", "spiderX", "mldsa65Verify",
	))
	// No mark, interface, tproxy, customSockopt or tcpCongestion: they
	// change how the host routes or tunes sockets. BindInterface sets the
	// interface itself.
	sockoptRule = object(with(fieldsOf(
		"domainStrategy", "dialerProxy", "tcpFastOpen", "tcpKeepAliveInterval", "tcpKeepAliveIdle",
		"tcpUserTimeout", "tcpWindowClamp", "tcpMaxSeg", "tcpMptcp", "v6only", "penetrate",
		"addressPortStrategy",
	), fields{"happyEyeballs": object(fieldsOf("prioritizeIPv6", "tryDelayMs", "interleave", "maxConcurrentTry"))}))
	finalmaskRule = object(fields{
		"tcp": masks("header-custom", "fragment", "sudoku"),
		// Not xicmp: it opens raw ICMP sockets.
		"udp": masks("header-custom", "header-dns", "header-dtls", "header-srtp", "header-utp",
			"header-wechat", "header-wireguard", "mkcp-original", "mkcp-aes128gcm", "noise",
			"salamander", "sudoku", "xdns"),
		// Not debug: it sets environment variables.
		"quicParams": object(with(fieldsOf(
			"congestion", "initStreamReceiveWindow", "maxStreamReceiveWindow",
			"initConnectionReceiveWindow", "maxConnectionReceiveWindow", "maxIdleTimeout",
			"keepAlivePeriod", "disablePathMTUDiscovery", "maxIncomingStreams",
		), fields{"brutalUp": data, "brutalDown": data, "udpHop": data})),
	})
	headersFields = fields{"host": scalar, "path": scalar, "headers": stringMap}
)

// streamRule cleans streamSettings. Inside XHTTP's downloadSettings, which
// is itself a streamSettings, the download address and port are allowed.
func streamRule(download bool) rule {
	f := fields{
		"network":             scalar,
		"security":            scalar,
		"tlsSettings":         tlsRule,
		"realitySettings":     realityRule,
		"rawSettings":         object(fields{"header": data}),
		"tcpSettings":         object(fields{"header": data}),
		"wsSettings":          object(with(headersFields, fields{"heartbeatPeriod": scalar})),
		"httpupgradeSettings": object(headersFields),
		"grpcSettings": object(fieldsOf("authority", "serviceName", "multiMode", "idle_timeout",
			"health_check_timeout", "permit_without_stream", "initial_windows_size", "user_agent")),
		"kcpSettings": object(with(fieldsOf("mtu", "tti", "uplinkCapacity", "downlinkCapacity",
			"congestion", "readBufferSize", "writeBufferSize", "seed"), fields{"header": data})),
		"xhttpSettings":     xhttpRule(download),
		"splithttpSettings": xhttpRule(download),
		"hysteriaSettings": object(with(fieldsOf("version", "auth", "udpIdleTimeout", "congestion", "up", "down"),
			fields{"udphop": data})),
		"finalmask": finalmaskRule,
		"sockopt":   sockoptRule,
	}
	if download {
		f["address"] = scalar
		f["port"] = scalar
	}
	return object(f)
}

// xhttpRule cleans xhttpSettings. Xray replaces the settings with "extra"
// (keeping host, path and mode), so that's what gets cleaned. A download
// connection can't have its own downloadSettings.
func xhttpRule(download bool) rule {
	f := with(headersFields, fieldsOf(
		"mode", "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement",
		"xPaddingMethod", "uplinkHTTPMethod", "sessionPlacement", "sessionKey", "seqPlacement",
		"seqKey", "uplinkDataPlacement", "uplinkDataKey", "noGRPCHeader", "noSSEHeader",
		"scMaxBufferedPosts",
	))
	for _, k := range []string{"xPaddingBytes", "uplinkChunkSize", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs"} {
		f[k] = data
	}
	f["xmux"] = object(fieldsOf("maxConcurrency", "maxConnections", "cMaxReuseTimes",
		"hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"))
	f["headers"] = stringMap
	if !download {
		f["downloadSettings"] = func(c *cleaner, path string, v any) (any, bool) {
			return streamRule(true)(c, path, v)
		}
	}
	clean := object(f)
	return func(c *cleaner, path string, v any) (any, bool) {
		m, ok := v.(map[string]any)
		if !ok {
			c.drop(path)
			return nil, false
		}
		merged := map[string]any{}
		if raw := m["extra"]; raw != nil {
			extra, ok := raw.(map[string]any)
			if !ok {
				c.drop(join(path, "extra"))
			}
			for k, val := range extra {
				merged[k] = val
			}
			for _, k := range []string{"host", "path", "mode"} {
				delete(merged, k)
				if val, ok := m[k]; ok {
					merged[k] = val
				}
			}
		} else {
			for k, val := range m {
				merged[k] = val
			}
		}
		// Xray reads only one level of "extra".
		if merged["extra"] != nil {
			c.drop(join(path, "extra.extra"))
		}
		delete(merged, "extra")
		return clean(c, path, merged)
	}
}

var (
	userFields  = fieldsOf("level", "email")
	addrFields  = with(userFields, fieldsOf("address", "port"))
	authFields  = fieldsOf("user", "pass", "level", "email")
	ssFields    = with(addrFields, fieldsOf("method", "password", "uot", "uotVersion"))
	trojanField = with(addrFields, fieldsOf("password", "flow"))

	// Settings per protocol. No "reverse" for VLESS: it lets the server
	// open connections into this machine.
	settingsRules = map[string]rule{
		"vless": object(with(addrFields, fields{
			"id": scalar, "flow": scalar, "encryption": scalar,
			"vnext": list(object(with(fieldsOf("address", "port"), fields{
				"users": list(object(with(userFields, fieldsOf("id", "flow", "encryption")))),
			}))),
		})),
		"vmess": object(with(addrFields, fields{
			"id": scalar, "security": scalar, "experiments": scalar,
			"vnext": list(object(with(fieldsOf("address", "port"), fields{
				"users": list(object(with(userFields, fieldsOf("id", "security", "experiments", "alterId")))),
			}))),
		})),
		"trojan":      object(with(trojanField, fields{"servers": list(object(trojanField))})),
		"shadowsocks": object(with(ssFields, fields{"servers": list(object(ssFields))})),
		"socks": object(with(addrFields, fields{
			"user": scalar, "pass": scalar,
			"servers": list(object(with(fieldsOf("address", "port"), fields{"users": list(object(authFields))}))),
		})),
		"http": object(with(addrFields, fields{
			"user": scalar, "pass": scalar, "headers": stringMap,
			"servers": list(object(with(fieldsOf("address", "port"), fields{"users": list(object(authFields))}))),
		})),
		"hysteria": object(fieldsOf("version", "address", "port")),
		"wireguard": object(with(fieldsOf("secretKey", "address", "mtu", "workers", "reserved", "domainStrategy", "noKernelTun"), fields{
			"peers": list(object(fieldsOf("publicKey", "preSharedKey", "endpoint", "keepAlive", "allowedIPs"))),
		})),
		// Only as a chain helper, for fragmentation.
		"freedom": object(fields{
			"domainStrategy": scalar, "targetStrategy": scalar,
			"fragment": data, "noise": data, "noises": list(data),
		}),
	}

	outboundFields = fields{
		"tag":            scalar,
		"protocol":       scalar,
		"streamSettings": streamRule(false),
		"proxySettings":  object(fieldsOf("tag", "transportLayer")),
		"mux":            object(fieldsOf("enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443")),
		"targetStrategy": scalar,
	}
)

// sanitizeOutbound rebuilds an outbound from the allowed fields. Helpers
// (outbounds a server dials through) may also be freedom, for
// fragmentation. It returns what was dropped, as paths.
func sanitizeOutbound(ob map[string]any, helper bool) (map[string]any, []string, error) {
	proto, _ := ob["protocol"].(string)
	switch {
	case proxyProtocols[proto]:
	case proto == "freedom" && helper:
	case proto == "":
		return nil, nil, fmt.Errorf("outbound has no protocol")
	case helperProtocols[proto]:
		return nil, nil, fmt.Errorf("%s outbound doesn't go through a server", proto)
	default:
		return nil, nil, fmt.Errorf("unsupported protocol %q", proto)
	}
	c := &cleaner{}
	f := with(outboundFields, fields{"settings": settingsRules[proto]})
	out, _ := object(f)(c, "", ob)
	clean := out.(map[string]any)
	if proto == "wireguard" {
		// Kernel WireGuard needs root and changes sysctls; the userspace
		// one works anywhere.
		settings, _ := clean["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			clean["settings"] = settings
		}
		settings["noKernelTun"] = true
	}
	return clean, c.dropped, nil
}

// sanitizeAll cleans a server's outbounds (helpers after the first
// primaries) and summarises what was dropped in one warning.
func sanitizeAll(obs []map[string]any, primaries int) ([]map[string]any, []string, error) {
	var (
		out     []map[string]any
		dropped []string
	)
	for i, ob := range obs {
		clean, d, err := sanitizeOutbound(ob, i >= primaries)
		if err != nil {
			if t, _ := ob["tag"].(string); t != "" {
				return nil, nil, fmt.Errorf("outbound %q: %w", t, err)
			}
			return nil, nil, err
		}
		out = append(out, clean)
		for _, p := range d {
			if p == "streamSettings.tlsSettings.allowInsecure" {
				continue // has its own warning
			}
			if !slices.Contains(dropped, p) {
				dropped = append(dropped, p)
			}
		}
	}
	var warnings []string
	for _, ob := range obs {
		if v, _ := child(ob, "streamSettings", "tlsSettings")["allowInsecure"].(bool); v {
			warnings = append(warnings, "allowInsecure is no longer supported by Xray; certificate will be verified")
			break
		}
	}
	if len(dropped) > 0 {
		const show = 6
		msg := strings.Join(dropped[:min(show, len(dropped))], ", ")
		if len(dropped) > show {
			msg += fmt.Sprintf(" and %d more", len(dropped)-show)
		}
		warnings = append(warnings, "ignored unsupported or unsafe options: "+msg)
	}
	return out, warnings, nil
}

// child walks nested objects, returning nil if one is missing.
func child(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		m, _ = m[k].(map[string]any)
	}
	return m
}

// Health check bounds. Xray probes every member sampling times per
// interval, so these cap how hard a provider can make it work.
const (
	DefaultProbeURL = "https://www.gstatic.com/generate_204"
	minProbeEvery   = 10 * time.Second
	maxProbeEvery   = time.Hour
	maxProbeTimeout = 30 * time.Second
	maxProbeSamples = 10
)

// SanitizeProbe cleans a provider's health check (burstObservatory
// pingConfig). "connectivity" is dropped: Xray fetches it directly, outside
// the proxy, which would reveal the user's address to a host the provider
// picks. The destination must be https; numbers are clamped.
func SanitizeProbe(pc map[string]any) map[string]any {
	out := map[string]any{"destination": DefaultProbeURL}
	if d, _ := pc["destination"].(string); d != "" {
		if u, err := url.Parse(strings.TrimSpace(d)); err == nil && u.Scheme == "https" && u.Hostname() != "" {
			out["destination"] = u.String()
		}
	}
	duration := func(key string, def, lo, hi time.Duration) {
		d := def
		if v, ok := pc[key].(string); ok {
			if p, err := time.ParseDuration(v); err == nil {
				d = p
			}
		}
		out[key] = min(max(d, lo), hi).String()
	}
	duration("interval", time.Minute, minProbeEvery, maxProbeEvery)
	duration("timeout", 5*time.Second, time.Second, maxProbeTimeout)
	samples := 2
	if n, ok := pc["sampling"].(float64); ok {
		samples = int(n)
	} else if n, ok := pc["sampling"].(int); ok {
		samples = n
	}
	out["sampling"] = min(max(samples, 1), maxProbeSamples)
	if m, _ := pc["httpMethod"].(string); m == "GET" || m == "HEAD" {
		out["httpMethod"] = m
	}
	return out
}
