// Package share converts proxy share links and Xray JSON configs into Xray
// outbound objects. Supported links: vless://, vmess://, trojan://, ss://,
// hysteria2:// (hy2://), socks:// (socks5://), http:// / https://, and
// wireguard:// (wg://). Any other Xray outbound can be delivered through a
// JSON subscription.
package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Server is a single proxy endpoint ready to be used as an Xray outbound.
type Server struct {
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Address  string          `json:"address"`
	Port     int             `json:"port"`
	Link     string          `json:"link,omitempty"`
	Outbound json.RawMessage `json:"outbound"`
	// Helper outbounds the main one dials through (from JSON configs).
	Chain []json.RawMessage `json:"chain,omitempty"`
	// Pool is set for entries that balance across several servers, like a
	// provider's "Auto". Outbound is then the first member.
	Pool *Pool `json:"pool,omitempty"`
	// Warnings collected while converting the link (unsupported options etc).
	Warnings []string `json:"warnings,omitempty"`
}

// Pool is a group of outbounds Xray balances between.
type Pool struct {
	// Members are outbounds with their original tags.
	Members []json.RawMessage `json:"members"`
	// Selector holds tag prefixes choosing the members.
	Selector []string `json:"selector"`
	// Strategy is the Xray balancer strategy object.
	Strategy json.RawMessage `json:"strategy,omitempty"`
	// Probe is the provider's health check (burstObservatory pingConfig).
	Probe json.RawMessage `json:"probe,omitempty"`
}

// ChainTag is the tag of a helper outbound. Helpers live outside tag's
// prefix so a pool's selector (a prefix match) can never pick one.
func ChainTag(tag, helper string) string { return "chain:" + tag + "~" + helper }

// MemberTag is the tag of a pool member.
func MemberTag(tag, member string) string { return tag + "~" + member }

// Primaries is how many of Outbounds' results are servers (the rest are
// chain helpers): 1, or the member count for a pool.
func (s *Server) Primaries() int {
	if s.Pool != nil {
		return len(s.Pool.Members)
	}
	return 1
}

// Members returns a pool's members as standalone servers (with the pool's
// chain helpers), or nil for an ordinary server.
func (s *Server) Members() []*Server {
	if s.Pool == nil {
		return nil
	}
	var out []*Server
	for i, raw := range s.Pool.Members {
		var ob map[string]any
		if json.Unmarshal(raw, &ob) != nil {
			continue
		}
		m := &Server{
			Name:     fmt.Sprintf("%s #%d", s.Name, i+1),
			Outbound: raw,
			Chain:    s.Chain,
		}
		m.Protocol, _ = ob["protocol"].(string)
		m.Address, m.Port = endpoint(ob)
		out = append(out, m)
	}
	return out
}

// Outbounds returns the server's Xray outbounds: the server tagged tag (or,
// for a pool, its members tagged MemberTag), followed by chain helpers.
// They're sanitized again here, so servers saved by older versions get
// the same treatment as new imports.
func (s *Server) Outbounds(tag string) ([]map[string]any, error) {
	primaries := []json.RawMessage{s.Outbound}
	if s.Pool != nil {
		primaries = s.Pool.Members
	}
	var obs []map[string]any
	for _, raw := range append(append([]json.RawMessage{}, primaries...), s.Chain...) {
		var ob map[string]any
		if err := json.Unmarshal(raw, &ob); err != nil {
			return nil, fmt.Errorf("server %q: bad outbound: %w", s.Name, err)
		}
		if ob == nil {
			return nil, fmt.Errorf("server %q: empty outbound", s.Name)
		}
		obs = append(obs, ob)
	}
	obs, _, err := sanitizeAll(obs, len(primaries))
	if err != nil {
		return nil, fmt.Errorf("server %q: %w", s.Name, err)
	}
	rename := func(t string) string { return ChainTag(tag, t) }
	for i, ob := range obs {
		t, _ := ob["tag"].(string)
		switch {
		case i >= len(primaries):
			ob["tag"] = rename(t)
		case s.Pool != nil:
			ob["tag"] = MemberTag(tag, t)
		default:
			ob["tag"] = tag
		}
		renameDependencies(ob, rename)
	}
	return obs, nil
}

// ParseLink converts one share link into a Server.
func ParseLink(link string) (*Server, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link: %q", truncate(link, 40))
	}
	var (
		s   *Server
		err error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		s, err = parseVLESS(link)
	case "vmess":
		s, err = parseVMess(link)
	case "trojan":
		s, err = parseTrojan(link)
	case "ss":
		s, err = parseShadowsocks(link)
	case "hysteria2", "hy2":
		s, err = parseHysteria2(link)
	case "socks", "socks5", "socks5h":
		s, err = parseSocks(link)
	case "http", "https":
		s, err = parseHTTP(link)
	case "wireguard", "wg":
		s, err = parseWireGuard(link)
	case "happ":
		return nil, fmt.Errorf("happ:// links are app-specific (often encrypted) and can't be imported; use the plain subscription URL instead")
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("%s link: %w", scheme, err)
	}
	s.Link = link
	if s.Name == "" {
		s.Name = fmt.Sprintf("%s:%d", s.Address, s.Port)
	}
	return s, nil
}

// ParseLinks parses newline separated links, skipping blanks and comments.
// Links that fail to parse are reported in errs but don't stop parsing.
func ParseLinks(text string) (servers []*Server, errs []error) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		s, err := ParseLink(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		servers = append(servers, s)
	}
	return servers, errs
}

// stdURL is a parsed link with convenient query access.
type stdURL struct {
	*url.URL
	q url.Values
}

func parseStd(link string) (*stdURL, error) {
	u, err := url.Parse(escapeUserinfo(link))
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing host")
	}
	if u.Port() == "" {
		return nil, fmt.Errorf("missing port")
	}
	return &stdURL{URL: u, q: u.Query()}, nil
}

// escapeUserinfo percent-encodes '/' in the userinfo part. Base64 keys and
// passwords (WireGuard, Shadowsocks) often contain it unescaped, which would
// otherwise end the authority section early.
func escapeUserinfo(link string) string {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return link
	}
	end := len(rest)
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		end = i
	}
	at := strings.Index(rest[:end], "@")
	if at < 0 || !strings.Contains(rest[:at], "/") {
		return link
	}
	return scheme + "://" + strings.ReplaceAll(rest[:at], "/", "%2F") + rest[at:]
}

func (u *stdURL) port() (int, error) {
	p, err := strconv.Atoi(u.Port())
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bad port %q", u.Port())
	}
	return p, nil
}

func (u *stdURL) name() string {
	// Fragment is already unescaped by url.Parse, but some generators
	// double-encode it.
	name := u.Fragment
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	return strings.TrimSpace(name)
}

func (u *stdURL) get(keys ...string) string {
	for _, k := range keys {
		if v := u.q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// streamParams holds transport/security options shared by vless, vmess and
// trojan links.
type streamParams struct {
	network     string // tcp/raw, ws, grpc, httpupgrade, xhttp, kcp
	security    string // none, tls, reality
	host        string
	path        string
	headerType  string
	sni         string
	alpn        string
	fingerprint string
	serviceName string
	authority   string
	mode        string
	extra       string
	seed        string
	publicKey   string
	shortID     string
	spiderX     string
	pqv         string
	pcs         string
	vcn         string
	ech         string
	insecure    bool
}

func (p *streamParams) build(defaultSNI string) (map[string]any, []string) {
	var warnings []string
	network := strings.ToLower(p.network)
	switch network {
	case "", "tcp", "raw":
		network = "raw"
	case "splithttp":
		network = "xhttp"
	case "http", "h2":
		// HTTP/2 transport was removed from Xray; XHTTP is the replacement.
		warnings = append(warnings, "h2 transport is not supported by Xray anymore; using xhttp")
		network = "xhttp"
	}
	ss := map[string]any{"network": network}

	switch network {
	case "raw":
		if p.headerType == "http" {
			req := map[string]any{}
			if p.path != "" {
				req["path"] = strings.Split(p.path, ",")
			}
			if p.host != "" {
				req["headers"] = map[string]any{"Host": strings.Split(p.host, ",")}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		ws := map[string]any{"path": orDefault(p.path, "/")}
		if p.host != "" {
			ws["host"] = p.host
		}
		ss["wsSettings"] = ws
	case "httpupgrade":
		hu := map[string]any{"path": orDefault(p.path, "/")}
		if p.host != "" {
			hu["host"] = p.host
		}
		ss["httpupgradeSettings"] = hu
	case "grpc":
		g := map[string]any{"serviceName": p.serviceName}
		if p.authority != "" {
			g["authority"] = p.authority
		}
		if p.mode == "multi" {
			g["multiMode"] = true
		}
		ss["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": orDefault(p.path, "/")}
		if p.host != "" {
			x["host"] = p.host
		}
		if p.mode != "" {
			x["mode"] = p.mode
		}
		if p.extra != "" {
			var extra map[string]any
			if err := json.Unmarshal([]byte(p.extra), &extra); err == nil {
				for k, v := range extra {
					x[k] = v
				}
			} else {
				warnings = append(warnings, "ignored malformed xhttp extra: "+err.Error())
			}
		}
		ss["xhttpSettings"] = x
	case "kcp", "mkcp":
		ss["network"] = "kcp"
		k := map[string]any{}
		if p.seed != "" {
			k["seed"] = p.seed
		}
		if p.headerType != "" && p.headerType != "none" {
			k["header"] = map[string]any{"type": p.headerType}
		}
		ss["kcpSettings"] = k
	default:
		warnings = append(warnings, fmt.Sprintf("unknown transport %q passed through as-is", network))
	}

	sni := p.sni
	if sni == "" {
		sni = p.host
	}
	if sni == "" {
		sni = defaultSNI
	}

	switch strings.ToLower(p.security) {
	case "", "none":
	case "tls", "xtls":
		ss["security"] = "tls"
		tls := map[string]any{"serverName": sni}
		if p.fingerprint != "" {
			tls["fingerprint"] = p.fingerprint
		}
		if p.alpn != "" {
			tls["alpn"] = splitList(p.alpn)
		}
		if p.pcs != "" {
			tls["pinnedPeerCertSha256"] = p.pcs
		}
		if p.vcn != "" {
			tls["verifyPeerCertByName"] = p.vcn
		}
		if p.ech != "" {
			tls["echConfigList"] = p.ech
		}
		if p.insecure && p.pcs == "" {
			// Xray removed allowInsecure; without a pinned cert hash
			// the connection will verify the certificate normally.
			warnings = append(warnings, "allowInsecure is no longer supported by Xray; certificate will be verified")
		}
		ss["tlsSettings"] = tls
	case "reality":
		ss["security"] = "reality"
		r := map[string]any{
			"serverName":  sni,
			"password":    p.publicKey,
			"fingerprint": orDefault(p.fingerprint, "chrome"),
		}
		if p.shortID != "" {
			r["shortId"] = p.shortID
		}
		if p.spiderX != "" {
			r["spiderX"] = p.spiderX
		}
		if p.pqv != "" {
			r["mldsa65Verify"] = p.pqv
		}
		ss["realitySettings"] = r
	default:
		warnings = append(warnings, fmt.Sprintf("unknown security %q ignored", p.security))
	}
	return ss, warnings
}

func streamFromQuery(u *stdURL, defaultSecurity string) *streamParams {
	return &streamParams{
		network:     u.get("type", "net"),
		security:    orDefault(u.get("security"), defaultSecurity),
		host:        u.get("host"),
		path:        u.get("path"),
		headerType:  u.get("headerType"),
		sni:         u.get("sni", "peer"),
		alpn:        u.get("alpn"),
		fingerprint: u.get("fp"),
		serviceName: u.get("serviceName"),
		authority:   u.get("authority"),
		mode:        u.get("mode"),
		extra:       u.get("extra"),
		seed:        u.get("seed"),
		publicKey:   u.get("pbk", "password"),
		shortID:     u.get("sid"),
		spiderX:     u.get("spx"),
		pqv:         u.get("pqv"),
		pcs:         u.get("pcs", "pinSHA256"),
		vcn:         u.get("vcn"),
		ech:         u.get("ech"),
		insecure:    isTrue(u.get("allowInsecure", "insecure")),
	}
}

func parseVLESS(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	id := u.User.Username()
	if id == "" {
		return nil, fmt.Errorf("missing user id")
	}
	stream, warnings := streamFromQuery(u, "none").build(u.Hostname())
	settings := map[string]any{
		"address":    u.Hostname(),
		"port":       port,
		"id":         id,
		"encryption": orDefault(u.get("encryption"), "none"),
	}
	if flow := u.get("flow"); flow != "" {
		settings["flow"] = flow
	}
	return newServer(u.name(), "vless", u.Hostname(), port, settings, stream, warnings)
}

func parseTrojan(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}
	stream, warnings := streamFromQuery(u, "tls").build(u.Hostname())
	settings := map[string]any{
		"address":  u.Hostname(),
		"port":     port,
		"password": password,
	}
	return newServer(u.name(), "trojan", u.Hostname(), port, settings, stream, warnings)
}

// vmess links are base64 encoded JSON ("v2rayN format").
func parseVMess(link string) (*Server, error) {
	body := link[len("vmess://"):]
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	raw, err := decodeBase64(body)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	str := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	address := str("add")
	port, err := strconv.Atoi(str("port"))
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("bad port %q", str("port"))
	}
	if address == "" || str("id") == "" {
		return nil, fmt.Errorf("missing address or id")
	}
	p := &streamParams{
		network:     str("net"),
		security:    str("tls"),
		host:        str("host"),
		path:        str("path"),
		headerType:  str("type"),
		sni:         str("sni"),
		alpn:        str("alpn"),
		fingerprint: str("fp"),
		mode:        str("mode"),
		insecure:    isTrue(str("allowInsecure")) || isTrue(str("insecure")),
	}
	if p.network == "grpc" {
		p.serviceName = p.path
		p.mode = str("type")
		p.headerType = ""
	}
	if p.network == "kcp" {
		p.seed = p.path
	}
	stream, warnings := p.build(address)
	settings := map[string]any{
		"address":  address,
		"port":     port,
		"id":       str("id"),
		"security": orDefault(str("scy"), "auto"),
	}
	return newServer(str("ps"), "vmess", address, port, settings, stream, warnings)
}

// Shadowsocks: SIP002 (ss://base64(method:pass)@host:port#name or
// ss://method:pass@host:port) and the legacy ss://base64(method:pass@host:port).
func parseShadowsocks(link string) (*Server, error) {
	rest := link[len("ss://"):]
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	if !strings.Contains(rest, "@") {
		// Legacy format: everything before the query is base64.
		body, query, _ := strings.Cut(rest, "?")
		dec, err := decodeBase64(body)
		if err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		rest = string(dec)
		if query != "" {
			rest += "?" + query
		}
	}
	u, err := parseStd("ss://" + rest)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	var method, password string
	if pw, ok := u.User.Password(); ok {
		method, password = u.User.Username(), pw
	} else {
		dec, err := decodeBase64(u.User.Username())
		if err != nil {
			return nil, fmt.Errorf("decode userinfo: %w", err)
		}
		method, password, _ = strings.Cut(string(dec), ":")
	}
	if method == "" || password == "" {
		return nil, fmt.Errorf("missing method or password")
	}
	var warnings []string
	if plugin := u.get("plugin"); plugin != "" {
		warnings = append(warnings, "shadowsocks plugins are not supported: "+plugin)
	}
	settings := map[string]any{
		"address":  u.Hostname(),
		"port":     port,
		"method":   method,
		"password": password,
	}
	if isTrue(u.get("uot")) {
		settings["uot"] = true
	}
	return newServer(strings.TrimSpace(name), "shadowsocks", u.Hostname(), port, settings, map[string]any{"network": "raw"}, warnings)
}

func parseHysteria2(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	tls := map[string]any{
		"serverName": orDefault(u.get("sni", "peer"), u.Hostname()),
		"alpn":       []string{"h3"},
	}
	var warnings []string
	if pcs := u.get("pinSHA256", "pcs"); pcs != "" {
		tls["pinnedPeerCertSha256"] = pcs
	} else if isTrue(u.get("insecure")) {
		warnings = append(warnings, "insecure is no longer supported by Xray; certificate will be verified")
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	if obfs := u.get("obfs"); obfs != "" {
		if obfs != "salamander" {
			return nil, fmt.Errorf("unsupported obfs %q", obfs)
		}
		stream["finalmask"] = map[string]any{"udp": []any{map[string]any{
			"type":     "salamander",
			"settings": map[string]any{"password": u.get("obfs-password")},
		}}}
	}
	quic := map[string]any{}
	if mport := u.get("mport"); mport != "" {
		// Port hopping: the server listens on a range, the client hops between them.
		hop := map[string]any{"ports": mport}
		if iv := u.get("hop-interval", "hopInterval"); iv != "" {
			hop["interval"] = strings.TrimSuffix(iv, "s")
		}
		quic["udpHop"] = hop
	}
	if cc := u.get("congestion"); cc != "" {
		quic["congestion"] = cc
	}
	if len(quic) > 0 {
		fm, _ := stream["finalmask"].(map[string]any)
		if fm == nil {
			fm = map[string]any{}
			stream["finalmask"] = fm
		}
		fm["quicParams"] = quic
	}
	settings := map[string]any{"version": 2, "address": u.Hostname(), "port": port}
	return newServer(u.name(), "hysteria", u.Hostname(), port, settings, stream, warnings)
}

// socks://base64(user:pass)@host:port#name (v2rayN) or
// socks5://user:pass@host:port#name.
func parseSocks(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	settings := map[string]any{"address": u.Hostname(), "port": port}
	user := u.User.Username()
	pass, hasPass := u.User.Password()
	if user != "" && !hasPass {
		if dec, err := decodeBase64(user); err == nil && strings.Contains(string(dec), ":") {
			user, pass, _ = strings.Cut(string(dec), ":")
		}
	}
	if user != "" {
		settings["user"] = user
		settings["pass"] = pass
	}
	return newServer(u.name(), "socks", u.Hostname(), port, settings, nil, nil)
}

// http://user:pass@host:port#name; https:// wraps the proxy connection in TLS.
func parseHTTP(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	settings := map[string]any{"address": u.Hostname(), "port": port}
	if user := u.User.Username(); user != "" {
		pass, _ := u.User.Password()
		settings["user"] = user
		settings["pass"] = pass
	}
	var stream map[string]any
	if u.Scheme == "https" || u.get("security") == "tls" {
		tls := map[string]any{"serverName": orDefault(u.get("sni"), u.Hostname())}
		if fp := u.get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		stream = map[string]any{"network": "raw", "security": "tls", "tlsSettings": tls}
	}
	return newServer(u.name(), "http", u.Hostname(), port, settings, stream, nil)
}

// wireguard://privateKey@host:port?publickey=..&address=10.0.0.2/32,fd00::2/128
// &reserved=1,2,3&mtu=1280&presharedkey=..#name
func parseWireGuard(link string) (*Server, error) {
	u, err := parseStd(link)
	if err != nil {
		return nil, err
	}
	port, err := u.port()
	if err != nil {
		return nil, err
	}
	secret := u.User.Username()
	if secret == "" {
		secret = u.get("privatekey", "privateKey", "secretKey")
	}
	publicKey := u.get("publickey", "publicKey", "peer_public_key")
	if secret == "" || publicKey == "" {
		return nil, fmt.Errorf("missing private or public key")
	}
	// Keys are base64 and may contain '+', which url.Query decodes as space.
	secret = strings.ReplaceAll(secret, " ", "+")
	publicKey = strings.ReplaceAll(publicKey, " ", "+")

	addresses := splitList(u.get("address", "ip", "local_address"))
	if len(addresses) == 0 {
		addresses = []string{"10.0.0.2/32"}
	}
	peer := map[string]any{
		"publicKey": publicKey,
		"endpoint":  u.Host,
	}
	if psk := u.get("presharedkey", "preSharedKey", "psk"); psk != "" {
		peer["preSharedKey"] = strings.ReplaceAll(psk, " ", "+")
	}
	if ka, err := strconv.Atoi(u.get("keepalive")); err == nil && ka > 0 {
		peer["keepAlive"] = ka
	}
	settings := map[string]any{
		"secretKey": secret,
		"address":   addresses,
		"peers":     []any{peer},
	}
	if mtu, err := strconv.Atoi(u.get("mtu")); err == nil && mtu > 0 {
		settings["mtu"] = mtu
	}
	if r := u.get("reserved"); r != "" {
		var reserved []int
		for _, part := range splitList(r) {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("bad reserved value %q", r)
			}
			reserved = append(reserved, n)
		}
		settings["reserved"] = reserved
	}
	return newServer(u.name(), "wireguard", u.Hostname(), port, settings, nil, nil)
}

func newServer(name, protocol, address string, port int, settings, stream map[string]any, warnings []string) (*Server, error) {
	ob := map[string]any{
		"protocol": protocol,
		"settings": settings,
	}
	if stream != nil {
		ob["streamSettings"] = stream
	}
	// Links carry options too, e.g. xhttp "extra". Sanitizing works on
	// decoded JSON, hence the round trip.
	raw, err := json.Marshal(ob)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &ob); err != nil {
		return nil, err
	}
	obs, more, err := sanitizeAll([]map[string]any{ob}, 1)
	if err != nil {
		return nil, err
	}
	if raw, err = json.Marshal(obs[0]); err != nil {
		return nil, err
	}
	warnings = append(warnings, more...)
	return &Server{
		Name:     name,
		Protocol: protocol,
		Address:  address,
		Port:     port,
		Outbound: raw,
		Warnings: warnings,
	}, nil
}

// decodeBase64 accepts standard and URL alphabets, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// DecodeBase64 is exported for subscription bodies.
func DecodeBase64(s string) ([]byte, error) { return decodeBase64(s) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func isTrue(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
