package cli

const defaultConfigYAML = `# proxy-router settings. Subscriptions and the selected server live in
# state.json and are managed with the CLI (sub add, use, ...).

listen:
  socks: 127.0.0.1:10808   # SOCKS5 (TCP + UDP). Empty string disables it.
  http: 127.0.0.1:10809    # HTTP / HTTPS CONNECT proxy. Empty string disables it.
  # Login for both. Needed to listen beyond this machine (0.0.0.0, a LAN
  # address); a host-less ":10808" means 127.0.0.1. Note that SOCKS5 UDP is
  # let through for any program on an IP that has logged in once.
  user: ""
  password: ""
  # Allow listening beyond this machine without a login: an open proxy for
  # anyone who can reach the port.
  allow_open: false

# Interface for proxy-router's own connections (to servers and "direct").
#   auto: if another VPN (Happ in VPN mode, WireGuard, ...) owns the default
#         route, go around it via the physical interface (e.g. en0)
#   none: always follow system routing
#   en0:  always use this interface
bind_interface: auto

# Routing rules file, relative to this directory. "run --rules" overrides it.
rules: routing.yaml

# Xray log level: debug, info, warning, error, none
log_level: warning
# Print every connection and the outbound it went through (or use run -v).
access_log: false

# Subscriptions older than this are refreshed when "run" starts and while it
# runs. 0 disables automatic updates.
update_interval: 12h

# User-Agent for subscription requests. Panels pick the format by it; the
# default is Happ's, which gets full Xray configs including "Auto" pools.
# user_agent: Happ/3.24.1

# Sources for geoip:/geosite: rules ("proxy-router geo update").
# For Russia-specific lists (geosite:ru-blocked, geoip:ru-blocked), use:
#   https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
#   https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
geo:
  geoip: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
  geosite: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

ping:
  url: https://www.gstatic.com/generate_204
  timeout: 5s
  # Max simultaneous tests per server IP. Providers often put dozens of
  # "servers" behind one entry point that drops bursts of connections.
  per_endpoint: 2
  # Downloaded through each server after the latency request. Censors often
  # let a connection to a server start and cut it after ~16 KB, which the
  # latency request never notices: a server whose download stalls fails.
  # How fast it arrives ranks "ping" and "use --fastest". Empty disables.
  download_url: https://speed.cloudflare.com/__down?bytes=262144

# After "use --fastest", a running proxy-router watches its connections to the
# server it picked. When one shows trouble (data stops mid-transfer or a
# handshake goes unanswered for "stall", a connection is reset, the server
# hangs up right after the handshake, or can't be reached), it downloads
# ping.download_url through the server. After "failures" failed downloads in
# a row (the download stalls, or takes longer than timeout), it tests the
# other servers (of the --group given, if any) and switches to the fastest
# working one. Nothing is tested while traffic flows fine. Hysteria (QUIC) is
# watched for unanswered handshakes and a server gone silent, and also checked
# every 5 intervals; servers whose connections can't be watched (XHTTP over
# HTTP/3, mKCP, WireGuard) are checked every interval. Picking a server by
# name turns this off; enabled: false or interval: 0 too.
auto_switch:
  enabled: true
  stall: 10s
  interval: 1m
  failures: 2
  timeout: 15s

# Destinations that always use the system's own routing: never proxied, never
# pinned to an interface, and never sent into the TUN. Keeps Tailscale (and
# other VPNs' private ranges) working while proxy-router is on.
# Names here are looked up with the system resolver in plain DNS (MagicDNS
# names exist nowhere else) and follow the system route when their address
# is in one of the IP ranges here; a name alone could be faked by any app.
system_route:
  - 100.64.0.0/10          # Tailscale IPv4
  - fd7a:115c:a1e0::/48    # Tailscale IPv6
  - domain:ts.net          # Tailscale MagicDNS names

# Resolve destination names here (DNS-over-HTTPS through the tunnel) and send
# servers IP addresses, instead of each server resolving them itself. Servers'
# resolvers can return broken answers (YouTube failed through every server
# of one provider until this was on). Ignored for apps in TUN mode, which
# already connect to IPs. A dns: section in the rules file replaces the DoH
# servers used.
resolve_locally: true

# Server hostnames are looked up with DNS-over-HTTPS (1.1.1.1, 8.8.8.8)
# outside the tunnel. If that fails, ask the system resolver, which sends
# them in plain DNS for the network to see. false: never.
system_dns_fallback: true

# ---- Happ's advanced settings ----

# Split the TLS ClientHello into pieces so DPI can't read the SNI.
fragment:
  enabled: false
  packets: tlshello        # tlshello, or a range of TCP segments like 1-3
  length: 50-100           # bytes per piece
  delay: 10-20             # ms between pieces
  max_split: 3-6           # pieces per packet

# Junk UDP packets sent before UDP-based connections (Hysteria2, WireGuard,
# mKCP). Doesn't affect TCP servers like VLESS/Reality.
noises:
  enabled: false
  items:
    - type: array          # array (bytes like "1,2,0x16"), str, hex, base64
      packet: ""           # empty = random bytes, see rand
      delay: 10-20         # ms
      rand: 1-8192         # random packet length
      rand_range: 0-255    # random byte values

# Multiplex connections over one. Not usable with XTLS Vision (flow) servers;
# those are skipped with a note.
mux:
  enabled: false
  concurrency: 8
  xudp_concurrency: 16
  xudp_proxy_udp443: reject   # reject, allow, skip

# Which IP family to use when a name resolves to both: auto, ipv4, ipv6,
# ipv4v6 (prefer v4), ipv6v4 (prefer v6).
preferred_ip: ipv4

# Capture all system traffic, like Happ's "Xray TUN". Needs root:
#   sudo proxy-router run --tun
# LAN, Tailscale and other more specific routes keep working. System DNS is
# pointed into the TUN.
tun:
  enabled: false
  name: ""                 # empty picks a free utunN
  mtu: 1500
  ipv6: false              # proxy IPv6 too; when false it's blocked, never leaked
  # Block anything that would leave outside the TUN, also while restarting
  # or after a crash. LAN and system_route stay reachable. If networking is
  # stuck after a crash, "sudo proxy-router stop" removes it.
  kill_switch: true
`

const defaultRoutingYAML = `# proxy-router routing rules.
#
# Rules are checked top to bottom; the first match wins. Unmatched traffic
# goes to "default".
#
# outbound:  proxy          the selected server ("proxy-router use")
#            direct         no proxy
#            block          drop the connection
#            server:<name>  a specific server (index, name, or group/name)
#
# Conditions (each accepts one value, a comma-separated string, or a list):
#   domain:   example.com      substring match
#             domain:ru        the domain and all subdomains
#             full:x.com       exact domain
#             keyword:google   substring match
#             regexp:\.cn$     regular expression
#             geosite:google   category from geosite.dat
#   ip:       10.0.0.0/8, 1.1.1.1, geoip:ru, geoip:private, !geoip:ru
#   port:     443, "80,443", "1000-2000"
#   network:  tcp, udp
#   protocol: http, tls, quic, bittorrent   (detected by sniffing)
#   source:   client IPs/CIDRs (useful when listening on the LAN)
#   process:  local process names or paths, e.g. curl, /Applications/Telegram.app/
#   inbound:  socks, http, tun
# "domain" and "ip" in one rule mean "either one matches"; every other
# condition must also match.
#
# Pools balance across several servers and skip dead ones:
#   pools:
#     sweden:
#       servers: [Швеция, "My VPN/🇸🇪 Stockholm", 12]   # name text, group/name, index; "*" = all
#       strategy: leastPing        # leastPing, leastLoad, random, roundRobin
#   pool_probe:                    # health check for every pool
#     url: https://www.youtube.com/    # only use servers where this loads
#     interval: 30s
# and send traffic there with outbound: pool:sweden.
#
# geosite:/geoip: lists are downloaded automatically on first use.
# Tailscale ranges are handled before these rules by system_route in
# config.yaml.

default: proxy

# AsIs:         match domain rules only on the domain name
# IPIfNonMatch: if no domain rule matches, resolve it and try IP rules
#               (connections to an IP keep using that IP)
# IPOnDemand:   resolve immediately when an IP rule is reached; for
#               connections to an IP with a sniffed name, the name's
#               addresses are used instead of the real one
domain_strategy: IPIfNonMatch

rules:
  # By address only: a TLS/HTTP name like x.lan is whatever the app sends,
  # even to a public address. Apps that look local names up themselves
  # (everything in TUN mode) connect to a local address, which this matches.
  - name: local network
    outbound: direct
    ip:
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 169.254.0.0/16
      - ::1/128
      - fc00::/7
      - fe80::/10

  # - name: ads
  #   outbound: block
  #   domain: geosite:category-ads-all

  # - name: russian sites direct
  #   outbound: direct
  #   domain: [geosite:category-ru, domain:ru, domain:xn--p1ai]
  #   ip: geoip:ru

  # - name: openai through a US server
  #   outbound: server:USA
  #   domain: [domain:openai.com, domain:chatgpt.com]

  # - name: YouTube via whichever server can load it right now
  #   outbound: pool:youtube       # define pools.youtube with servers: "*"
  #   domain: [geosite:youtube]

  # - name: no torrents through the proxy
  #   outbound: direct
  #   protocol: bittorrent

# Optional DNS settings in Xray's format, passed through unchanged:
# dns:
#   servers:
#     - https://1.1.1.1/dns-query
#     - address: 77.88.8.8
#       domains: [geosite:category-ru]
`
