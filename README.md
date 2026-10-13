<img src="assets/icon.svg" width="64" height="64" alt="">

# proxy-router

A command-line proxy client in the spirit of Happ. It fetches subscriptions,
lets you pick or auto-select a server, and routes traffic with rules from a
YAML file. Xray-core is embedded, so it's a single binary with nothing else
to install.

## Protocols

Everything Happ handles:

| Link | Notes |
| --- | --- |
| `vless://` | raw/TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP, mKCP; TLS, REALITY, XTLS Vision, VLESS Encryption |
| `vmess://` | v2rayN base64 JSON format, all transports above |
| `trojan://` | all transports, TLS / REALITY |
| `ss://` | SIP002 and legacy base64, AEAD and Shadowsocks 2022 |
| `hysteria2://`, `hy2://` | salamander obfs, port hopping (`mport`) |
| `socks://`, `socks5://` | with or without auth (v2rayN base64 style too) |
| `http://`, `https://` | HTTP proxy, optionally over TLS |
| `wireguard://`, `wg://` | reserved bytes, multiple addresses, PSK |

Subscriptions can be base64 or plain link lists, or **Xray JSON configs**
(what Remnawave/Marzban serve to Happ). JSON configs keep the whole outbound,
including chained helper outbounds like fragment (`dialerProxy`). So any
protocol Xray supports works, not just the links above.

## Install

```sh
go install github.com/knocking4thcylinder/proxy-router@latest
# or
go build -o proxy-router .
```

## Quick start

```sh
proxy-router sub add 'https://panel.example.com/api/sub/TOKEN'
proxy-router list                # servers, * = selected
proxy-router ping                # real latency through every server
proxy-router use --fastest       # or: use 3 / use "Germany" / use "My VPN/🇩🇪 Germany"
proxy-router run                 # SOCKS5 on :10808, HTTP on :10809
proxy-router run --system-proxy  # also point macOS proxy settings at it
```

Then point apps at `socks5://127.0.0.1:10808` or `http://127.0.0.1:10809`,
e.g. `export https_proxy=http://127.0.0.1:10809`.

## Commands

| Command | |
| --- | --- |
| `sub add <url> [-n name] [--user-agent UA] [-H 'K: V'] [--hwid]` | add a subscription |
| `sub list` | servers, last update, traffic used / total, expiry |
| `sub update [name...]` | re-fetch (all by default) |
| `sub remove <name>` | |
| `add <link>...` / `add -` | add servers from links (or stdin) |
| `remove <server>` | remove a manually added server |
| `list [-g group]` | list servers |
| `use <server>` / `use --fastest [-g group]` | select the server for `proxy` |
| `ping [server...] [-g group]` | latency test (full HTTP request through the proxy) |
| `run [-r rules.yaml] [-s server] [--system-proxy] [--tun] [-v]` | start the proxy (`--tun` needs sudo) |
| `config [-r rules.yaml] [-q] [--tun]` | validate, and print the generated Xray config |
| `geo update` | download fresh `geoip.dat` / `geosite.dat` |
| `init [--force]` | (re)create default `config.yaml` and `routing.yaml` |

`<server>` can be the number from `list`, the exact name, `group/name`, or
any unique part of the name.

While `run` is active it picks up changes by itself:
- editing the rules file or `config.yaml` applies within ~2 seconds
- `proxy-router use …` from another terminal switches the server
- subscriptions are re-fetched every `update_interval`

It only restarts when the generated config actually changed. `kill -HUP`
forces a reload.

## Routing rules

Rules live in `~/.config/proxy-router/routing.yaml` (or pass any file with
`run --rules file.yaml`). The first matching rule wins:

```yaml
default: proxy                  # proxy | direct | block
domain_strategy: IPIfNonMatch   # AsIs | IPIfNonMatch | IPOnDemand

rules:
  - name: ads
    outbound: block
    domain: geosite:category-ads-all

  - name: russian sites direct
    outbound: direct
    domain: [geosite:category-ru, domain:ru, domain:xn--p1ai]
    ip: [geoip:ru, geoip:private]

  - name: openai via a specific server
    outbound: server:USA        # index, name or group/name
    domain: [domain:openai.com, domain:chatgpt.com]

  - name: torrents direct
    outbound: direct
    protocol: bittorrent

  - name: telegram always proxied
    outbound: proxy
    process: [Telegram]
```

Conditions: `domain`, `ip`, `port`, `network`, `protocol`, `source`,
`process`, `inbound`. Each takes a single value, a comma-separated string or
a list. `domain` and `ip` in the same rule are alternatives (either one
matches). Every other condition must also match. Domain syntax is Xray's:
`domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`, or a plain substring.

Typos are errors (`domian:` is rejected), and `proxy-router config -q`
checks the whole thing against Xray, including that geosite categories exist.
`geoip.dat`/`geosite.dat` download automatically the first time a rule needs
them. The source is set in `config.yaml`; the comments there point at the
[runetfreedom](https://github.com/runetfreedom/russia-v2ray-rules-dat) lists
(`geosite:ru-blocked` etc.).

An optional `dns:` section in Xray's format is passed through unchanged.

## Files

Everything is in `~/.config/proxy-router/` (override with `--dir` or
`$PROXY_ROUTER_HOME`):

- `config.yaml`: listen addresses, interface binding, log level, update interval, User-Agent, geo URLs, ping URL
- `routing.yaml`: routing rules
- `state.json`: subscriptions, cached servers, selected server (managed by the CLI, mode 0600)
- `assets/`: geo files

## Happ's advanced settings

Everything from Happ's settings screen lives in `config.yaml`:

```yaml
fragment:                  # Enable Fragmentation (type Xray)
  enabled: true
  packets: tlshello        # or a range of TCP segments like 1-3
  length: 50-100
  delay: 10-20             # ms
  max_split: 3-6

noises:                    # Enable Noises
  enabled: true
  items:
    - type: array          # array, str, hex, base64
      packet: ""
      delay: 10-20
      rand: 1-8192
      rand_range: 0-255

mux:                       # Enable Mux
  enabled: false
  concurrency: 8

preferred_ip: ipv4         # Preferred IP Type: auto, ipv4, ipv6, ipv4v6, ipv6v4

tun:                       # Xray TUN
  enabled: false
  mtu: 1500
```

They're applied the way Xray-based clients do it. Fragmentation becomes a
`finalmask` TCP mask on each server's outbound; noises become a `finalmask`
UDP mask. Fragmentation only goes on TCP transports, noises only on UDP
ones (Hysteria2, WireGuard, mKCP). Mux is skipped, with a note, where it
can't work: XTLS Vision servers, and XHTTP (which multiplexes by itself;
stacking mux on it breaks connections). `ping` uses the same settings, so it
measures what you'll actually get. Values are validated, because Xray
silently accepts things like a reversed range and then does nothing.

"On Demand" (iOS auto-connect) has no CLI equivalent. "Inbounds" is
`listen:`.

## TUN mode

```sh
sudo proxy-router run --tun      # or tun.enabled: true
```

This captures all system traffic, so apps don't need proxy settings.
proxy-router creates a `utunN` interface and points `0.0.0.0/1` +
`128.0.0.0/1` at it (`::/1` + `8000::/1` with `tun.ipv6: true`). These beat
the default route without replacing it, so anything more specific keeps
working as before: your LAN, and Tailscale's peers and `100.64.0.0/10`.
proxy-router's own connections are pinned to the physical interface, so
they can't loop back into the TUN. The routes are removed on exit (and
disappear with the interface anyway).

DNS isn't captured: apps keep using the system resolver, which keeps
Tailscale's MagicDNS working. Files written while running under sudo stay
owned by you. `proxy-router config --tun` shows the TUN config without
needing root.

## Tailscale

`system_route` (in `config.yaml`) lists destinations that always use the
system's own routing: never proxied, never pinned to an interface, never
captured by the TUN. By default that's Tailscale's `100.64.0.0/10`,
`fd7a:115c:a1e0::/48` and `*.ts.net`, so tailnet hosts stay reachable
through proxy-router's SOCKS/HTTP proxy and in TUN mode. Add other VPNs'
private ranges there too.

## Running next to another VPN (e.g. Happ)

If Happ (or any VPN) is on in VPN/TUN mode, its tunnel owns the default
route. Without help, proxy-router's connections would go through it, and
latency doubles or connections time out. With `bind_interface: auto` (the
default), proxy-router notices this and connects through the physical
interface (e.g. `en0`) instead, both to servers and for `direct` traffic.
While `run` is active it re-checks every few seconds, so turning the other
VPN on or off, or switching networks, is picked up automatically. Set
`bind_interface: none` to always follow system routing, or name an
interface.

Happ also listens on 127.0.0.1:10808/10809. If it's running, give
proxy-router other ports under `listen:` in `config.yaml`. `run` tells you
when a port is taken and by which process.

## Notes

- Xray removed `allowInsecure`. Links that set it are imported with
  certificate verification on, and you get a warning. Use `pcs=`
  (pinned cert SHA-256) or `vcn=` links instead.
- Some panels pick the subscription format by User-Agent. If a subscription
  comes back empty, try `--user-agent Happ/3.0`. Panels with device limits
  need `--hwid`.
- Encrypted `happ://crypt…` links can't be imported. Use the plain
  subscription URL.
- `--system-proxy` is macOS only for now. It restores the previous settings
  on exit.
- `ping` tests at most `ping.per_endpoint` (default 2) servers per IP at
  once. Subscriptions often put dozens of "servers" behind one entry
  point, and testing them all at once makes that entry drop connections.
- Quitting Happ's window doesn't stop its VPN. Disconnect it in Happ, or
  check with `scutil --nc list`.
