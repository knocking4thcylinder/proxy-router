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
proxy-router start               # background service: SOCKS5 on :10808, HTTP on :10809
proxy-router start --tun         # or capture all traffic (asks for sudo)
proxy-router status
```

Then point apps at `socks5://127.0.0.1:10808` or `http://127.0.0.1:10809`,
e.g. `export https_proxy=http://127.0.0.1:10809` (not needed with `--tun`).

## Shell completions

Generate completions from the installed binary. They include command flags
(also after a bare `proxy-router run `), cached server names and indices,
subscription names, groups, and file/directory paths where appropriate.
Completions respect `--dir` and `$PROXY_ROUTER_HOME` and read cached state
without fetching subscriptions or creating config files.

**Fish:**

```fish
mkdir -p ~/.config/fish/completions
proxy-router completion fish > ~/.config/fish/completions/proxy-router.fish
source ~/.config/fish/completions/proxy-router.fish
```

**Bash:** add `source <(proxy-router completion bash)` to `~/.bashrc`
(requires bash-completion).

**Zsh:** after `autoload -Uz compinit; compinit` in `~/.zshrc`, add
`source <(proxy-router completion zsh)`.

**PowerShell:** add `proxy-router completion powershell | Out-String | Invoke-Expression`
to your PowerShell profile.

Rebuild or reinstall the binary after updating proxy-router. If replacing
older completions, regenerate the script and reload it or open a new shell.

## Background service

`proxy-router start` installs proxy-router as a service and starts it; it
then starts by itself, and is restarted if it crashes. The `proxy-router`
command you type only controls it.

| Mode | Runs as | Starts | macOS | Linux |
| --- | --- | --- | --- | --- |
| proxy (default) | you | at login | LaunchAgent | systemd user unit |
| TUN (`--tun`) | root | at boot | LaunchDaemon | systemd system unit |

- **Mode:** `--tun` / `--no-tun`, else the mode of the installed service,
  else `tun.enabled` in `config.yaml`. TUN mode needs root, so `start` (and
  `stop`, `restart`) ask for sudo for the system service's part; the user
  service is always handled as you. Switching modes replaces the old
  service. See [packaging/README.md](packaging/README.md) for what runs as
  root.
- **Changes apply live:** `use`, `sub update`, and edits to `config.yaml` or
  the rules file. The service watches its files the same way `run` does.
- **After rebuilding proxy-router**, run `proxy-router restart`. The service
  runs its own copy of the binary (in `~/Library/Application Support/proxy-router/`,
  `/Library/Application Support/proxy-router/`, `~/.local/share/proxy-router/`
  or `/var/lib/proxy-router/`), so a rebuild doesn't affect it until then.
  `status` notes when the copy is out of date. `start` doesn't update an
  installed TUN service's copy; only `restart` does.
- **At boot or login, TUN mode waits** for a network connection, and for
  another VPN to disconnect, instead of failing. `status` shows what it's
  waiting for.
- **Logs** go to `~/.config/proxy-router/proxy-router.log`
  (`proxy-router logs -f`; `start -v` / `-vv` for more detail). The log is
  cleared when it reaches 10 MB.

`run` still runs proxy-router in the foreground, for debugging. It refuses
to start while the service is running. It prints a running status and stays
attached until Ctrl-C, including while subscriptions refresh in the
background. Refreshes report when they finish. To return to the shell while
the proxy runs, stop the foreground run and use `proxy-router start --tun`
(or `proxy-router start` for proxy-only mode).

## Tray icon

```sh
proxy-router tray
```

puts an icon in the system tray (the menu bar on macOS) and gives you the
terminal back; the icon stays after you close the terminal. Its output
goes to `~/.config/proxy-router/tray.log` (`--foreground` keeps it attached
instead, for debugging).

The icon is orange while connected, faded while starting or waiting for the
network, and grey when disconnected. Its menu:

- **Connect / Disconnect**: `start` / `stop` the background service
- **TUN Mode (All Traffic)**: switch modes (restarts the service if it's
  running). TUN mode asks for your password in the system's dialog
  (polkit on Linux, the standard macOS prompt) instead of sudo. On macOS
  that's once: the dialog also adds a sudoers rule
  (`/etc/sudoers.d/proxy-router`) so connecting and disconnecting TUN mode
  don't ask again. It allows only the root part of those two (`start
  --tun` and `stop --system`, for your user and config folder), run by
  the service's own root-owned copy of proxy-router, so switching modes
  and updating the service to a new build still ask. Switching to proxy
  mode and `uninstall` remove the rule.
- **Servers**: pick a server (grouped by subscription), use the fastest,
  update subscriptions
- **Edit Routing Rules**, **Show Log**, **Open Config Folder**
- **Start Tray at Login**: adds a login item (`~/.config/autostart` on
  Linux, a LaunchAgent on macOS) that runs this `proxy-router` binary, so
  keep it somewhere stable (e.g. `~/go/bin`)

Quitting the tray leaves the service running.

- **Linux:** works on KDE Plasma (including the Steam Deck's desktop mode),
  XFCE, Cinnamon and others with StatusNotifierItem support; GNOME needs
  the *AppIndicator and KStatusNotifierItem Support* extension. No extra
  libraries are needed.
- **macOS:** the menu bar icon needs cgo, so build on the Mac with Xcode's
  command line tools installed (`xcode-select --install`); a build without
  cgo still works, minus `tray`.

## Commands

| Command | |
| --- | --- |
| `sub add <url> [-n name] [--user-agent UA] [-H 'K: V'] [--hwid]` | add a subscription |
| `sub list [--show-url]` | servers, last update, traffic used / total, expiry; optionally show full URLs |
| `sub update [name...]` | re-fetch (all by default) |
| `sub remove <name>` | |
| `add <link>...` / `add -` | add servers from links (or stdin) |
| `remove <server>` | remove a manually added server |
| `list [-g group] [-v]` | list servers; `-v` includes warnings |
| `use <server>` / `use --fastest [-g group]` | select the server for `proxy` |
| `ping [server...] [-g group] [--exit] [-q]` | live latency tests through each proxy; `--exit` checks exit countries; `-q` prints only the final results |
| `start [--tun \| --no-tun] [--force] [-v]` | start the background service and enable it at login (boot for TUN) |
| `stop` | stop the service; it won't start automatically until `start` |
| `restart` | restart it (picks up a rebuilt binary) |
| `status` | is it running, which mode, server, listen addresses |
| `logs [-f] [-n lines]` | the service's log |
| `uninstall` | remove the service (config and servers are kept) |
| `tray` | tray / menu bar icon to connect, switch mode and pick servers |
| `run [-r rules.yaml] [-s server] [--system-proxy] [--tun [--force]] [-v\|-vv]` | run in the foreground instead (`--tun` needs sudo) |
| `config [-r rules.yaml] [-q] [--tun]` | validate, and print the generated Xray config |
| `geo update` | download fresh `geoip.dat` / `geosite.dat` |
| `init [--force]` | (re)create default `config.yaml` and `routing.yaml` |

`<server>` can be the number from `list`, the exact name, `group/name`, or
any unique part of the name. After `group/`, only that group's servers
match, so another subscription can't take over the name.

`ping` prints each result as it finishes, with an animated progress counter
and elapsed time in a terminal. The final table is sorted fastest first;
`*` marks the selected server. Live progress goes to stderr, so redirecting
stdout saves just the final table. Use `--quiet` (`-q`) to skip progress.
With `--exit`, countries appear as `Finland (FI)`; `unknown (lookup failed)`
means the latency test worked but the separate country lookup did not.
Pools have a separate `POOL` column showing how many members responded;
their latency and exit come from the fastest responding member.

While the service (or `run`) is active it picks up changes by itself:
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
`$PROXY_ROUTER_HOME`, which is ignored under sudo). Root only uses it if
it's yours and nobody else can write to it or the directories above it:

- `config.yaml`: listen addresses, interface binding, log level, update interval, User-Agent, geo URLs, ping URL
- `routing.yaml`: routing rules
- `state.json`: subscriptions, cached servers, selected server (managed by the CLI, mode 0600)
- `assets/`: geo files
- `proxy-router.log`: the background service's log
- `status.json`: what the running proxy-router is doing (for `status`)

## Pools (Auto)

A pool is a group of servers Xray balances between, skipping ones that stop
working.

**Provider pools.** Subscriptions are fetched with Happ's User-Agent, so
panels send the same full configs Happ gets. That includes entries like
"Авто"/"Турбо", which balance across several servers. They show up in
`list` as `pool of N`; select them like any server, and `ping` tests every
member (`170ms (5/5 alive)`). Providers often make these fall back to
`direct` (unproxied, from your real IP) whenever their servers look down,
including for the first minute after starting, before the first health
check. proxy-router falls back to the first member server instead and
never leaks.

**Your own pools,** in the rules file:

```yaml
pools:
  youtube:
    servers: "*"              # or [Швеция, "ALL VPN/🇩🇪 Germany", 12]
    strategy: leastPing       # leastPing, leastLoad, random, roundRobin
pool_probe:                   # one health check for all pools (an Xray limit)
  url: https://www.youtube.com/   # only use servers where this loads
  interval: 30s

rules:
  - outbound: pool:youtube
    domain: [geosite:youtube]
```

## Resolving names locally

With `resolve_locally: true` (the default), proxy-router resolves the
names of the sites you visit itself, using DNS-over-HTTPS through the
tunnel, and sends servers IP addresses. Servers' own resolvers can return
broken answers. With one real subscription, YouTube failed through every
one of 108 servers when they resolved it, and worked through all of them
once it was resolved locally. A `dns:` section in the rules file replaces
the default DoH servers. In TUN mode apps already connect to IP addresses,
so this mostly matters for the SOCKS/HTTP proxy.

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
proxy-router start --tun         # background service (asks for sudo)
sudo proxy-router run --tun      # or in the foreground
```

This captures all system traffic, so apps don't need proxy settings.
proxy-router creates a `utunN` interface and points `0.0.0.0/1` +
`128.0.0.0/1` at it. These beat the default route without replacing it, so
anything more specific keeps working as before: your LAN, and Tailscale's
peers and `100.64.0.0/10`. proxy-router's own connections are pinned to the
physical interface, so they can't loop back into the TUN. The routes are
removed on exit (and disappear with the interface anyway).

IPv6 is always taken over too (`::/1` + `8000::/1`). With `tun.ipv6: true`
it goes through the proxy; otherwise (the default) those routes reject it,
so apps fall back to IPv4 at once instead of leaking around the proxy.
Without IPv6 on the machine there's nothing to take over, and that's fine.

proxy-router only touches routes it owns. If another VPN already has the
split routes, TUN mode refuses to start instead of replacing them (on Linux
its routes are tagged `proto 112`).

```yaml
tun:
  ipv6: false        # true: proxy IPv6 too; false: block it
  kill_switch: true  # block traffic outside the TUN, see below
```

### DNS

System DNS is pointed into the TUN, where proxy-router answers it:

- **Linux with systemd-resolved** (`/etc/resolv.conf` →
  `127.0.0.53`): the TUN becomes resolved's DNS route for every name
  (`resolvectl dns/domain ~./default-route`), reverted on exit. Names with
  a more specific route keep theirs: Tailscale's tailnet, a LAN search
  domain like `lan`.
- **Linux without it** (a static `/etc/resolv.conf`): the kill switch
  redirects DNS bound for a local resolver into the TUN. With the kill
  switch off, proxy-router warns that those queries leak.
- **macOS:** the primary network service's DNS servers are overridden in
  the dynamic store (not saved to disk), kept in place when DHCP or the
  network changes, and restored on exit.

The resolver address is `198.18.0.53`, which only exists inside the TUN.

### Kill switch

`tun.kill_switch` (on by default) is a firewall policy that blocks traffic
leaving outside the TUN: an nftables table `inet proxy_router` on Linux, a
pf anchor `com.apple/proxy-router` on macOS. It lets through:

- loopback and the TUN itself;
- proxy-router's own connections (on Linux they carry socket mark
  `0x7072`; pf has no marks, so on macOS it's anything run by root);
- `system_route` addresses (Tailscale, including MagicDNS's DNS);
- the LAN, link-local, multicast and broadcast, and DHCP and IPv6
  neighbour discovery;

and rejects DNS (port 53 and 853) to anything else, LAN resolvers
included. A LAN-only name (`printer.lan`) then only resolves if you add the
router's address to `system_route`.

It's on from the moment the TUN comes up, and **it stays on when the
service exits**: while it restarts after a crash or a config error, and
during `proxy-router restart`, nothing leaks; traffic just stops. A
foreground `run --tun` removes it when you stop it.

**If the network is stuck** (the service keeps failing, or you stopped it
with `systemctl`/`launchctl` directly):

```sh
sudo proxy-router stop     # stops the service and removes the kill switch
```

`stop`, `uninstall` and switching to proxy mode always remove it. It isn't
saved anywhere, so a reboot also clears it, but the service puts it back
once TUN mode is up. By hand: `sudo nft delete table inet proxy_router`
(Linux) or `sudo pfctl -a com.apple/proxy-router -F all` (macOS). Set
`tun.kill_switch: false` to turn it off. pf stays enabled once proxy-router
enabled it; with only macOS's own rules that changes nothing.

Not covered: traffic before the service first brings the TUN up after a
boot, and traffic forwarded for containers or VMs (only this machine's own
traffic is filtered).

On Linux, TUN mode needs `CAP_NET_ADMIN` (the TUN device, routes,
nftables, socket marks, binding to the interface), netlink and
`AF_INET`/`AF_INET6`/`AF_UNIX` sockets, `/dev/net/tun`, and D-Bus or
varlink access to systemd-resolved. Network tools (`ip`, `nft`,
`resolvectl`; `route`, `pfctl`, `scutil`, `netstat` on macOS) are run from
the system directories, never from `$PATH`.

On Linux, tailscaled's own encrypted traffic to its peers also follows these
routes, so it goes through the proxy. Tailnet addresses still work, but
peer-to-peer connections may fall back to relays.

How it works:

- **Two Xray instances.** A small front instance owns the TUN device and
  forwards everything over loopback SOCKS to the main instance, which has
  the servers, rules and DNS. Config changes only restart the main
  instance; the device and routes stay up. (Xray doesn't release a TUN
  device when an instance closes, so restarting it would fail with "device
  or resource busy".) If the main instance can't be restored after a
  failed reload, `run` exits rather than staying up with nothing behind it.
- **DNS is answered by proxy-router.** Queries apps send through the TUN
  (to `198.18.0.53`, see above, or any other resolver) are answered from
  Xray's cached resolver: DNS-over-HTTPS through the tunnel. Tailscale
  names (`*.ts.net`) go to the system resolver.
- **Server names never depend on the tunnel.** Server hostnames are
  resolved before the TUN starts and written into the config as IPs. If that
  fails, Xray resolves them with DoH sent *outside* the tunnel, pinned to
  the physical interface. The same goes for the pool health-check host.
  Resolving them through the tunnel would deadlock, which showed up as
  "can't connect to anything".
- **proxy-router's own connections bypass the TUN** by binding to the
  physical interface (`en0`, `eth0`...). On macOS that binding only works
  through a default route scoped to the interface, which macOS doesn't
  create for the primary interface, so `run --tun` adds one (and removes it
  on exit). Without it every connection to the servers fails with "network
  is unreachable".
- **One VPN at a time.** `run --tun` refuses to start while another VPN
  (Happ, Hiddify, a WireGuard tunnel...) owns the default route, because
  two VPNs capturing all traffic break each other's routing and DNS.
  Disconnect it first (closing its window isn't enough; `scutil --nc list`
  shows what's connected on macOS) or pass `--force`.

Files written while running under sudo stay owned by you.
`proxy-router config --tun` shows the TUN config without needing root.

## Tailscale

`system_route` (in `config.yaml`) lists destinations that always use the
system's own routing: never proxied, never pinned to an interface, never
captured by the TUN. (In TUN mode, traffic for these that still arrives
through the TUN is rejected: it means the OS has no other route for it,
and handing it back would loop.) By default that's Tailscale's
`100.64.0.0/10`,
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
- Servers from subscriptions are rebuilt from known-safe Xray options
  only. Local certificate files, socket marks and interfaces, kernel
  WireGuard, VLESS reverse and server-only options are dropped (`list -v`
  shows what), and a provider can't make the selected server a direct or
  blocking outbound. Provider health checks must use https and can't make
  direct requests.
- Subscriptions are fetched as Happ (`Happ/3.24.1`) by default. Change it
  with `user_agent` in `config.yaml` or `sub add --user-agent`. Panels with
  device limits need `--hwid`.
- Encrypted `happ://crypt…` links can't be imported. Use the plain
  subscription URL.
- `--system-proxy` is macOS only for now. It restores the previous settings
  on exit.
- `ping` tests at most `ping.per_endpoint` (default 2) servers per IP at
  once. Subscriptions often put dozens of "servers" behind one entry
  point, and testing them all at once makes that entry drop connections.
- Server names don't always say where traffic exits. `ping --exit` shows
  the real country. Some providers fall back to a Russian exit when their
  foreign link is down, and then sites blocked in Russia fail.
- Quitting Happ's window doesn't stop its VPN. Disconnect it in Happ, or
  check with `scutil --nc list`.
