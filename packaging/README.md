# Packaging notes: running as root

TUN mode needs root. This is how proxy-router gets it, and what that
still trusts.

## What runs as root

- **The TUN service** runs `/var/lib/proxy-router/proxy-router` (macOS:
  `/Library/Application Support/proxy-router/proxy-router`), a copy owned
  by root, as
  `proxy-router --dir <config dir> --uid <your uid> run --service --tun`.
- **`start`, `stop`, `restart`, `uninstall`** do their root half through
  `sudo`, or through the desktop's password dialog when the tray runs them
  (`pkexec` on Linux, `osascript ... with administrator privileges` on
  macOS). The user half (the proxy-mode user service) is done as you, never
  as root. What they run as root is the TUN service's copy above, once
  it's installed, after checking that it and every directory above it are
  owned by root and not group- or world-writable.
- **Who root works for** is passed as `--uid`. When sudo or pkexec ran the
  command, the uid they report (`SUDO_UID`, `PKEXEC_UID`) has to match it.
  Root ignores `$PROXY_ROUTER_HOME`, `$XDG_CONFIG_HOME` and `$HOME`, and
  refuses a config directory that isn't owned by that user, or that
  another user could change (including through the directories above it).
- **Connecting and disconnecting TUN mode** from the tray don't ask every
  time. The first password dialog also writes
  `/etc/sudoers.d/proxy-router`, which lets that user run the root-owned
  copy above as root without a password, with exactly
  `--dir <config dir> --uid <your uid> start --tun` or the same with
  `stop --system`. Nothing else matches the rule, so switching to proxy
  mode, updating the service, `restart` and `uninstall` still ask. The
  rule is removed with the system service (`uninstall`, or switching to
  proxy mode). On Linux this needs `sudo`; without it, pkexec asks each
  time.

## What still trusts your proxy-router binary

The copy root runs has to come from somewhere: from the `proxy-router`
binary you run. So installing the TUN service the first time, and
`restart` when the service has a different build (the tray's "Update
Service to This Build"), run *your* binary as root, which then copies
itself into place. Anything that can replace that binary (anything
running as you) gets root when you next approve one of those. `start`
says `installing this build (...) as the TUN service's binary` when it's
about to do that. Approve it only for a build you just installed.

Everything else (connecting or disconnecting an installed TUN service,
switching to proxy mode, `stop`, `uninstall`) runs root's own copy and
doesn't trust your binary. Two exceptions: a TUN service installed before
`--uid` existed is updated with your binary the first time, and one
installed before the sudoers rule existed runs your binary once (only
`tray --allow-sudo`, which writes the rule) the first time you connect or
disconnect from the tray; the action itself still runs the root-owned
copy.

On macOS `osascript` reports no uid, so `--uid` isn't cross-checked
there. The config directory still has to be owned by that uid.

## polkit policy (Linux, optional)

Without a policy, pkexec authorizes `org.freedesktop.policykit.exec`
("run a program as root"). `linux/io.github.knocking4thcylinder.proxy-router.policy`
gives the root-owned copy its own action, with a message saying what it's
for. Distribution packages can ship it, or you can install it yourself:

```sh
sudo install -m 644 packaging/linux/io.github.knocking4thcylinder.proxy-router.policy /usr/share/polkit-1/actions/
```

It only matches `/var/lib/proxy-router/proxy-router` (polkit compares the
program's path). It doesn't apply to the install step, which runs your
binary under the generic action. It stays `auth_admin`: relaxing it to
`yes` or `auth_self` would let anything running as you control a root
service that runs `--dir <any path>` without a password. Connecting and
disconnecting from the tray stop asking after the first dialog because of
the sudoers rule above, not because of this policy. On read-only `/usr`
systems (SteamOS) it can't be installed. Nothing depends on it.

## The fixed design

The remaining exposure goes away only with a small root-owned helper
that's installed once by a package (not copied from a user-writable
binary), takes a fixed set of operations (install, start, stop, remove
the TUN service), and never takes a program or binary path from the
caller. It would update the service only from a package-managed path, or
after checking a signature. The service itself would read the user's
files through a narrow interface, or drop privileges after setting up
the TUN device. That's a packaging change and is out of scope here.
