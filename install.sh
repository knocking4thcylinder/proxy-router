#!/bin/sh
# Install a proxy-router release for Linux or macOS arm64.
#
#   curl -fsSL https://github.com/knocking4thcylinder/proxy-router/releases/latest/download/install.sh | sh
#   ./install.sh v0.1.0
#
# Set BINDIR to choose where the binary goes (default: ~/.local/bin).

set -eu

repo="knocking4thcylinder/proxy-router"
version="${1:-}"

case "$version" in
  -h|--help)
    echo "usage: $0 [version]"
    echo "  version defaults to the latest release, e.g. v0.1.0"
    exit 0
    ;;
  ""|latest) version="" ;;
  v*) ;;
  *) version="v$version" ;;
esac

case "$(uname -s)" in
  Linux) asset_os=linux ;;
  Darwin) asset_os=macos ;;
  *)
    echo "unsupported OS: $(uname -s); use the Windows .zip release" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) asset_arch=amd64 ;;
  arm64|aarch64) asset_arch=arm64 ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [ "$asset_os" = "macos" ] && [ "$asset_arch" != "arm64" ]; then
  echo "macOS builds are arm64 only" >&2
  exit 1
fi

asset="proxy-router-$asset_os-$asset_arch.tar.gz"
if [ -n "$version" ]; then
  base="https://github.com/$repo/releases/download/$version"
else
  base="https://github.com/$repo/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    echo "need curl or wget" >&2
    exit 1
  fi
}

echo "Downloading $asset..."
download "$base/$asset" "$tmp/$asset"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS"

expected="$(awk -v a="$asset" '$2 == a { print $1; exit }' "$tmp/SHA256SUMS")"
if [ -z "$expected" ]; then
  echo "no checksum for $asset" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
else
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
fi
if [ "$actual" != "$expected" ]; then
  echo "checksum mismatch for $asset" >&2
  exit 1
fi

tar -xzf "$tmp/$asset" -C "$tmp"

bindir="${BINDIR:-$HOME/.local/bin}"
mkdir -p "$bindir"
install -m 755 "$tmp/proxy-router" "$bindir/proxy-router"

echo "installed $bindir/proxy-router"
"$bindir/proxy-router" --version

case ":$PATH:" in
  *":$bindir:"*) ;;
  *)
    echo
    echo "Add it to your PATH:"
    echo "  export PATH=\"$bindir:\$PATH\""
    ;;
esac

echo
echo "If the background service is installed, run: proxy-router restart"
