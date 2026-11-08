# syntax=docker/dockerfile:1

# The panel is cgo, so the build stage needs a C toolchain and the
# OpenGL / Wayland / X11 headers. It uses Debian slim for a glibc baseline
# old enough to run on current distros; the artifact stage is still empty
# except for the binary.
ARG GO_VERSION=1.27.1

FROM debian:bookworm-slim AS build

ARG GO_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        libc6-dev \
        pkg-config \
        libgl1-mesa-dev \
        libwayland-dev \
        libxkbcommon-dev \
        libx11-dev \
        libxcursor-dev \
        libxi-dev \
        libxrandr-dev \
        libxinerama-dev \
        libxxf86vm-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go here rather than inheriting the much larger golang image.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64|arm64|s390x|riscv64) ;; \
        armhf) arch=armv6l ;; \
        i386) arch=386 ;; \
        ppc64el) arch=ppc64le ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:$PATH

WORKDIR /src

# Keep the module download in its own layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build \
        -trimpath \
        -buildvcs=false \
        -o /out/proxy-router \
        .

# Export the binary with:
#   podman build --output type=local,dest="$HOME/.local/bin" .
FROM scratch AS artifact
COPY --from=build /out/proxy-router /proxy-router
