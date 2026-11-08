# syntax=docker/dockerfile:1

# The panel needs cgo and the OpenGL / Wayland / X11 development headers.
# Override GO_VERSION if the 1.27 image is not available yet.
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
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
#   docker buildx build --output=dist .
FROM scratch AS artifact
COPY --from=build /out/proxy-router /proxy-router
