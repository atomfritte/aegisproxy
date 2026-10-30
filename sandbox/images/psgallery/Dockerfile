# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy package-firewall sandbox image: psgallery (PowerShell 7.5 on Ubuntu 24.04).
#   Build context is control-plane/ (the Go module). Build via: make sandbox-images

FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ENV GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RUNNER_VERSION=3.0.0-dev
RUN go build -trimpath -ldflags "-s -w -X aegisproxy/control-plane/internal/sandbox/runner.Version=${RUNNER_VERSION}" \
      -o /out/aegis-runner ./cmd/aegis-sandbox-runner

FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81
ARG RUNNER_VERSION=3.0.0-dev
LABEL org.aegisproxy.sandbox.ecosystem="psgallery" \
      org.aegisproxy.sandbox.runner-version="${RUNNER_VERSION}"
ENV POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# Ubuntu 24.04 ships an `ubuntu` user at uid 1000; replace it with `sandbox`.
RUN set -eux; \
    if id -u 1000 >/dev/null 2>&1; then userdel -rf "$(id -nu 1000)" 2>/dev/null || true; fi; \
    groupadd -g 1000 sandbox; \
    useradd -m -u 1000 -g 1000 -s /bin/sh sandbox; \
    mkdir -p /home/sandbox /aegis /work; \
    chown 1000:1000 /home/sandbox /work
COPY --from=build /out/aegis-runner /aegis/runner
ENTRYPOINT ["/aegis/runner"]
