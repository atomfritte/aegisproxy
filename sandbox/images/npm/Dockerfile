# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy package-firewall sandbox image: npm (Node 22 LTS on Debian slim).
#   Build context is control-plane/ (the Go module). Build via: make sandbox-images  (or scripts/sandbox/build-images.sh)
# Base images are pinned by tag + digest.

FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ENV GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RUNNER_VERSION=3.0.0-dev
RUN go build -trimpath -ldflags "-s -w -X aegisproxy/control-plane/internal/sandbox/runner.Version=${RUNNER_VERSION}" \
      -o /out/aegis-runner ./cmd/aegis-sandbox-runner

FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
ARG RUNNER_VERSION=3.0.0-dev
LABEL org.aegisproxy.sandbox.ecosystem="npm" \
      org.aegisproxy.sandbox.runner-version="${RUNNER_VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# Create the unprivileged uid-1000 user `sandbox` (the base node image uses uid 1000 for `node`; replace it).
RUN set -eux; \
    if id -u 1000 >/dev/null 2>&1; then userdel -rf "$(id -nu 1000)" 2>/dev/null || true; fi; \
    groupadd -g 1000 sandbox; \
    useradd -m -u 1000 -g 1000 -s /bin/sh sandbox; \
    mkdir -p /home/sandbox /aegis /work; \
    chown 1000:1000 /home/sandbox /work
COPY --from=build /out/aegis-runner /aegis/runner
# The runner starts as root to prepare observers and bind the loopback resolver/sinks, then drops every analyzed
# process to uid 1000 itself.
ENTRYPOINT ["/aegis/runner"]
