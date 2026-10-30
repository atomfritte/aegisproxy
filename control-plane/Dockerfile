# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy control-plane API only (no bundled console) — for deployments where the console is
# hosted separately (frontend/Dockerfile, CDN, IIS, ...).
#   docker build -t ghcr.io/atomfritte/aegisproxy-control-plane-api:v3.0.0 control-plane/   (or: make images)
# Base images are pinned by digest (tag kept for readability; Dependabot updates both).

FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
# Only the go.sum-verified modules: a vendor/ directory or a go.work in the context (excluded by .dockerignore
# anyway) would otherwise replace them without any checksum check.
ENV GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=3.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/aegis-control-plane . \
 && mkdir -p /out/data /out/certs

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/aegis-control-plane /app/aegis-control-plane
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/certs /certs
ENV CONTROL_PLANE_PORT=8081 DATA_DIR=/data CERTS_DIR=/certs
USER 65532:65532
EXPOSE 8081
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD ["/app/aegis-control-plane", "healthcheck"]
ENTRYPOINT ["/app/aegis-control-plane"]
