# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy control-plane + bundled web console ("all-in-one" image).
#   docker build -t ghcr.io/atomfritte/aegisproxy-control-plane:v3.0.0 --build-arg VERSION=3.0.0 .   (or: make images)
# For split deployments use control-plane/Dockerfile (API only) and frontend/Dockerfile (console only).
# Base images are pinned by digest (tag kept for readability; Dependabot updates both).

FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS ui
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
# Only the go.sum-verified modules: a vendor/ directory or a go.work in the context (excluded by .dockerignore
# anyway) would otherwise replace them without any checksum check.
ENV GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY control-plane/go.mod control-plane/go.sum ./
RUN go mod download
COPY control-plane/ ./
ARG VERSION=3.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/aegis-control-plane . \
 && mkdir -p /out/data /out/certs

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="AegisProxy control-plane" \
      org.opencontainers.image.description="Policy, threat-intel and audit control-plane with bundled web console" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"
COPY --from=build /out/aegis-control-plane /app/aegis-control-plane
COPY --from=ui /src/dist /app/ui
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/certs /certs
ENV CONTROL_PLANE_PORT=8081 DATA_DIR=/data CERTS_DIR=/certs AEGIS_UI_DIR=/app/ui
USER 65532:65532
EXPOSE 8081
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD ["/app/aegis-control-plane", "healthcheck"]
ENTRYPOINT ["/app/aegis-control-plane"]
