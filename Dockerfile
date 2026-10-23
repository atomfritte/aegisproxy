# syntax=docker/dockerfile:1.7
# AegisProxy control-plane + bundled web console ("all-in-one" image).
#   docker build -t aegisproxy/control-plane:2.1.0 --build-arg VERSION=2.1.0 .
# For split deployments use control-plane/Dockerfile (API only) and frontend/Dockerfile (console only).

FROM node:24-alpine AS ui
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY control-plane/go.mod control-plane/go.sum ./
RUN go mod download
COPY control-plane/ ./
ARG VERSION=2.1.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/aegis-control-plane . \
 && mkdir -p /out/data /out/certs

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="AegisProxy control-plane" \
      org.opencontainers.image.description="Policy, threat-intel and audit control-plane with bundled web console" \
      org.opencontainers.image.licenses="Proprietary"
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
