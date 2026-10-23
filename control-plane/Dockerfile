# syntax=docker/dockerfile:1.7
# AegisProxy control-plane API only (no bundled console) — for deployments where the console is
# hosted separately (frontend/Dockerfile, CDN, IIS, ...).
#   docker build -t aegisproxy/control-plane-api:2.1.0 control-plane/

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=2.1.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/aegis-control-plane . \
 && mkdir -p /out/data /out/certs

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegis-control-plane /app/aegis-control-plane
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/certs /certs
ENV CONTROL_PLANE_PORT=8081 DATA_DIR=/data CERTS_DIR=/certs
USER 65532:65532
EXPOSE 8081
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD ["/app/aegis-control-plane", "healthcheck"]
ENTRYPOINT ["/app/aegis-control-plane"]
