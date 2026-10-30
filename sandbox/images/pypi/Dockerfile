# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy package-firewall sandbox image: pypi (CPython 3.13 slim).
#   Build context is control-plane/ (the Go module). Build via: make sandbox-images
# The PEP 517 build backends are hash-pinned and installed from wheels only, so a hostile sdist's build runs with
# a known, verified toolchain (the backend code it triggers is what we are analyzing, not these).

FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ENV GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RUNNER_VERSION=3.0.0-dev
RUN go build -trimpath -ldflags "-s -w -X aegisproxy/control-plane/internal/sandbox/runner.Version=${RUNNER_VERSION}" \
      -o /out/aegis-runner ./cmd/aegis-sandbox-runner

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
ARG RUNNER_VERSION=3.0.0-dev
LABEL org.aegisproxy.sandbox.ecosystem="pypi" \
      org.aegisproxy.sandbox.runner-version="${RUNNER_VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# Hash-pinned PEP 517 build backends (and their closure), wheels only.
RUN cat > /tmp/build-backends.txt <<'EOF'
flit-core==4.2.0 --hash=sha256:2bee22dc8ba89c2e35b4e1ad575e596aac945c85672dd8f3cad21b629036e044
hatchling==1.33.0 --hash=sha256:415290b84f464d2884303fca8974d38e7b85579069fab02a15db0828fbb1446d
packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pathspec==1.1.1 --hash=sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189
pdm-backend==2.5.0 --hash=sha256:5b8746b567a16a1fd506ce66ee28e89d46374526f52238aa1b96cc2c08245c63
pluggy==1.7.0 --hash=sha256:7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec
poetry-core==2.5.0 --hash=sha256:98ee465b66f7e14bb9fbe68fb5e00d0cff184f036993ec94610ae4b5612f3add
setuptools==84.2.1 --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2
tomlkit==0.15.2 --hash=sha256:05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437
trove-classifiers==2026.9.21.13 --hash=sha256:8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17
wheel==0.48.0 --hash=sha256:3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab
EOF
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: --no-deps -r /tmp/build-backends.txt \
 && rm -f /tmp/build-backends.txt
RUN set -eux; \
    if id -u 1000 >/dev/null 2>&1; then userdel -rf "$(id -nu 1000)" 2>/dev/null || true; fi; \
    groupadd -g 1000 sandbox; \
    useradd -m -u 1000 -g 1000 -s /bin/sh sandbox; \
    mkdir -p /home/sandbox /aegis /work; \
    chown 1000:1000 /home/sandbox /work
COPY --from=build /out/aegis-runner /aegis/runner
ENTRYPOINT ["/aegis/runner"]
