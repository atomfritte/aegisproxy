#!/usr/bin/env bash
# Builds the four AegisProxy package-firewall sandbox images, one per ecosystem. The build context is the Go
# module (control-plane/); the runner is compiled in a multi-stage build and copied into each ecosystem runtime.
#
#   scripts/sandbox/build-images.sh [TAG] [VERSION]
#
# TAG defaults to ${SANDBOX_TAG:-dev}; VERSION (stamped into the runner + image label) defaults to TAG. Images are
# tagged aegisproxy-sandbox-<eco>:<TAG>.
set -euo pipefail

tag=${1:-${SANDBOX_TAG:-dev}}
version=${2:-$tag}
root=$(git -C "$(dirname "${BASH_SOURCE[0]}")/../.." rev-parse --show-toplevel)
ctx="$root/control-plane"

ecos=${SANDBOX_ECOSYSTEMS:-npm pypi nuget psgallery}
for eco in $ecos; do
    dockerfile="$root/sandbox/images/$eco/Dockerfile"
    [ -f "$dockerfile" ] || { echo "build-images: no Dockerfile for $eco" >&2; exit 1; }
    echo "build-images: building aegisproxy-sandbox-$eco:$tag"
    docker build \
        -f "$dockerfile" \
        --build-arg RUNNER_VERSION="$version" \
        -t "aegisproxy-sandbox-$eco:$tag" \
        "$ctx"
done
echo "build-images: done ($ecos)"
