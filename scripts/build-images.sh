#!/usr/bin/env bash
# Builds the four AegisProxy images (make images) from a committed tree, not from the working copy: the build
# contexts are exported with `git archive`, so neither a file planted in the checkout (tracked or not, however it
# is hidden from `git status`) nor an uncommitted change reaches an image. The .dockerignore allowlists of that
# tree must be current (scripts/gen-dockerignore.sh).
#
#   scripts/build-images.sh REGISTRY TAG VERSION [REV]     REV defaults to HEAD
set -euo pipefail

registry=${1:?registry} tag=${2:?image tag} version=${3:?version} rev=${4:-HEAD}
root=$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)
contexts=(Dockerfile .dockerignore control-plane data-plane frontend)

commit=$(git -C "$root" rev-parse --verify --quiet "$rev^{commit}") || { echo "build-images: $rev is not a commit" >&2; exit 1; }
"$root/scripts/gen-dockerignore.sh" --check "$commit"
if [ "$rev" = HEAD ] && ! git -C "$root" diff --quiet HEAD -- "${contexts[@]}"; then
    echo "build-images: uncommitted changes below ${contexts[*]} are NOT part of the images (built from HEAD $commit):" >&2
    git -C "$root" diff --stat HEAD -- "${contexts[@]}" >&2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/aegis-images.XXXXXX")
trap 'rm -rf "$work"' EXIT
git -C "$root" archive --format=tar "$commit" -- "${contexts[@]}" | tar -x -C "$work"
echo "build-images: building $commit from $work"

docker build -t "$registry/aegisproxy-control-plane:$tag" --build-arg VERSION="$version" "$work"
docker build -t "$registry/aegisproxy-control-plane-api:$tag" --build-arg VERSION="$version" "$work/control-plane"
docker build -t "$registry/aegisproxy-data-plane:$tag" "$work/data-plane"
docker build -t "$registry/aegisproxy-console:$tag" "$work/frontend"
