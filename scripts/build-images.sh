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
# git archive also applies export-ignore and export-subst from $GIT_DIR/info/attributes, which `git status` does not
# show: the exported tree must be exactly the committed one (every file with its committed content, nothing else).
want=$(git -C "$root" ls-tree -r --format='%(path) %(objectname)' "$commit" -- "${contexts[@]}" | LC_ALL=C sort)
mapfile -t files < <(find "$work" -type f -printf '%P\n' | LC_ALL=C sort)
got=$(paste -d' ' <(printf '%s\n' "${files[@]}") \
    <(for f in "${files[@]}"; do printf '%s/%s\n' "$work" "$f"; done | git -C "$root" hash-object --no-filters --stdin-paths) |
    LC_ALL=C sort)
if [ "$got" != "$want" ]; then
    echo "build-images: the exported tree differs from $commit (export-ignore / export-subst in .git/info/attributes?):" >&2
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | head -20 >&2 || true
    exit 1
fi
echo "build-images: building $commit from $work"

docker build -t "$registry/aegisproxy-control-plane:$tag" --build-arg VERSION="$version" "$work"
docker build -t "$registry/aegisproxy-control-plane-api:$tag" --build-arg VERSION="$version" "$work/control-plane"
docker build -t "$registry/aegisproxy-data-plane:$tag" "$work/data-plane"
docker build -t "$registry/aegisproxy-console:$tag" "$work/frontend"
