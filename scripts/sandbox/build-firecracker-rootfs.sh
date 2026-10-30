#!/usr/bin/env bash
# Exports a built sandbox image's filesystem into an ext4 rootfs for Firecracker. The AegisProxy runner is the
# init of the microVM: boot the kernel with `init=/aegis/runner` (an /init symlink is also created), attach this
# image as the root block device and the RunnerInput+artifact as a second virtio drive (/dev/vdb). The runner
# mounts /proc, /sys, /dev, /tmp, /run, brings loopback up, reads /dev/vdb and writes the report to the serial
# console between AEGIS-REPORT-BEGIN/END, then powers the VM off.
#
#   scripts/sandbox/build-firecracker-rootfs.sh <ecosystem> <out.ext4>
#
# Env: SANDBOX_TAG (image tag, default dev), ROOTFS_SIZE_MB (default 1024).
set -euo pipefail

eco=${1:?usage: build-firecracker-rootfs.sh <ecosystem> <out.ext4>}
out=${2:?usage: build-firecracker-rootfs.sh <ecosystem> <out.ext4>}
tag=${SANDBOX_TAG:-dev}
size=${ROOTFS_SIZE_MB:-1024}
img="aegisproxy-sandbox-$eco:$tag"

command -v mkfs.ext4 >/dev/null 2>&1 || { echo "mkfs.ext4 not found (install e2fsprogs)" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/aegis-rootfs.XXXXXX")
cid=""
cleanup() { [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

cid=$(docker create "$img")
mkdir -p "$work/root"
docker export "$cid" | tar -x -C "$work/root"
# The runner is PID 1; make both /sbin/init and /init resolve to it.
ln -sf /aegis/runner "$work/root/init"
mkdir -p "$work/root/sbin" && ln -sf /aegis/runner "$work/root/sbin/init"

rm -f "$out"
truncate -s "${size}M" "$out"
if command -v fakeroot >/dev/null 2>&1; then
    fakeroot mkfs.ext4 -F -q -L aegis-rootfs -d "$work/root" "$out"
else
    echo "warn: fakeroot not found; files in the image get the build user's uid/gid. The runner chowns the" >&2
    echo "      directories the analyzed process needs at runtime, so this only affects base-image ownership." >&2
    mkfs.ext4 -F -q -L aegis-rootfs -d "$work/root" "$out"
fi
echo "wrote $out (${size} MiB) from $img"
