#!/usr/bin/env bash
# pip-audit of the Python packages an image actually ships (CI images job, DEP4-3): the package directories of
# the image's own interpreter are copied out of the image (docker create + docker cp) and audited with the
# hash-locked pip-audit of .github/requirements-audit.txt. This covers the base image's packages and the
# overrides installed on top of it, which the lock-file audits do not see. Nothing from the image is executed
# on the host; the image's python3 runs once, without network, to name its package directories.
#
#   scripts/audit-image-python.sh IMAGE WORKDIR [DISTRIBUTION...]
#       DISTRIBUTION: names that must be among the copied distributions (fails closed on a wrong copy)
#   PIP_AUDIT=/path/to/pip-audit scripts/audit-image-python.sh ...   use an existing pip-audit
set -euo pipefail

image=${1:?image} work=${2:?work directory}
shift 2
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -e "$work" ] && [ -n "$(ls -A "$work")" ]; then echo "audit-image-python: $work is not empty" >&2; exit 1; fi
mkdir -p "$work"

pip_audit=${PIP_AUDIT:-}
if [ -z "$pip_audit" ]; then
    python3 -m venv "$work/venv"
    "$work/venv/bin/pip" install -q --require-hashes --only-binary=:all: -r "$root/.github/requirements-audit.txt"
    pip_audit=$work/venv/bin/pip-audit
fi

# Directories that hold the image's installed distributions (site-packages / dist-packages).
mapfile -t dirs < <(docker run --rm --network none --entrypoint python3 "$image" -I -c '
import importlib.metadata as m
print("\n".join(sorted({str(d.locate_file("")) for d in m.distributions()})))')
[ "${#dirs[@]}" -gt 0 ] || { echo "audit-image-python: no installed distributions found in $image" >&2; exit 1; }

id=$(docker create "$image")
trap 'docker rm -f "$id" >/dev/null 2>&1 || true' EXIT
paths=()
for d in "${dirs[@]}"; do
    case "$d" in /*) ;; *) echo "audit-image-python: unexpected package directory '$d'" >&2; exit 1 ;; esac
    mkdir -p "$work/root$d"
    docker cp -q "$id:$d/." "$work/root$d"
    paths+=(--path "$work/root$d")
done

# Fail closed when the copy does not hold what the image is known to ship.
python3 -I - "$work/root" "${#dirs[@]}" "${dirs[@]}" "$@" <<'PY'
import importlib.metadata as m, re, sys
root, n = sys.argv[1], int(sys.argv[2])
dirs, expected = sys.argv[3:3 + n], sys.argv[3 + n:]
norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()
dists = list(m.distributions(path=[root + d for d in dirs]))
names = {norm(d.metadata["Name"]) for d in dists}
print(f"{len(dists)} distributions in {', '.join(dirs)}")
missing = {norm(e) for e in expected} - names
if not dists or missing:
    sys.exit("audit-image-python: not found in the copied package directories: " + ", ".join(sorted(missing)))
PY
"$pip_audit" "${paths[@]}"
