#!/bin/sh
# Prepares python.org's Windows CPython 3.12 (embeddable, hash-checked) with the data-plane's win_amd64
# wheels from the hash lock data-plane/requirements-lock.txt (mitmproxy 12.3.0, YARA-X 1.22.0 and the security
# overrides), as the Windows installer installs them by default.
#   scripts/wine/prepare-windows-python.sh <work-dir>      -> <work-dir>/python
set -eu
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mkdir -p "$1" && CDPATH='' cd -- "$1" && pwd)
PY_VERSION=3.12.10
PY_SHA256=4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3
rm -rf "$WORK/python" "$WORK/site"; mkdir -p "$WORK/python/Lib" "$WORK/site"
curl -fsSL -o "$WORK/python-embed.zip" "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-amd64.zip"
echo "$PY_SHA256  $WORK/python-embed.zip" | sha256sum -c -
python3 -I -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$WORK/python-embed.zip" "$WORK/python"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$WORK:/w" -v "$REPO/data-plane:/lock:ro" python:3.14-slim sh -c '
  pip install --quiet --user uv==0.8.0 &&
  /tmp/.local/bin/uv pip install --quiet --require-hashes --no-deps --only-binary :all: \
    --python-platform x86_64-pc-windows-msvc --python-version 3.12 --target /w/site -r /lock/requirements-lock.txt'
mv "$WORK/site" "$WORK/python/Lib/site-packages"
printf 'python312.zip\n.\nLib\\site-packages\nimport site\n' > "$WORK/python/python312._pth"
echo "Windows Python ready: $WORK/python"
