# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy data-plane worker (mitmproxy 12 + AegisProxy addon).
#   docker build -t ghcr.io/atomfritte/aegisproxy-data-plane:v2.1.0 data-plane/   (or: make images)
# Base images are pinned by digest (tag kept for readability; Dependabot updates both).
FROM mitmproxy/mitmproxy:12.3.0@sha256:c8a3753de11fd8266afeb103e163f7b7ac6a4a568a707fa2e15b23d20acf4eba

USER root
# Every package added to the base image is pinned by hash; a missing or mismatching hash fails the build.
# requirements-image.txt: the security overrides of requirements-security.txt (mitmproxy's upper bound
# excludes the fix) and patched releases of vulnerable packages shipped in the base image.
COPY requirements-security.txt requirements-image.txt /opt/aegis/
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes --no-deps -r /opt/aegis/requirements-image.txt \
 && python3 -c "import re, sys, importlib.metadata as md; pins = re.findall(r'^([A-Za-z0-9_.-]+)==([^\s#]+)', open('/opt/aegis/requirements-security.txt').read(), re.M); bad = [f'{n} {md.version(n)} (requires {v})' for n, v in pins if md.version(n) != v]; sys.exit('requirements-image.txt does not install the security baseline: ' + ', '.join(bad)) if bad else None"
# YARA-X (VirusTotal's YARA engine) for YARA rule scanning; binary wheel, pinned by hash.
COPY requirements-extra.txt /opt/aegis/requirements-extra.txt
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes --no-deps -r /opt/aegis/requirements-extra.txt
COPY aegis_addon.py healthcheck.py entrypoint.sh /opt/aegis/
COPY aegis_dp/ /opt/aegis/aegis_dp/
# /var/lib/aegis/flow-spool: mount point of the optional traffic-record spool (AEGIS_FLOW_SPOOL_DIR). Owned by the
# runtime user so a new named volume mounted there inherits a writable, private directory.
# Bytecode comes only from the copied sources: any .pyc that slipped through the build context is deleted first
# (compileall keeps, and Python then runs, a .pyc whose header matches the source's mtime and size).
RUN chmod 0755 /opt/aegis/entrypoint.sh /opt/aegis/healthcheck.py \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/aegis/flow-spool \
 && find /opt/aegis \( -name '*.pyc' -o -name '*.pyo' \) -delete \
 && python3 -m compileall -q /opt/aegis \
 && chmod -R a+rX /opt/aegis \
 && { pip check | grep -vi -e "^mitmproxy .* has requirement brotli" -e "no broken requirements" | (! grep .); } \
 && { pip uninstall -y -q setuptools wheel 2>/dev/null || true; } \
 && python3 -m pip uninstall -y -q pip \
 && rm -rf /usr/local/lib/python3*/ensurepip /root/.cache \
 && python3 -c "import mitmproxy, yara_x, msgpack"
# The runtime image has no package manager for Python (pip/setuptools removed): smaller attack surface.

# Runs as the same non-root UID as the control-plane image so both can share the CA secret volume.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp \
    AEGIS_CA_DIR=/certs AEGIS_CONFDIR=/tmp/mitmproxy AEGIS_LISTEN_PORT=8080 AEGIS_OPS_ADDR=0.0.0.0:9091
USER 65532:65532
EXPOSE 8080 9091
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s CMD ["python3", "/opt/aegis/healthcheck.py", "readyz"]
ENTRYPOINT ["/opt/aegis/entrypoint.sh"]
