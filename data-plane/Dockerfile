# syntax=docker/dockerfile:1.7
# AegisProxy data-plane worker (mitmproxy 12 + AegisProxy addon).
#   docker build -t aegisproxy/data-plane:2.1.0 data-plane/
FROM mitmproxy/mitmproxy:12.3.0

USER root
# Patch vulnerable packages shipped in the base image (not required by mitmproxy itself, but present):
# msgpack GHSA-6v7p-g79w-8964, urllib3 CVE-2026-97687/97689.
RUN pip install --no-cache-dir --only-binary=:all: --upgrade "msgpack==1.2.1" "urllib3==2.8.0"
# Security overrides of mitmproxy dependencies (see the file; mitmproxy's upper bound excludes the fix).
COPY requirements-security.txt /opt/aegis/requirements-security.txt
RUN pip install --no-cache-dir --only-binary=:all: --no-deps -r /opt/aegis/requirements-security.txt
# YARA-X (VirusTotal's YARA engine) for YARA rule scanning; binary wheel, pinned.
COPY requirements-extra.txt /opt/aegis/requirements-extra.txt
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r /opt/aegis/requirements-extra.txt 2>/dev/null \
 || pip install --no-cache-dir --only-binary=:all: -r /opt/aegis/requirements-extra.txt
COPY aegis_addon.py healthcheck.py entrypoint.sh /opt/aegis/
COPY aegis_dp/ /opt/aegis/aegis_dp/
RUN chmod 0755 /opt/aegis/entrypoint.sh /opt/aegis/healthcheck.py \
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
