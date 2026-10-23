#!/bin/sh
# AegisProxy data-plane entrypoint: stage the enterprise CA into a private, writable mitmproxy
# confdir (the CA volume/secret stays read-only) and start mitmdump with hardened defaults.
set -eu

CA_DIR="${AEGIS_CA_DIR:-/certs}"
CONFDIR="${AEGIS_CONFDIR:-/tmp/mitmproxy}"

if [ ! -r "$CA_DIR/mitmproxy-ca.pem" ]; then
    echo "FATAL: $CA_DIR/mitmproxy-ca.pem (CA key + certificate) not found or not readable." >&2
    echo "       Provision it with: aegis-control-plane gen-ca <dir>  (see docs/operations.md)" >&2
    exit 1
fi

umask 077
mkdir -p "$CONFDIR"
# The confdir may survive container restarts (emptyDir/tmpfs): replace stale copies, which can be
# read-only because cp inherits the secret's file mode.
rm -f "$CONFDIR/mitmproxy-ca.pem" "$CONFDIR/mitmproxy-ca-cert.pem"
cp "$CA_DIR/mitmproxy-ca.pem" "$CONFDIR/mitmproxy-ca.pem"
chmod 600 "$CONFDIR/mitmproxy-ca.pem"
if [ -r "$CA_DIR/mitmproxy-ca-cert.pem" ]; then
    cp "$CA_DIR/mitmproxy-ca-cert.pem" "$CONFDIR/mitmproxy-ca-cert.pem"
    chmod 644 "$CONFDIR/mitmproxy-ca-cert.pem"
fi

exec mitmdump \
    -s /opt/aegis/aegis_addon.py \
    --set confdir="$CONFDIR" \
    --listen-host "${AEGIS_LISTEN_HOST:-0.0.0.0}" \
    --listen-port "${AEGIS_LISTEN_PORT:-8080}" \
    --set connection_strategy=lazy \
    --set rawtcp=false \
    --set onboarding=false \
    --set block_global=false \
    --set ssl_insecure=false \
    --set tls_version_server_min=TLS1_2 \
    --set body_size_limit="${AEGIS_BODY_SIZE_LIMIT:-1g}" \
    --set termlog_verbosity="${AEGIS_MITM_LOG_LEVEL:-info}" \
    "$@"
