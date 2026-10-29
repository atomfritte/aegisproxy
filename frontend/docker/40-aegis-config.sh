#!/bin/sh
# Generates the runtime console configuration and the optional /api reverse proxy before nginx starts.
set -eu
OUT=/tmp/aegis
mkdir -p "$OUT"

API_BASE="${AEGIS_API_BASE_URL:-}"
case "$API_BASE" in
    ""|https://*|http://*) ;;
    *) echo "AEGIS_API_BASE_URL must be empty or an http(s) URL" >&2; exit 1 ;;
esac
# Values are restricted to URL characters, so they can be embedded into JS/headers verbatim.
if printf '%s' "$API_BASE${AEGIS_API_UPSTREAM:-}" | grep -q '[^A-Za-z0-9:/._%-]'; then
    echo "AEGIS_API_BASE_URL / AEGIS_API_UPSTREAM contain invalid characters" >&2; exit 1
fi
printf 'window.__AEGIS_CONFIG__ = { apiBaseUrl: "%s" };\n' "$API_BASE" > "$OUT/config.js"

CONNECT_SRC="'self'"
if [ -n "$API_BASE" ]; then CONNECT_SRC="'self' $API_BASE"; fi
cat > "$OUT/headers.conf" <<HDR
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src $CONNECT_SRC; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
HDR

# Optional AEGIS_TRUSTED_PROXY_SECRET(_FILE): sent to the control-plane in X-Aegis-Proxy-Auth, so that only this
# proxy (not every container that shares its address) can supply X-Forwarded-For. X-Forwarded-For is appended to,
# not replaced: the console usually sits behind an ingress or load balancer whose entry the control-plane needs.
# The address appended here is the console's own peer: that ingress or load balancer (a trusted hop) or a client
# (where the control-plane's walk stops), so entries a client writes itself are never used. Same characters as the
# control-plane accepts, so it can be embedded into the nginx configuration verbatim.
PROXY_AUTH=""
SECRET="${AEGIS_TRUSTED_PROXY_SECRET:-}"
if [ -n "${AEGIS_TRUSTED_PROXY_SECRET_FILE:-}" ]; then SECRET=$(tr -d '\r\n' < "$AEGIS_TRUSTED_PROXY_SECRET_FILE"); fi
if [ -n "$SECRET" ]; then
    if [ "${#SECRET}" -lt 32 ] || printf '%s' "$SECRET" | grep -q '[^A-Za-z0-9._~+/=-]'; then
        echo "AEGIS_TRUSTED_PROXY_SECRET must be at least 32 characters of letters, digits and -._~+/=" >&2; exit 1
    fi
    PROXY_AUTH="proxy_set_header X-Aegis-Proxy-Auth \"$SECRET\";"
fi

if [ -n "${AEGIS_API_UPSTREAM:-}" ]; then
    umask 077
    cat > "$OUT/api-proxy.conf" <<API
location /api/flows/stream {
    proxy_pass ${AEGIS_API_UPSTREAM};
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    $PROXY_AUTH
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1h;
}
location /api/ {
    proxy_pass ${AEGIS_API_UPSTREAM};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    $PROXY_AUTH
    proxy_read_timeout 60s;
    client_max_body_size 16m;
}
API
else
    : > "$OUT/api-proxy.conf"
fi
