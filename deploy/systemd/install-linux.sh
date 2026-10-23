#!/usr/bin/env bash
# AegisProxy - Linux installer (systemd) for the control-plane and/or the data-plane worker.
#
# Supported: Debian 12+/Ubuntu 22.04+ and RHEL/Rocky/AlmaLinux 9+ (systemd >= 248 for LoadCredential/%d).
# Idempotent: a re-run upgrades binary/addon/venv/units and keeps secrets, CA, state and env files.
#
#   sudo deploy/systemd/install-linux.sh --public-url https://aegis.corp.example --ui-dir frontend/dist
#   sudo deploy/systemd/install-linux.sh --component data-plane --control-plane-url https://aegis.corp.example \
#        --dataplane-key-file /root/dataplane.key --ca-file /root/mitmproxy-ca.pem
#
# Layout:
#   /usr/local/bin/aegis-control-plane         control-plane binary
#   /opt/aegis/console/                        built web console (AEGIS_UI_DIR, optional)
#   /opt/aegis/data-plane/{venv,aegis_addon.py,aegis_dp/}
#   /etc/aegis/{control-plane,dataplane}.env   non-secret settings (root:root 0640)
#   /etc/aegis/secrets/                        jwt.key, dataplane.key, ... (root:root 0700/0600, LoadCredential)
#   /etc/aegis/ca/mitmproxy-ca.pem             CA key + cert (root:root 0600) - data-plane only
#   /var/lib/aegis/{data,certs}                control-plane state and public CA certificate
#
# See docs/deployment/linux.md and docs/configuration.md.
set -euo pipefail
umask 022

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
REPO_ROOT=$(readlink -f -- "$SCRIPT_DIR/../..")

MITMPROXY_VERSION=12.3.0
YARA_X_VERSION=1.22.0
MIN_SYSTEMD=248
CP_BIN=/usr/local/bin/aegis-control-plane
CONSOLE_DIR=/opt/aegis/console
DP_DIR=/opt/aegis/data-plane
VENV=$DP_DIR/venv
ETC=/etc/aegis
SECRETS=$ETC/secrets
CA_DIR=$ETC/ca
STATE=/var/lib/aegis
UNIT_DIR=/etc/systemd/system
CP_ENV=$ETC/control-plane.env
DP_ENV=$ETC/dataplane.env

# --- options -----------------------------------------------------------------------------------------
COMPONENT=all
CP_SOURCE_BIN=$REPO_ROOT/control-plane/aegis-control-plane
UI_SRC=""
DP_SRC=$REPO_ROOT/data-plane
PUBLIC_URL=""
CONTROL_PLANE_URL=""
CLAMD_ADDRESS=""
DP_KEY_SRC=""
JWT_SRC=""
ENC_SRC=""
CA_SRC=""
DB_URL_SRC=""
BOOTSTRAP_PW_SRC=""
TLS_CERT_SRC=""
TLS_KEY_SRC=""
GEN_METRICS_TOKEN=0
PYTHON=""
PIP_EXTRA=""
REQUIREMENTS=""
INSTALL_DEPS=0
NO_START=0
FORCE=0

usage() {
    cat <<'EOF'
Usage: install-linux.sh [options]

Components
  --component all|control-plane|data-plane   what to install on this host (default: all)

Control-plane
  --binary PATH                aegis-control-plane (linux/amd64|arm64) (default: control-plane/aegis-control-plane)
  --public-url URL             AEGIS_PUBLIC_URL (required on the first installation)
  --ui-dir PATH                built console (frontend/dist) -> /opt/aegis/console, sets AEGIS_UI_DIR
  --database-url-file PATH     PostgreSQL DSN -> secrets/database-url, sets AEGIS_STORAGE=postgres (cluster)
  --jwt-secret-file PATH       import the JWT secret of cluster node 1
  --encryption-key-file PATH   import the secrets encryption key of cluster node 1
  --bootstrap-admin-password-file PATH   password for the bootstrap super admin "admin"
  --tls-cert PATH --tls-key PATH         native HTTPS (PEM) instead of a TLS reverse proxy
  --generate-metrics-token     protect /metrics with a bearer token (secrets/metrics-token)

Shared
  --dataplane-key-file PATH    import the data-plane key (data-plane-only hosts, cluster nodes 2..n)
  --ca-file PATH               import mitmproxy-ca.pem (CA key + certificate) instead of generating one

Data-plane
  --source-dir PATH            repository data-plane folder (default: data-plane)
  --control-plane-url URL      CONTROL_PLANE_URL (default on all-in-one hosts: http://127.0.0.1:8081)
  --clamd-address ADDR         AEGIS_CLAMD_ADDRESS, e.g. unix:///run/clamav/clamd.ctl or tcp://127.0.0.1:3310
  --python PATH                Python >= 3.12 used to create the venv
  --pip-args "ARGS"            extra pip arguments, e.g. "--no-index --find-links /srv/wheels"
  --requirements FILE          hash-pinned requirements file (pip --require-hashes); add yara-x to it for YARA;
                               it must pin the baseline of data-plane/requirements-security.txt (Brotli>=1.2.1)
  --no-yara                    do not install the YARA-X engine (YARA rule sets then report "unavailable")
  --install-deps               install missing OS packages (python3 venv) with apt/dnf

General
  --no-start                   install and enable, but do not (re)start the services
  --force                      allow replacing an existing, different secret or CA
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --component) COMPONENT=${2:?}; shift 2 ;;
        --binary) CP_SOURCE_BIN=${2:?}; shift 2 ;;
        --public-url) PUBLIC_URL=${2:?}; shift 2 ;;
        --ui-dir) UI_SRC=${2:?}; shift 2 ;;
        --database-url-file) DB_URL_SRC=${2:?}; shift 2 ;;
        --jwt-secret-file) JWT_SRC=${2:?}; shift 2 ;;
        --encryption-key-file) ENC_SRC=${2:?}; shift 2 ;;
        --bootstrap-admin-password-file) BOOTSTRAP_PW_SRC=${2:?}; shift 2 ;;
        --tls-cert) TLS_CERT_SRC=${2:?}; shift 2 ;;
        --tls-key) TLS_KEY_SRC=${2:?}; shift 2 ;;
        --generate-metrics-token) GEN_METRICS_TOKEN=1; shift ;;
        --dataplane-key-file) DP_KEY_SRC=${2:?}; shift 2 ;;
        --ca-file) CA_SRC=${2:?}; shift 2 ;;
        --source-dir) DP_SRC=${2:?}; shift 2 ;;
        --control-plane-url) CONTROL_PLANE_URL=${2:?}; shift 2 ;;
        --clamd-address) CLAMD_ADDRESS=${2:?}; shift 2 ;;
        --python) PYTHON=${2:?}; shift 2 ;;
        --pip-args) PIP_EXTRA=${2:?}; shift 2 ;;
        --requirements) REQUIREMENTS=${2:?}; shift 2 ;;
        --no-yara) NO_YARA=1; shift ;;
        --install-deps) INSTALL_DEPS=1; shift ;;
        --no-start) NO_START=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# --- helpers -----------------------------------------------------------------------------------------
log()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

want_cp() { [ "$COMPONENT" = all ] || [ "$COMPONENT" = control-plane ]; }
want_dp() { [ "$COMPONENT" = all ] || [ "$COMPONENT" = data-plane ]; }

gen_secret() {
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
    else od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; echo; fi
}

secret_len() { tr -d '[:space:]' < "$1" | wc -c; }

# install_secret SRC DST - copies a secret (root:root 0600), refuses to replace a different one without --force.
install_secret() {
    local src=$1 dst=$2
    [ -r "$src" ] || die "Cannot read $src"
    if [ "$(secret_len "$src")" -lt 32 ] && [ "$(basename "$dst")" != database-url ] && [ "$(basename "$dst")" != bootstrap-admin-password ]; then
        die "$src must contain at least 32 characters"
    fi
    if [ -s "$dst" ] && ! cmp -s <(tr -d '[:space:]' < "$src") <(tr -d '[:space:]' < "$dst"); then
        [ "$FORCE" = 1 ] || die "$dst exists with a different value (use --force to replace it)"
        warn "Replacing $dst (--force)"
    fi
    (umask 077; tr -d '\r' < "$src" | sed -e '1s/^\xEF\xBB\xBF//' > "$dst.tmp")
    chown root:root "$dst.tmp"; chmod 0600 "$dst.tmp"; mv -f "$dst.tmp" "$dst"
}

ensure_secret() {
    local dst=$1
    if [ ! -s "$dst" ] || [ "$(secret_len "$dst")" -lt 32 ]; then
        (umask 077; gen_secret > "$dst.tmp")
        chown root:root "$dst.tmp"; chmod 0600 "$dst.tmp"; mv -f "$dst.tmp" "$dst"
        ok "Generated $dst"
    fi
}

# env_set FILE KEY VALUE - sets KEY in a systemd EnvironmentFile (replaces active lines, else the first
# commented template line, else appends). Preserves ownership and permissions of FILE.
env_set() {
    local file=$1 key=$2 value=$3 mode
    case "$value" in *$'\n'*) die "Invalid value for $key" ;; esac
    if grep -q "^${key}=" "$file"; then mode=active
    elif grep -q "^#${key}=" "$file"; then mode=commented
    else printf '%s=%s\n' "$key" "$value" >> "$file"; return; fi
    awk -v k="$key" -v v="$value" -v mode="$mode" '
        mode == "active"    && index($0, k "=") == 1      { print k "=" v; next }
        mode == "commented" && !done && index($0, "#" k "=") == 1 { print k "=" v; done = 1; next }
        { print }' "$file" > "$file.tmp"
    cat "$file.tmp" > "$file"; rm -f "$file.tmp"
}

env_get() { # FILE KEY -> last active value (quotes stripped)
    [ -r "$1" ] || return 0
    sed -n "s/^$2=//p" "$1" | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

ensure_user() { # NAME COMMENT
    local name=$1 nologin
    nologin=$(command -v nologin || echo /usr/sbin/nologin)
    getent group "$name" >/dev/null || groupadd --system "$name"
    if ! getent passwd "$name" >/dev/null; then
        useradd --system --gid "$name" --home-dir /nonexistent --no-create-home --shell "$nologin" --comment "$2" "$name"
        ok "Created system user $name"
    fi
}

ca_fingerprint() { # PEM certificate -> SHA-256 fingerprint AA:BB:...
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$1" | sed '1d;$d' | base64 -d 2>/dev/null \
        | sha256sum | cut -c1-64 | tr 'a-f' 'A-F' | sed -e 's/../&:/g' -e 's/:$//'
}

# publish_ca_public_files - derives the public certificate files from /etc/aegis/ca/mitmproxy-ca.pem.
publish_ca_public_files() {
    local pem=$CA_DIR/mitmproxy-ca-cert.pem
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$CA_DIR/mitmproxy-ca.pem" > "$pem.tmp"
    [ -s "$pem.tmp" ] || die "$CA_DIR/mitmproxy-ca.pem contains no certificate"
    mv -f "$pem.tmp" "$pem"
    cp -f "$pem" "$CA_DIR/aegis-enterprise-ca.crt"
    sed '1d;$d' "$pem" | base64 -d > "$CA_DIR/aegis-enterprise-ca.der"
    chown root:root "$pem" "$CA_DIR/aegis-enterprise-ca.crt" "$CA_DIR/aegis-enterprise-ca.der"
    chmod 0644 "$pem" "$CA_DIR/aegis-enterprise-ca.crt" "$CA_DIR/aegis-enterprise-ca.der"
}

# --- preflight ---------------------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
case "$COMPONENT" in all|control-plane|data-plane) ;; *) die "--component must be all, control-plane or data-plane" ;; esac
command -v systemctl >/dev/null || die "systemd is required."
SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 {print $2}' | sed 's/[^0-9].*//')
[ "${SYSTEMD_VERSION:-0}" -ge "$MIN_SYSTEMD" ] || die "systemd $SYSTEMD_VERSION is too old (>= $MIN_SYSTEMD needed for LoadCredential=/%d). Use the container deployment on this host."

OS_IDS=$( . /etc/os-release 2>/dev/null; echo " ${ID:-} ${ID_LIKE:-} " )
case "$OS_IDS" in
    *" debian "*|*" ubuntu "*) OS_FAMILY=debian ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) OS_FAMILY=rhel ;;
    *) OS_FAMILY=other; warn "Unrecognised distribution ($OS_IDS) - continuing with generic settings." ;;
esac
log "Distribution family: $OS_FAMILY, systemd $SYSTEMD_VERSION, component: $COMPONENT"

for unit in aegis-control-plane.service aegis-dataplane.service aegis.logrotate control-plane.env.example dataplane.env.example; do
    [ -r "$SCRIPT_DIR/$unit" ] || die "Missing $SCRIPT_DIR/$unit"
done

if want_cp; then
    [ -x "$CP_SOURCE_BIN" ] || [ -x "$CP_BIN" ] || die "Control-plane binary not found: $CP_SOURCE_BIN (use --binary)"
    if [ ! -e "$CP_ENV" ] && [ -z "$PUBLIC_URL" ]; then die "--public-url is required on the first installation"; fi
    case "$PUBLIC_URL" in ""|http://*|https://*) ;; *) die "--public-url must be an http(s) URL" ;; esac
    if [ -n "$UI_SRC" ] && [ ! -f "$UI_SRC/index.html" ]; then die "$UI_SRC contains no index.html (npm --prefix frontend run build)"; fi
    if [ -n "$TLS_CERT_SRC$TLS_KEY_SRC" ] && { [ -z "$TLS_CERT_SRC" ] || [ -z "$TLS_KEY_SRC" ]; }; then die "--tls-cert and --tls-key belong together"; fi
fi
if want_dp; then
    [ -f "$DP_SRC/aegis_addon.py" ] && [ -f "$DP_SRC/aegis_dp/addon.py" ] || die "$DP_SRC is not the data-plane folder (use --source-dir)"
    case "$CLAMD_ADDRESS" in ""|unix://*|tcp://*) ;; *) die "--clamd-address must start with unix:// or tcp://" ;; esac
fi

# --- users and directories ---------------------------------------------------------------------------
want_cp && ensure_user aegis "AegisProxy control-plane"
want_dp && ensure_user aegis-dp "AegisProxy data-plane"
install -d -m 0755 -o root -g root "$ETC" /opt/aegis
install -d -m 0700 -o root -g root "$SECRETS"
install -d -m 0755 -o root -g root "$CA_DIR"
install -d -m 0755 -o root -g root "$UNIT_DIR"

# --- secrets -----------------------------------------------------------------------------------------
[ -n "$DP_KEY_SRC" ] && install_secret "$DP_KEY_SRC" "$SECRETS/dataplane.key" && ok "Imported data-plane key"
if want_cp; then
    [ -n "$JWT_SRC" ] && install_secret "$JWT_SRC" "$SECRETS/jwt.key" && ok "Imported JWT secret"
    ensure_secret "$SECRETS/jwt.key"
    [ -n "$ENC_SRC" ] && install_secret "$ENC_SRC" "$SECRETS/encryption.key" && ok "Imported encryption key"
    ensure_secret "$SECRETS/encryption.key"
    ensure_secret "$SECRETS/dataplane.key"
    [ -n "$DB_URL_SRC" ] && install_secret "$DB_URL_SRC" "$SECRETS/database-url" && ok "Stored PostgreSQL DSN"
    [ -n "$BOOTSTRAP_PW_SRC" ] && install_secret "$BOOTSTRAP_PW_SRC" "$SECRETS/bootstrap-admin-password" && ok "Stored bootstrap admin password"
    if [ "$GEN_METRICS_TOKEN" = 1 ]; then ensure_secret "$SECRETS/metrics-token"; fi
    if [ -n "$TLS_CERT_SRC" ]; then
        grep -q -- '-----BEGIN CERTIFICATE-----' "$TLS_CERT_SRC" || die "$TLS_CERT_SRC is not a PEM certificate"
        grep -Eq -- '-----BEGIN (RSA |EC )?PRIVATE KEY-----' "$TLS_KEY_SRC" || die "$TLS_KEY_SRC is not an unencrypted PEM key"
        install -m 0600 -o root -g root "$TLS_CERT_SRC" "$SECRETS/tls.crt"
        install -m 0600 -o root -g root "$TLS_KEY_SRC" "$SECRETS/tls.key"
        ok "Stored TLS certificate and key"
    fi
elif [ ! -s "$SECRETS/dataplane.key" ]; then
    die "--dataplane-key-file is required on data-plane-only hosts (control-plane: /etc/aegis/secrets/dataplane.key)"
fi

# --- control-plane binary ----------------------------------------------------------------------------
if want_cp && [ -x "$CP_SOURCE_BIN" ]; then
    # timeout: outdated builds without the "version" subcommand would start a server instead of exiting.
    NEW_VERSION=$(timeout 15 "$CP_SOURCE_BIN" version) || die "$CP_SOURCE_BIN does not run on this host or is an outdated build without the 'version'/'gen-ca' subcommands"
    install -m 0755 -o root -g root "$CP_SOURCE_BIN" "$CP_BIN.new"
    mv -f "$CP_BIN.new" "$CP_BIN"
    ok "Installed $CP_BIN (version $NEW_VERSION)"
fi

# --- enterprise root CA ------------------------------------------------------------------------------
if [ -n "$CA_SRC" ]; then
    grep -Eq -- '-----BEGIN (RSA |EC )?PRIVATE KEY-----' "$CA_SRC" && grep -q -- '-----BEGIN CERTIFICATE-----' "$CA_SRC" \
        || die "$CA_SRC must contain the CA private key AND certificate (mitmproxy-ca.pem)"
    if [ -s "$CA_DIR/mitmproxy-ca.pem" ] && ! cmp -s "$CA_SRC" "$CA_DIR/mitmproxy-ca.pem"; then
        [ "$FORCE" = 1 ] || die "A different CA exists in $CA_DIR (use --force; every client must then trust the new CA)"
        warn "Replacing the enterprise CA (--force)"
    fi
    install -m 0600 -o root -g root "$CA_SRC" "$CA_DIR/mitmproxy-ca.pem"
    publish_ca_public_files
    ok "Imported CA from $CA_SRC"
elif [ ! -s "$CA_DIR/mitmproxy-ca.pem" ]; then
    if [ -s "$STATE/certs/mitmproxy-ca.pem" ]; then
        # Adopt a CA that an earlier control-plane run generated itself.
        install -m 0600 -o root -g root "$STATE/certs/mitmproxy-ca.pem" "$CA_DIR/mitmproxy-ca.pem"
        publish_ca_public_files
        ok "Adopted the existing CA from $STATE/certs"
    elif want_cp; then
        log "Generating the enterprise root CA (RSA 3072, 10 years)"
        TMP_CA=$(mktemp -d)
        trap 'rm -rf "$TMP_CA"' EXIT
        chmod 0700 "$TMP_CA"
        "$CP_BIN" gen-ca "$TMP_CA" | sed 's/^/    /'
        install -m 0600 -o root -g root "$TMP_CA/mitmproxy-ca.pem" "$CA_DIR/mitmproxy-ca.pem"
        rm -rf "$TMP_CA"
        publish_ca_public_files
    else
        die "--ca-file is required on data-plane-only hosts (control-plane: /etc/aegis/ca/mitmproxy-ca.pem)"
    fi
fi

# --- control-plane -----------------------------------------------------------------------------------
if want_cp; then
    install -d -m 0750 -o aegis -g aegis "$STATE" "$STATE/certs"
    install -d -m 0700 -o aegis -g aegis "$STATE/data"
    for f in mitmproxy-ca-cert.pem aegis-enterprise-ca.crt aegis-enterprise-ca.der; do
        install -m 0644 -o root -g root "$CA_DIR/$f" "$STATE/certs/$f"
    done
    if [ -e "$STATE/certs/mitmproxy-ca.pem" ]; then
        # The control-plane never needs the CA private key.
        if cmp -s "$STATE/certs/mitmproxy-ca.pem" "$CA_DIR/mitmproxy-ca.pem"; then rm -f "$STATE/certs/mitmproxy-ca.pem"
        else warn "$STATE/certs/mitmproxy-ca.pem differs from $CA_DIR/mitmproxy-ca.pem - review and remove it manually"; fi
    fi

    if [ -n "$UI_SRC" ]; then
        rm -rf "$CONSOLE_DIR.new" "$CONSOLE_DIR.old"
        mkdir -p "$CONSOLE_DIR.new"
        cp -R "$UI_SRC/." "$CONSOLE_DIR.new/"
        chown -R root:root "$CONSOLE_DIR.new"; chmod -R u=rwX,go=rX "$CONSOLE_DIR.new"
        [ -d "$CONSOLE_DIR" ] && mv "$CONSOLE_DIR" "$CONSOLE_DIR.old"
        mv "$CONSOLE_DIR.new" "$CONSOLE_DIR"; rm -rf "$CONSOLE_DIR.old"
        ok "Web console installed in $CONSOLE_DIR"
    fi

    if [ ! -e "$CP_ENV" ]; then
        install -m 0640 -o root -g root "$SCRIPT_DIR/control-plane.env.example" "$CP_ENV"
        ok "Created $CP_ENV (review it!)"
    fi
    [ -n "$PUBLIC_URL" ] && env_set "$CP_ENV" AEGIS_PUBLIC_URL "${PUBLIC_URL%/}"
    [ -d "$CONSOLE_DIR" ] && [ -f "$CONSOLE_DIR/index.html" ] && env_set "$CP_ENV" AEGIS_UI_DIR "$CONSOLE_DIR"
    [ -n "$DB_URL_SRC" ] && env_set "$CP_ENV" AEGIS_STORAGE postgres
    if [ "$(env_get "$CP_ENV" AEGIS_STORAGE)" = postgres ] && [ ! -s "$SECRETS/database-url" ]; then
        die "AEGIS_STORAGE=postgres but $SECRETS/database-url is missing (--database-url-file)"
    fi

    install -m 0644 -o root -g root "$SCRIPT_DIR/aegis-control-plane.service" "$UNIT_DIR/aegis-control-plane.service"
    DROPIN=$UNIT_DIR/aegis-control-plane.service.d
    install -d -m 0755 "$DROPIN"
    {
        echo "# Generated by install-linux.sh - optional credentials found in $SECRETS. Re-run the script after changes."
        echo "[Service]"
        for pair in database-url:AEGIS_DATABASE_URL_FILE bootstrap-admin-password:AEGIS_BOOTSTRAP_ADMIN_PASSWORD_FILE \
                    metrics-token:AEGIS_METRICS_TOKEN_FILE tls.crt:AEGIS_TLS_CERT_FILE tls.key:AEGIS_TLS_KEY_FILE; do
            name=${pair%%:*}; var=${pair#*:}
            if [ -s "$SECRETS/$name" ]; then
                echo "LoadCredential=$name:$SECRETS/$name"
                echo "Environment=$var=%d/$name"
            fi
        done
    } > "$DROPIN/10-credentials.conf"
    chmod 0644 "$DROPIN/10-credentials.conf"
    ok "Installed aegis-control-plane.service (+ $DROPIN/10-credentials.conf)"
fi

# --- data-plane --------------------------------------------------------------------------------------
if want_dp; then
    find_python() {
        local c
        for c in "$PYTHON" python3.12 python3.13 python3.14 python3; do
            [ -n "$c" ] || continue
            command -v "$c" >/dev/null 2>&1 || continue
            if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
                command -v "$c"; return 0
            fi
        done
        return 1
    }
    PY=$(find_python) || PY=""
    if [ -z "$PY" ] || ! "$PY" -c 'import ensurepip, venv' 2>/dev/null; then
        if [ "$INSTALL_DEPS" = 1 ]; then
            case "$OS_FAMILY" in
                debian) apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv ;;
                rhel)   dnf install -y -q python3.12 ;;
                *)      die "Install Python >= 3.12 with venv support manually." ;;
            esac
            PY=$(find_python) || die "No Python >= 3.12 available from the distribution (Debian 12 ships 3.11: use Debian 13 / Ubuntu 24.04, a vendor Python build, or --python)."
        else
            die "Python >= 3.12 with venv support not found. Debian/Ubuntu: apt install python3 python3-venv (Ubuntu 24.04+/Debian 13+). RHEL/Rocky 9: dnf install python3.12. Or use --install-deps / --python."
        fi
    fi
    log "Python: $PY ($("$PY" -c 'import platform; print(platform.python_version())'))"

    install -d -m 0755 -o root -g root "$DP_DIR"
    if [ -x "$VENV/bin/python" ]; then
        if [ "$("$VENV/bin/python" -c 'import sys; print(sys.version_info[:2])')" != "$("$PY" -c 'import sys; print(sys.version_info[:2])')" ]; then
            warn "Recreating $VENV for $PY (Python version changed)"; rm -rf "$VENV"
        fi
    fi
    [ -x "$VENV/bin/python" ] || { log "Creating virtualenv $VENV"; "$PY" -m venv "$VENV"; }
    [ -n "$REQUIREMENTS" ] || warn "Supply chain: prefer an offline, hash-pinned install from a vetted mirror (--requirements <lock from uv pip compile --generate-hashes --override requirements-security.txt> --pip-args \"--no-index --find-links DIR\")."
    PIP_ARGS=(install --disable-pip-version-check --no-input --require-virtualenv)
    if [ -n "$REQUIREMENTS" ]; then
        # A complete lock file pins every dependency; --no-deps lets it raise packages above mitmproxy's upper
        # bounds (security baseline). Completeness is checked with "pip check" below.
        PIP_ARGS+=(--require-hashes --no-deps -r "$REQUIREMENTS")
    else
        PIP_ARGS+=("mitmproxy==$MITMPROXY_VERSION")
        # YARA-X ships binary wheels (no Rust toolchain needed); never fall back to a source build.
        [ -n "${NO_YARA:-}" ] || PIP_ARGS+=("yara-x==$YARA_X_VERSION" --only-binary yara-x)
    fi
    if [ -n "$PIP_EXTRA" ]; then read -r -a EXTRA <<< "$PIP_EXTRA"; PIP_ARGS+=("${EXTRA[@]}"); fi
    "$VENV/bin/python" -m pip "${PIP_ARGS[@]}"
    # Security overrides for mitmproxy dependencies (mitmproxy's upper bound excludes the fixed release).
    if [ -f "$DP_SRC/requirements-security.txt" ] && [ -z "$REQUIREMENTS" ]; then
        SEC_ARGS=(install --disable-pip-version-check --no-input --require-virtualenv --no-deps --only-binary=:all: -r "$DP_SRC/requirements-security.txt")
        if [ -n "$PIP_EXTRA" ]; then SEC_ARGS+=("${EXTRA[@]}"); fi
        "$VENV/bin/python" -m pip "${SEC_ARGS[@]}" || warn "Could not install the security overrides from requirements-security.txt (offline mirror?)"
    elif [ -f "$DP_SRC/requirements-security.txt" ]; then
        # Hash-pinned mode: an unhashed install on top would bypass --require-hashes, so only verify the pins.
        "$VENV/bin/python" - "$DP_SRC/requirements-security.txt" "$REQUIREMENTS" <<'PY' || die "The hash-pinned requirements do not meet the security baseline (see above)"
import importlib.metadata as m, re, sys
low = []
for line in open(sys.argv[1], encoding="utf-8"):
    hit = re.match(r"\s*([A-Za-z0-9._-]+)==([0-9]+(?:\.[0-9]+)+)", line)
    if not hit:
        continue
    name, minimum = hit.group(1), tuple(int(x) for x in hit.group(2).split("."))
    try:
        have = tuple(int(x) for x in re.findall(r"\d+", m.version(name))[:len(minimum)])
    except m.PackageNotFoundError:
        continue
    if have < minimum:
        low.append(f"{name} {m.version(name)} < {hit.group(2)}")
for item in low:
    print(f"{sys.argv[2]} installs {item} (security baseline in requirements-security.txt); pin it with its hash", file=sys.stderr)
sys.exit(1 if low else 0)
PY
        # Every dependency must be in the lock file; the only tolerated conflicts are the baseline overrides.
        "$VENV/bin/python" - "$DP_SRC/requirements-security.txt" <<'PY' || die "The hash-pinned requirements file is incomplete or inconsistent (see above)"
import re, subprocess, sys
overrides = set()
for line in open(sys.argv[1], encoding="utf-8"):
    hit = re.match(r"\s*([A-Za-z0-9._-]+)==", line)
    if hit:
        overrides.add(hit.group(1).lower().replace("_", "-"))
out = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True).stdout
bad = []
for line in out.splitlines():
    if not line.strip() or line.startswith("No broken"):
        continue
    hit = re.search(r"but you have (\S+) ", line)
    if hit and hit.group(1).lower().replace("_", "-") in overrides:
        continue
    bad.append(line)
for line in bad:
    print(line, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
    fi
    INSTALLED=$("$VENV/bin/python" -c 'import mitmproxy.version as v; print(v.VERSION)')
    [ "$INSTALLED" = "$MITMPROXY_VERSION" ] || warn "Installed mitmproxy $INSTALLED (expected $MITMPROXY_VERSION)"

    rm -rf "$DP_DIR/aegis_dp.new"
    mkdir -p "$DP_DIR/aegis_dp.new"
    cp -R "$DP_SRC/aegis_dp/." "$DP_DIR/aegis_dp.new/"
    find "$DP_DIR/aegis_dp.new" -depth \( -name __pycache__ -o -name tests \) -type d -exec rm -rf {} +
    install -m 0644 -o root -g root "$DP_SRC/aegis_addon.py" "$DP_DIR/aegis_addon.py"
    rm -rf "$DP_DIR/aegis_dp"; mv "$DP_DIR/aegis_dp.new" "$DP_DIR/aegis_dp"
    chown -R root:root "$DP_DIR/aegis_dp"; chmod -R u=rwX,go=rX "$DP_DIR/aegis_dp"
    "$VENV/bin/python" -m compileall -q "$DP_DIR/aegis_addon.py" "$DP_DIR/aegis_dp" >/dev/null
    "$VENV/bin/python" -c 'import sys; sys.path.insert(0, sys.argv[1]); import aegis_dp.addon' "$DP_DIR" \
        || die "Addon import check failed"
    if "$VENV/bin/python" -c 'import yara_x' 2>/dev/null; then
        ok "YARA-X $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("yara-x"))') available for YARA rule sets"
    else
        warn "YARA-X is not installed: YARA rule sets report \"unavailable\" on this worker (add yara-x to --requirements or omit --no-yara)"
    fi
    ok "mitmproxy $INSTALLED + AegisProxy addon installed in $DP_DIR"

    if [ ! -e "$DP_ENV" ]; then
        install -m 0640 -o root -g root "$SCRIPT_DIR/dataplane.env.example" "$DP_ENV"
        if [ -z "$CONTROL_PLANE_URL" ] && want_cp; then CONTROL_PLANE_URL=http://127.0.0.1:8081; fi
        if [ -z "$CLAMD_ADDRESS" ] && [ "$OS_FAMILY" = rhel ]; then CLAMD_ADDRESS=tcp://127.0.0.1:3310; fi
        ok "Created $DP_ENV (review it!)"
    fi
    [ -n "$CONTROL_PLANE_URL" ] && env_set "$DP_ENV" CONTROL_PLANE_URL "${CONTROL_PLANE_URL%/}"
    [ -n "$CLAMD_ADDRESS" ] && env_set "$DP_ENV" AEGIS_CLAMD_ADDRESS "$CLAMD_ADDRESS"
    [ -s "$CA_DIR/mitmproxy-ca.pem" ] || die "$CA_DIR/mitmproxy-ca.pem is missing (--ca-file)"

    install -m 0644 -o root -g root "$SCRIPT_DIR/aegis-dataplane.service" "$UNIT_DIR/aegis-dataplane.service"
    ok "Installed aegis-dataplane.service"
fi

# --- logrotate, SELinux ------------------------------------------------------------------------------
if want_cp && [ -d /etc/logrotate.d ]; then
    install -m 0644 -o root -g root "$SCRIPT_DIR/aegis.logrotate" /etc/logrotate.d/aegis
fi

SELINUX=off
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != Disabled ]; then
    SELINUX=on
    if want_dp; then
        # systemd may only execute files labelled bin_t; files below /opt default to usr_t.
        if command -v semanage >/dev/null 2>&1; then
            semanage fcontext -a -t bin_t "$VENV/bin(/.*)?" 2>/dev/null || semanage fcontext -m -t bin_t "$VENV/bin(/.*)?"
        else
            warn "semanage not found (dnf install policycoreutils-python-utils) - labelling $VENV/bin with chcon (not persistent)"
            chcon -R -t bin_t "$VENV/bin"
        fi
    fi
    restorecon -RF /opt/aegis "$ETC" 2>/dev/null || true
    [ -e "$CP_BIN" ] && restorecon -F "$CP_BIN" 2>/dev/null || true
fi

# --- enable / start ----------------------------------------------------------------------------------
systemctl daemon-reload
UNITS=()
want_cp && UNITS+=(aegis-control-plane.service)
want_dp && UNITS+=(aegis-dataplane.service)
systemctl enable "${UNITS[@]}" >/dev/null
ok "Enabled: ${UNITS[*]}"

CP_OK=skipped
DP_OK=skipped
if [ "$NO_START" = 0 ]; then
    if want_cp; then
        systemctl restart aegis-control-plane.service
        port=$(env_get "$CP_ENV" AEGIS_LISTEN_ADDR); port=${port##*:}
        [ -n "$port" ] || port=$(env_get "$CP_ENV" CONTROL_PLANE_PORT)
        [ -n "$port" ] || port=8081
        tls=""; [ -s "$SECRETS/tls.crt" ] && tls=1
        CP_OK=no
        for _ in $(seq 1 30); do
            sleep 2
            if CONTROL_PLANE_PORT=$port AEGIS_TLS_CERT_FILE=$tls "$CP_BIN" healthcheck; then CP_OK=yes; break; fi
            systemctl is-failed --quiet aegis-control-plane.service && break
        done
        if [ "$CP_OK" = yes ]; then ok "Control-plane healthy (127.0.0.1:$port/healthz)"
        else warn "Control-plane not healthy - journalctl -u aegis-control-plane -n 50"; journalctl -u aegis-control-plane -n 20 --no-pager || true; fi
    fi
    if want_dp; then
        systemctl restart aegis-dataplane.service
        ops=$(env_get "$DP_ENV" AEGIS_OPS_ADDR); ops=${ops:-127.0.0.1:9091}; ops=${ops/0.0.0.0/127.0.0.1}
        DP_OK=no
        for _ in $(seq 1 60); do
            sleep 2
            if "$VENV/bin/python" - "http://$ops/readyz" <<'PY' 2>/dev/null
import sys, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # ignore http_proxy for loopback
sys.exit(0 if opener.open(sys.argv[1], timeout=3).status == 200 else 1)
PY
            then DP_OK=yes; break; fi
            systemctl is-failed --quiet aegis-dataplane.service && break
        done
        if [ "$DP_OK" = yes ]; then ok "Data-plane ready (http://$ops/readyz - policy bundle loaded)"
        else warn "Data-plane not ready - journalctl -u aegis-dataplane -n 50 (key mismatch -> 401 in the control-plane log)"; journalctl -u aegis-dataplane -n 20 --no-pager || true; fi
    fi
fi

# --- summary and hints -------------------------------------------------------------------------------
echo
echo "==================== AegisProxy ===================="
if [ -s "$CA_DIR/mitmproxy-ca-cert.pem" ]; then
    echo "Root CA SHA-256    : $(ca_fingerprint "$CA_DIR/mitmproxy-ca-cert.pem")"
fi
echo "CA key (data-plane): $CA_DIR/mitmproxy-ca.pem (root 0600 - copy securely to data-plane hosts)"
echo "Data-plane key     : $SECRETS/dataplane.key (root 0600)"
if want_cp; then
    echo "Control-plane      : $(env_get "$CP_ENV" AEGIS_PUBLIC_URL)  [health: $CP_OK]  config: $CP_ENV"
    if [ -s "$SECRETS/bootstrap-admin-password" ]; then echo "Admin login        : admin / (password from $SECRETS/bootstrap-admin-password)"
    else echo "Admin login        : admin / password in $STATE/data/secrets/initial-admin-password (created on first start)"; fi
    echo "TLS reverse proxy  : deploy/nginx/aegis-console.conf (set AEGIS_TRUSTED_PROXIES and an https AEGIS_PUBLIC_URL)"
fi
if want_dp; then
    echo "Data-plane         : proxy :$(env_get "$DP_ENV" AEGIS_LISTEN_PORT)  [ready: $DP_OK]  config: $DP_ENV"
    echo
    echo "ClamAV (antivirus, AEGIS_CLAMD_ADDRESS=$(env_get "$DP_ENV" AEGIS_CLAMD_ADDRESS)):"
    case "$OS_FAMILY" in
        debian) echo "  apt install clamav-daemon clamav-freshclam      # socket /run/clamav/clamd.ctl (mode 666)"
                echo "  /etc/clamav/clamd.conf: StreamMaxLength >= policy av_max_scan_bytes (default 25M); MaxScanSize/MaxFileSize >= that" ;;
        rhel)   echo "  dnf install epel-release && dnf install clamd clamav-update"
                echo "  /etc/clamd.d/scan.conf: remove 'Example', set 'TCPSocket 3310', 'TCPAddr 127.0.0.1', 'StreamMaxLength 100M'"
                echo "  freshclam && systemctl enable --now clamav-freshclam clamd@scan" ;;
        *)      echo "  install clamd, enable TCPSocket 3310 / TCPAddr 127.0.0.1 and StreamMaxLength, run freshclam" ;;
    esac
    echo "Firewall: allow TCP $(env_get "$DP_ENV" AEGIS_LISTEN_PORT) only from the server subnets, e.g."
    echo "  firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.20.0.0/16\" port port=\"8080\" protocol=\"tcp\" accept' && firewall-cmd --reload"
    echo "  ufw allow from 10.20.0.0/16 to any port 8080 proto tcp"
fi
if [ "$SELINUX" = on ]; then
    echo
    echo "SELinux is enabled:"
    echo "  nginx -> control-plane on 8081:  semanage port -a -t http_port_t -p tcp 8081   (or: setsebool -P httpd_can_network_connect 1)"
    echo "  proxy on a non-default port:     no label needed for the unconfined service; check 'ausearch -m avc -ts recent' on denials"
fi
echo
echo "Clients: <public-url>/api/public/ca/install-linux.sh (CA trust) + http_proxy/https_proxy=http://<user>:<token>@<proxy>:8080"
if [ "$CP_OK" = no ] || [ "$DP_OK" = no ]; then exit 1; fi
