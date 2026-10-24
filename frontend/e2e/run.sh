#!/usr/bin/env bash
# Console regression suite (Playwright, headless Chromium). Starts fresh control planes on free loopback ports with
# temporary data directories, each serving the given console build, plus the mock OpenID Connect provider, runs
# every suite against them and stops everything again. Builds nothing.
#
#   frontend/e2e/run.sh <control-plane binary> <console dist directory>
#
# Environment:
#   PYTHON            interpreter with frontend/e2e/requirements.txt installed (default: python3)
#   AEGIS_E2E_CHROME  browser executable (default: Playwright's Chromium, `python -m playwright install chromium`)
#   AEGIS_E2E_OUT     directory for control-plane logs, suite output and screenshots (default: a new temp directory)
#   AEGIS_E2E_SUITES  space-separated subset of: fleet_requests identity_protection azure_integrations
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <control-plane binary> <console dist directory>" >&2
  exit 2
fi
BIN=$(readlink -f "$1")
DIST=$(readlink -f "$2")
HERE=$(dirname "$(readlink -f "$0")")
PYTHON=${PYTHON:-python3}
[ -x "$BIN" ] || { echo "control-plane binary not executable: $BIN" >&2; exit 2; }
[ -f "$DIST/index.html" ] || { echo "no console build in $DIST (npm --prefix frontend run build)" >&2; exit 2; }
OUT=${AEGIS_E2E_OUT:-$(mktemp -d -t aegis-e2e-out.XXXXXX)}
mkdir -p "$OUT"
OUT=$(readlink -f "$OUT")
WORK=$(mktemp -d -t aegis-e2e.XXXXXX)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

free_port() { "$PYTHON" -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
secret() { "$PYTHON" -I -c 'import secrets; print(secrets.token_hex(24))'; }

wait_http() { # url name log
  for _ in $(seq 1 150); do
    if "$PYTHON" -I -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=1)' "$1" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  echo "$2 did not become ready at $1" >&2
  tail -n 40 "$3" >&2 || true
  exit 1
}

DP_KEY=$(secret)

start_cp() { # name port [VAR=value ...]
  local name=$1 port=$2
  shift 2
  mkdir -p "$WORK/$name"
  env CONTROL_PLANE_PORT="$port" DATA_DIR="$WORK/$name/data" CERTS_DIR="$WORK/$name/certs" AEGIS_PUBLIC_URL="http://127.0.0.1:$port" \
    AEGIS_UI_DIR="$DIST" AEGIS_JWT_SECRET="$(secret)" AEGIS_DATAPLANE_KEY="$DP_KEY" AEGIS_PROXY_ADDRESS=proxy.corp.example:8080 \
    AEGIS_LOG_FORMAT=text AEGIS_THREATINTEL_AUTOUPDATE=false "$@" "$BIN" > "$OUT/$name-control-plane.log" 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:$port/readyz" "control plane ($name)" "$OUT/$name-control-plane.log"
}

SUITES=${AEGIS_E2E_SUITES:-fleet_requests identity_protection azure_integrations}
FAILED=()
for suite in $SUITES; do
  port=$(free_port)
  extra=()
  case $suite in
    fleet_requests)
      start_cp "$suite" "$port" AEGIS_DEMO_MODE=true ;;
    identity_protection)
      idp_port=$(free_port)
      "$PYTHON" -I "$HERE/mock_idp.py" "$idp_port" > "$OUT/mock-idp.log" 2>&1 &
      PIDS+=("$!")
      wait_http "http://127.0.0.1:$idp_port/.well-known/openid-configuration" "mock IdP" "$OUT/mock-idp.log"
      extra=(AEGIS_E2E_IDP="http://127.0.0.1:$idp_port")
      start_cp "$suite" "$port" AEGIS_DEMO_MODE=true ;;
    azure_integrations)
      admin_pw="E2e-$(secret)"
      extra=(AEGIS_E2E_ADMIN_PASSWORD="$admin_pw")
      start_cp "$suite" "$port" AEGIS_BOOTSTRAP_ADMIN_PASSWORD="$admin_pw" ;;
    *)
      echo "unknown suite: $suite" >&2
      exit 2 ;;
  esac
  echo "=== $suite (control plane :$port)"
  mkdir -p "$OUT/$suite"
  # Not isolated (-I): the suites import common.py from their own directory.
  if ! env AEGIS_E2E_BASE="http://127.0.0.1:$port" AEGIS_E2E_OUT="$OUT/$suite" AEGIS_E2E_DATAPLANE_KEY="$DP_KEY" "${extra[@]}" \
      timeout 1200 "$PYTHON" "$HERE/$suite.py" 2>&1 | tee "$OUT/$suite.txt"; then
    FAILED+=("$suite")
  fi
done

echo
echo "Output: $OUT"
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "FAILED suites: ${FAILED[*]}"
  exit 1
fi
echo "All console suites passed: $SUITES"
