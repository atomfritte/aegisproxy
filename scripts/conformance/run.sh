#!/bin/sh
# Conformance of the log export and Microsoft integrations against independent, license-free reference
# implementations - no Splunk license and no Microsoft tenant needed (see README.md).
#   scripts/conformance/run.sh <work-dir>
set -eu
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mkdir -p "$1" && CDPATH='' cd -- "$1" && pwd)
OTELCOL=otel/opentelemetry-collector-contrib:0.162.0
VECTOR=timberio/vector:0.59.0-debian
SPEC_COMMIT=625f626f1c52a5c80be8462b7272a86894ec2785
SPEC_SHA256=e1f8e314d713683aa38aa299f254c5bb3da29ce7bdc34d5a67daa63d4c9dd658
SDKS="azure-identity==1.26.0 azure-monitor-ingestion==1.1.0 azure-core==1.41.0 msal==1.39.0"

cp -R "$REPO/scripts/conformance/." "$WORK/"
mkdir -p "$WORK/bin" "$WORK/tls" "$WORK/hec/out" "$WORK/hec/vout" "$WORK/logs" "$WORK/spec"
chmod 0777 "$WORK/hec/out" "$WORK/hec/vout"
# Outputs of an earlier run may belong to another user; the receivers must create their files themselves.
rm -f "$WORK/hec/out/hec.jsonl" "$WORK/hec/vout/hec_ack.jsonl"
go -C "$REPO/control-plane" build -o "$WORK/bin/aegis-cp" .

# Test PKI (CA with key usage: Python 3.13+ verifies strictly).
T=$WORK/tls
openssl ecparam -name prime256v1 -genkey -noout -out "$T/ca.key" 2>/dev/null
openssl req -x509 -new -key "$T/ca.key" -days 7 -subj "/CN=AegisProxy Conformance CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$T/ca.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$T/server.key" 2>/dev/null
openssl req -new -key "$T/server.key" -subj "/CN=localhost" -out "$T/server.csr"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$T/ext.cnf"
openssl x509 -req -in "$T/server.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 7 -extfile "$T/ext.cnf" -out "$T/server.pem" 2>/dev/null
chmod 0644 "$T/server.key"

# shellcheck disable=SC2329 # invoked by trap
cleanup() {
  docker rm -f conf-otelcol conf-vector >/dev/null 2>&1 || true
  [ -n "${CAPTURE_PID:-}" ] && kill "$CAPTURE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
docker rm -f conf-otelcol conf-vector >/dev/null 2>&1 || true
docker run -d --name conf-otelcol -p 127.0.0.1:18089:8088 -p 127.0.0.1:18133:13133 -v "$T:/tls:ro" -v "$WORK/hec/out:/out" \
  -v "$WORK/hec/otelcol.yaml:/etc/otelcol-contrib/config.yaml:ro" "$OTELCOL" --config /etc/otelcol-contrib/config.yaml >/dev/null
docker run -d --name conf-vector -p 127.0.0.1:18090:8088 -v "$WORK/hec/vector.yaml:/etc/vector/vector.yaml:ro" \
  -v "$WORK/hec/vout:/out" "$VECTOR" >/dev/null
# wait_for <what> <container or ""> <curl args...>: fails after 120 s instead of waiting forever.
wait_for() {
  what=$1 ctr=$2; shift 2
  i=0
  until curl "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "$what did not become ready" >&2
      [ -n "$ctr" ] && docker logs --tail 5 "$ctr" >&2
      exit 1
    fi
    sleep 1
  done
}
wait_for "OpenTelemetry Collector" conf-otelcol -sf http://127.0.0.1:18133/
sleep 2
rc=0
echo "== Splunk HEC (OpenTelemetry Collector contrib splunk_hec receiver, Vector with indexer acknowledgement)"
python3 -I "$WORK/hec/hec_e2e.py" "$WORK/bin/aegis-cp" || rc=1

echo "== Sentinel: official Azure SDKs against the capture server"
: > "$WORK/capture/sdk.jsonl"
python3 -I "$WORK/capture/capture.py" "$WORK/capture/sdk.jsonl" "$T" > "$WORK/logs/capture.log" 2>&1 &
CAPTURE_PID=$!
wait_for "capture server" "" -s --cacert "$T/ca.pem" https://localhost:18443/
# shellcheck disable=SC2086
docker run --rm --network host -u "$(id -u):$(id -g)" -e HOME=/tmp -e REQUESTS_CA_BUNDLE=/tls/ca.pem -e SSL_CERT_FILE=/tls/ca.pem \
  -e AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:18080 -v "$T:/tls:ro" -v "$WORK/sdk:/sdk:ro" python:3.14-slim \
  sh -c "pip install --quiet --user $SDKS >/dev/null 2>&1 && python /sdk/sdk_flows.py"
curl -fsSL -o "$WORK/spec/DataCollectionRules.json" \
  "https://raw.githubusercontent.com/Azure/azure-rest-api-specs/$SPEC_COMMIT/specification/monitor/data-plane/Ingestion/stable/2023-01-01/DataCollectionRules.json"
echo "$SPEC_SHA256  $WORK/spec/DataCollectionRules.json" | sha256sum -c -
echo "== Sentinel: AegisProxy compared with the SDKs and the official API definition"
python3 -I "$WORK/sentinel_e2e.py" "$WORK/bin/aegis-cp" "$WORK/capture/sdk.jsonl" "$WORK/spec/DataCollectionRules.json" || rc=1

echo "== Public Entra ID, Defender for Endpoint and Datadog endpoints (no credentials)"
go -C "$REPO/control-plane" test -tags live -count=1 -run Live ./internal/oidc ./internal/defender ./internal/export || rc=1
exit $rc
