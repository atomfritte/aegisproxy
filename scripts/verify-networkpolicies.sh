#!/usr/bin/env bash
# Verifies that the AegisProxy NetworkPolicies are enforced by your CNI: probes every component from a
# throw-away namespace, from an unlabelled pod in the release namespace and from a data-plane worker,
# and compares the result with the intended connectivity matrix. Read-only apart from two probe pods
# and the probe namespace, which are removed at the end.
#
#   scripts/verify-networkpolicies.sh [namespace] [release-fullname]     (defaults: aegis aegis-aegisproxy)
#   KUBECTL=/path/to/kubectl PROBE_IMAGE=busybox:1.36 scripts/verify-networkpolicies.sh
set -uo pipefail
NS=${1:-aegis}
FULL=${2:-aegis-aegisproxy}
K=${KUBECTL:-kubectl}
IMG=${PROBE_IMAGE:-busybox:1.36}
PROBE_NS="aegis-np-probe-$$"
pass=0; fail=0

cleanup() { $K delete ns "$PROBE_NS" --wait=false >/dev/null 2>&1; $K -n "$NS" delete pod "np-probe-$$" --wait=false >/dev/null 2>&1; }
trap cleanup EXIT

$K create ns "$PROBE_NS" >/dev/null
$K -n "$PROBE_NS" run "np-probe-$$" --image="$IMG" --restart=Never --command -- sleep 600 >/dev/null
$K -n "$NS" run "np-probe-$$" --image="$IMG" --restart=Never --command -- sleep 600 >/dev/null
# A pod outside kube-system that carries the cluster DNS label must not become a DNS (port 53) destination.
$K -n "$PROBE_NS" run "np-fake-dns-$$" --image="$IMG" --restart=Never --labels=k8s-app=kube-dns --command -- \
    sh -c 'while true; do nc -l -p 53 >/dev/null 2>&1; done' >/dev/null
$K -n "$PROBE_NS" wait --for=condition=Ready "pod/np-probe-$$" --timeout=180s >/dev/null || { echo "probe pod not ready"; exit 2; }
$K -n "$NS" wait --for=condition=Ready "pod/np-probe-$$" --timeout=180s >/dev/null || { echo "probe pod not ready"; exit 2; }
$K -n "$PROBE_NS" wait --for=condition=Ready "pod/np-fake-dns-$$" --timeout=180s >/dev/null || { echo "probe pod not ready"; exit 2; }
FAKE_DNS=$($K -n "$PROBE_NS" get pod "np-fake-dns-$$" -o jsonpath='{.status.podIP}')

svc() { echo "$FULL-$1.$NS.svc.cluster.local"; }
has_svc() { $K -n "$NS" get svc "$FULL-$1" >/dev/null 2>&1; }
check() { # name expect(open|blocked) command...
    local name=$1 expect=$2 got; shift 2
    if "$@" >/dev/null 2>&1; then got=open; else got=blocked; fi
    if [ "$got" = "$expect" ]; then pass=$((pass + 1)); echo "PASS  $name: $got"
    else fail=$((fail + 1)); echo "FAIL  $name: expected $expect, got $got"; fi
}
nc_from() { $K -n "$1" exec "np-probe-$$" -- nc -z -w 4 "$2" "$3"; }

for src in "$PROBE_NS:other namespace" "$NS:unlabelled pod in $NS"; do
    ns=${src%%:*}; label=${src#*:}
    check "$label -> control-plane API 8081" blocked nc_from "$ns" "$(svc control-plane)" 8081
    if has_svc clamav; then check "$label -> ClamAV 3310" blocked nc_from "$ns" "$(svc clamav)" 3310; fi
    if has_svc pg-rw; then check "$label -> PostgreSQL 5432" blocked nc_from "$ns" "$(svc pg-rw)" 5432; fi
    if has_svc console; then check "$label -> console 8080" blocked nc_from "$ns" "$(svc console)" 8080; fi
    check "$label -> proxy port 8080 (clients)" open nc_from "$ns" "$(svc proxy)" 8080
done
check "other namespace -> data-plane ops 9091" blocked nc_from "$PROBE_NS" "$(svc data-plane-ops)" 9091

DP=$($K -n "$NS" get pods -l app.kubernetes.io/component=data-plane,app.kubernetes.io/instance="${FULL%-aegisproxy}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$DP" ] || DP=$($K -n "$NS" get pods -l app.kubernetes.io/component=data-plane -o jsonpath='{.items[0].metadata.name}')
py() { $K -n "$NS" exec "$DP" -- python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 4)" "$1" "$2"; }
check "data-plane -> control-plane 8081" open py "$(svc control-plane)" 8081
if has_svc clamav; then check "data-plane -> ClamAV 3310" open py "$(svc clamav)" 3310; fi
if has_svc pg-rw; then check "data-plane -> PostgreSQL 5432" blocked py "$(svc pg-rw)" 5432; fi
check "data-plane -> cloud metadata 169.254.169.254:80" blocked py 169.254.169.254 80
check "data-plane -> Azure WireServer 168.63.129.16:80" blocked py 168.63.129.16 80
check "data-plane -> cluster DNS kube-dns.kube-system:53" open py kube-dns.kube-system.svc.cluster.local 53
check "probe namespace -> pod labelled k8s-app=kube-dns :53 (listener up)" open nc_from "$PROBE_NS" "$FAKE_DNS" 53
check "data-plane -> pod labelled k8s-app=kube-dns outside kube-system :53" blocked py "$FAKE_DNS" 53
check "data-plane -> internet example.com:443" open py example.com 443

# ClamAV: DNS and public HTTPS (signature updates) only.
CV=$($K -n "$NS" get pods -l app.kubernetes.io/component=clamav -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$CV" ]; then
    cv_nc() { $K -n "$NS" exec "$CV" -- nc -z -w 4 "$1" "$2"; }
    check "ClamAV -> control-plane 8081" blocked cv_nc "$(svc control-plane)" 8081
    check "ClamAV -> cloud metadata 169.254.169.254:80" blocked cv_nc 169.254.169.254 80
    check "ClamAV -> pod labelled k8s-app=kube-dns outside kube-system :53" blocked cv_nc "$FAKE_DNS" 53
    check "ClamAV -> internet example.com:80" blocked cv_nc example.com 80
    check "ClamAV -> signature mirror database.clamav.net:443" open cv_nc database.clamav.net 443
fi

echo; echo "$pass/$((pass + fail)) checks as intended"
[ "$fail" -eq 0 ]
