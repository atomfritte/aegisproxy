# Kubernetes (Helm)

Chart: `deploy/helm/aegisproxy` (Kubernetes ≥ 1.27).

| Resource | Purpose |
|---|---|
| Deployment `control-plane` | N replicas (PostgreSQL) or 1 replica + PVC (file storage); probes `/healthz`, `/readyz`; topology spread; PDB; 10 s drain on termination |
| Deployment `data-plane` | mitmproxy workers; probes on the ops port 9091; optional HPA; PDB |
| Service `proxy` | `LoadBalancer`/`NodePort` with `externalTrafficPolicy: Local` (client IP preserved) and `sessionAffinity: ClientIP` |
| StatefulSet `clamav` | clamd replicas with their own signature volumes |
| Deployment `console` (optional) | separately hosted nginx console, proxies `/api/` to the control-plane |
| Cluster (optional) | CloudNativePG PostgreSQL cluster with synchronous replication |
| Ingress (optional) | console/API (+ separate console host) |
| NetworkPolicies | control-plane, data-plane (no egress into private IPv4/IPv6 ranges), ClamAV (egress: DNS and public HTTPS only), console |
| ServiceMonitors (optional) | Prometheus Operator scraping |

All AegisProxy pods run with `runAsNonRoot`, read-only root filesystem, `drop: [ALL]`, `RuntimeDefault`
seccomp and no service-account token (compatible with the *restricted* Pod Security Standard). ClamAV runs
the same way as the image's `clamav` user (UID 100): the chart replaces the image's root-only `/init` with an
equivalent start script (initial signature download, freshclam daemon, clamd).

## Quick start (with CloudNativePG)

```bash
# 1. operator for the HA database (once per cluster)
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.30/releases/cnpg-1.30.1.yaml

# 2. root CA (recommended: created outside Helm)
aegis-control-plane gen-ca ./ca
kubectl create namespace aegis
kubectl -n aegis create secret generic aegis-ca \
  --from-file=./ca/mitmproxy-ca.pem --from-file=./ca/mitmproxy-ca-cert.pem

# 3. install
helm upgrade --install aegis deploy/helm/aegisproxy -n aegis \
  --set publicUrl=https://aegis.corp.example \
  --set ca.existingSecret=aegis-ca \
  --set storage.postgres.cnpg.enabled=true \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.host=aegis.corp.example --set ingress.tlsSecretName=aegis-tls

# 4. bootstrap admin password
kubectl -n aegis get secret aegis-aegisproxy-secrets -o jsonpath='{.data.bootstrap-admin-password}' | base64 -d
```

## External PostgreSQL

```bash
kubectl -n aegis create secret generic aegis-db \
  --from-literal=database-url='postgres://aegis:***@pg.corp.example:5432/aegis?sslmode=verify-full'
helm upgrade --install aegis deploy/helm/aegisproxy -n aegis \
  --set storage.postgres.existingSecret=aegis-db ...
```

## Secrets

By default the chart generates `jwt-secret`, `dataplane-key`, `bootstrap-admin-password` and `metrics-token`
once and keeps them on upgrades (`helm.sh/resource-policy: keep`). For GitOps / External Secrets Operator
create the Secret yourself and set `secrets.existingSecret`. Without `ca.existingSecret` Helm generates a
2048-bit CA once (quick start only).

## Important values

| Value | Default | Notes |
|---|---|---|
| `publicUrl` | `https://aegis.example.com` | must be the external console/API URL |
| `storage.type` | `postgres` | `file` = single replica + PVC |
| `controlPlane.replicas` | 2 | |
| `controlPlane.trustedProxies` | "" | pod CIDR of the ingress controller or addresses of an external load balancer (`AEGIS_TRUSTED_PROXIES`). Empty = the TCP peer is the client; never whole private ranges |
| `controlPlane.trustedProxyHosts` | "" | DNS names whose current addresses are trusted as proxies; with `console.enabled` (same-origin `/api` proxy) the console's headless Service is added automatically |
| `clusterDomain` | `cluster.local` | cluster DNS domain, used for the console's headless Service name |
| `controlPlane.serviceAccount.create` / `.name` / `.annotations` | off | dedicated ServiceAccount (API token never mounted), e.g. for AKS workload identity (`azure.workload.identity/client-id`) - see [log export → Sentinel](../log-export.md#microsoft-sentinel) |
| `controlPlane.podLabels` | – | extra pod labels, e.g. `azure.workload.identity/use: "true"` |
| `console.enabled` / `console.apiBaseUrl` | false / "" | separate console; empty = nginx proxies `/api/` |
| `dataPlane.replicas` / `dataPlane.autoscaling.*` | 3 / off | |
| `dataPlane.service.*` | LoadBalancer, Local, ClientIP | see [architecture](../architecture.md#server-identity) |
| `clamav.enabled` / `clamav.replicas` | true / 2 | |
| `clamav.image.digest` | pinned | ClamAV image digest (tag kept for readability); `*.image.digest` also pins the AegisProxy images |
| `clamav.podSecurityContext` / `clamav.containerSecurityContext` | uid 100, read-only root fs, no capabilities, RuntimeDefault seccomp | clamd and freshclam run as the image's `clamav` user ("restricted" Pod Security Standard); `/tmp` and `/var/log/clamav` are emptyDirs |
| `networkPolicy.enabled` | true | requires a CNI that enforces NetworkPolicy |
| `networkPolicy.proxyClientCIDRs` | [] | restrict who may use the proxy |
| `networkPolicy.dataPlaneEgressDeny` | private ranges | remove ranges hosting whitelisted internal services |
| `networkPolicy.dataPlaneEgressIPv6` / `.dataPlaneEgressDenyIPv6` | true / ULA, link-local, NAT64, 6to4, … | IPv6 egress is `::/0` minus the deny list (`false` = no IPv6 egress); add global-unicast pod/service/VPC ranges (e.g. EKS IPv6) |
| `networkPolicy.clamavExtraEgress` | [] | ClamAV may reach DNS and public HTTPS (signature updates) only; extra egress rules, e.g. for a private mirror |
| `networkPolicy.extraIngressFrom` | [] | extra peers (monitoring namespace, node CIDRs for probes) |
| `networkPolicy.cnpgOperatorNamespace` | `cnpg-system` | with CloudNativePG: PostgreSQL (5432) only from the control-plane and the other instances, the instance manager (8000) only from the operator namespace |
| `probes.mode` | `http` | `exec` runs every health probe inside the container (no node → pod traffic), for CNIs that enforce policy on kubelet traffic |
| `metrics.serviceMonitor.enabled` | false | Prometheus Operator |
| `metrics.prometheusRule.enabled` | false | `PrometheusRule` with the recommended alerts: worker failed closed, policy sync stale, ClamAV/ICAP unavailable, too few healthy workers, log export failing or dropping, login failures, stale threat intelligence (thresholds under `metrics.prometheusRule.*`) |

See `values.yaml` for the complete list.

## Notes

- **Client IP preservation**: server identification by IP/CIDR needs the original source address. Keep
  `externalTrafficPolicy: Local` (or use proxy tokens). With cloud load balancers make sure they do not SNAT.
- **NetworkPolicies and probes**: Kubernetes semantics allow node → pod traffic (kubelet probes). Some CNI
  configurations (e.g. Cilium with host firewall, `policy-enforcement=always` or eBPF host routing on some
  kernels) enforce policy on it. Set `probes.mode=exec` so probes run inside the containers instead of
  opening the policies; CloudNativePG's own probes need the equivalent CNI-level allowance (e.g. a
  `CiliumNetworkPolicy` with `fromEntities: [host]` on port 8000).
- **Verify enforcement in your cluster**: `scripts/verify-networkpolicies.sh <namespace> <release-fullname>`
  probes every component from a throw-away namespace, from an unlabelled pod in the release namespace and from a
  data-plane worker and compares the result with the intended matrix (control-plane, ClamAV, PostgreSQL and
  console unreachable from outside; proxy port open; data-plane egress to cluster ranges and cloud metadata
  blocked, internet open).
- **SSE through the ingress**: the default annotations disable proxy buffering and raise the read timeout
  for ingress-nginx; adapt them for other controllers.
- **Rolling updates**: control-plane replicas fail `/readyz` for 10 s after SIGTERM before closing the
  listener — verified with zero failed writes while pods were replaced.

## Verification performed

The chart was installed on Kubernetes 1.37 (kind) with CloudNativePG 1.30 (2 instances), 2 control-plane
replicas, 2 data-plane workers, the separate console and ClamAV:

- login through the separate console (nginx `/api` proxy), configuration changes visible on both replicas;
- proxying through the NodePort with preserved client IP (allowed and default-deny verdicts);
- 40/40 successful writes while control-plane pods were deleted twice;
- `helm lint` and `kubeconform -strict` for all value combinations.

Repeated for 2.1 with the final images: encryption at rest active in postgres mode, both workers report YARA
status, 100/100 writes while a control-plane pod was deleted, and `GET /api/audit/verify` verified the complete
keyed audit chain from the database. The optional `PrometheusRule` (`metrics.prometheusRule.enabled`) passes
`promtool check rules`.

**NetworkPolicy enforcement (2.1)** was validated with Cilium 1.20 (eBPF, no kube-proxy): with all policies
enforced and `probes.mode=exec`, all 9 pods became ready and `scripts/verify-networkpolicies.sh` passed 16/16
checks (17/17 in the extended test, which also confirmed the database is reachable for the control-plane only);
Hubble recorded the denied connections. The full functional test (9/9, 100/100 writes during a pod deletion)
passed again with the policies enforced. On that host Cilium classified kubelet traffic as `world`, which is
why `probes.mode=exec` exists; only CloudNativePG's own probe port needed a test-environment
`CiliumNetworkPolicy`.
