# Kubernetes (Helm)

Chart: `deploy/helm/aegisproxy` (Kubernetes ≥ 1.27).

| Resource | Purpose |
|---|---|
| Deployment `control-plane` | N replicas (PostgreSQL) or 1 replica + PVC (file storage); probes `/healthz`, `/readyz`; topology spread; PDB; 10 s drain on termination |
| Deployment `data-plane` | mitmproxy workers; probes on the ops port 9091; optional HPA; PDB |
| Service `proxy` | `LoadBalancer`/`NodePort` with `externalTrafficPolicy: Local` (client IP preserved) and `sessionAffinity: ClientIP`; a `LoadBalancer` must be restricted to the server networks (see [Exposing the proxy](#exposing-the-proxy)) |
| StatefulSet `clamav` | clamd replicas with their own signature volumes |
| Deployment `console` (optional) | separately hosted nginx console, proxies `/api/` to the control-plane |
| Cluster (optional) | CloudNativePG PostgreSQL cluster with synchronous replication |
| Ingress (optional) | console/API (+ separate console host) |
| Service `ingress-peers` (optional) | headless Service in the ingress controller's namespace; its DNS name is the only trusted `X-Forwarded-For` source (`ingress.trustedController`) |
| NetworkPolicies | control-plane, data-plane (no egress into private IPv4 ranges, cloud metadata or the Azure WireServer; IPv6 egress opt-in), ClamAV (egress: DNS and public HTTPS only), console; DNS only to the cluster DNS pods in `kube-system` |
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

# 3. install (pin the image digests you verified, see "Images")
helm upgrade --install aegis deploy/helm/aegisproxy -n aegis \
  --set publicUrl=https://aegis.corp.example \
  --set ca.existingSecret=aegis-ca \
  --set storage.postgres.cnpg.enabled=true \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.host=aegis.corp.example --set ingress.tlsSecretName=aegis-tls \
  --set ingress.trustedController.enabled=true \
  --set 'dataPlane.service.loadBalancerSourceRanges={10.20.0.0/16}'   # the server networks

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

## Images

The chart defaults to the release images of this repository, `ghcr.io/atomfritte/aegisproxy-control-plane`,
`-data-plane` and `-console`, tag `v<appVersion>` (e.g. `v2.1.0`). They are built by
`.github/workflows/release.yml` from the tag, signed keyless with cosign and carry an SBOM and SLSA build
provenance. Verify the image and pin the digest you verified, so a re-pushed tag cannot change what runs:

```bash
IMG=ghcr.io/atomfritte/aegisproxy-control-plane:v2.1.0
cosign verify "$IMG" \
  --certificate-identity-regexp '^https://github.com/atomfritte/aegisproxy/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
crane digest "$IMG"     # or: docker buildx imagetools inspect "$IMG"
helm upgrade ... --set controlPlane.image.digest=sha256:<digest> \
  --set dataPlane.image.digest=sha256:<digest> --set console.image.digest=sha256:<digest>
```

`global.imageRegistry` replaces the registry host of every image for a mirror or pull-through cache
(`harbor.corp.example/ghcr-proxy` → `harbor.corp.example/ghcr-proxy/atomfritte/aegisproxy-control-plane`); the
digests stay valid through a mirror. The ClamAV image is pinned by digest in `values.yaml`.

## Exposing the proxy

A `LoadBalancer` proxy Service is reachable from every network that reaches the load balancer, and an open
forward proxy is abused quickly. Rendering therefore fails unless the clients are restricted:

- `dataPlane.service.loadBalancerSourceRanges` — enforced by the cloud load balancer / kube-proxy, or
- `networkPolicy.proxyClientCIDRs` with `networkPolicy.enabled` — enforced by the CNI on the worker pods
  (needs `externalTrafficPolicy: Local`, the default, so the pods see the client addresses), or
- `dataPlane.service.allowPublicProxy=true` as a deliberate decision (e.g. an internal load balancer annotation
  on a network that only servers reach); the release notes then repeat the warning.

`NodePort` is not affected; restrict it with `proxyClientCIDRs` or the node firewall.

## Client addresses behind the ingress

Behind an ingress controller every request reaches the control-plane from a controller pod. Without a trusted
proxy the control-plane uses that pod address as the client, so per-IP login and SCIM lockouts hit everyone
and the audit trail records the controller. Never trust the pod CIDR (`controlPlane.trustedProxies`): every pod
and node in it could then choose its own client address. Instead set `ingress.trustedController.enabled=true`:
the chart creates a headless Service `<release>-aegisproxy-ingress-peers` in `ingress.trustedController.namespace`
that selects the controller pods by `podLabels`, and the control-plane trusts exactly the addresses its DNS
name resolves to (`AEGIS_TRUSTED_PROXY_HOSTS`, re-resolved every 30 s). The release needs the right to create
a Service in that namespace; otherwise create the headless Service yourself and set
`ingress.trustedController.existingServiceFQDN` to its absolute name (with the trailing dot). The console's
same-origin `/api` proxy (`console.enabled`) is trusted the same way through its own headless Service.

All trusted names are absolute (`name.namespace.svc.cluster.local.`). The chart does **not** set
`dnsConfig.options ndots:1`: with the cluster default `ndots:5` a relative name would be tried with every search
domain first, while `ndots:1` would send internal names such as `db.corp` to the upstream resolvers before the
search list. The trailing dot avoids both, independent of the pod's resolver options.

## Important values

| Value | Default | Notes |
|---|---|---|
| `publicUrl` | `https://aegis.example.com` | must be the external console/API URL |
| `storage.type` | `postgres` | `file` = single replica + PVC |
| `controlPlane.replicas` | 2 | |
| `global.imageRegistry` | "" | registry mirror: replaces the registry host of every image |
| `*.image.repository` / `.tag` / `.digest` | `ghcr.io/atomfritte/aegisproxy-*` / `v<appVersion>` / "" | see [Images](#images); pin the verified digest in production |
| `controlPlane.trustedProxies` | "" | addresses that belong to proxies alone, e.g. an external load balancer (`AEGIS_TRUSTED_PROXIES`). Empty = the TCP peer is the client; never a pod CIDR or a whole private range |
| `controlPlane.trustedProxyHosts` | "" | absolute DNS names (trailing dot) whose current addresses are trusted as proxies; the console's headless Service (`console.enabled`) and `ingress.trustedController` are added automatically |
| `ingress.trustedController.enabled` / `.namespace` / `.podLabels` / `.existingServiceFQDN` | false / `ingress-nginx` / ingress-nginx controller labels / "" | trust exactly the ingress controller pods, see [Client addresses behind the ingress](#client-addresses-behind-the-ingress) |
| `clusterDomain` | `cluster.local` | cluster DNS domain, used for the absolute names of the headless Services |
| `controlPlane.serviceAccount.create` / `.name` / `.annotations` | off | dedicated ServiceAccount (API token never mounted), e.g. for AKS workload identity (`azure.workload.identity/client-id`) - see [log export → Sentinel](../log-export.md#microsoft-sentinel) |
| `controlPlane.podLabels` | – | extra pod labels, e.g. `azure.workload.identity/use: "true"` |
| `console.enabled` / `console.apiBaseUrl` | false / "" | separate console; empty = nginx proxies `/api/` |
| `dataPlane.replicas` / `dataPlane.autoscaling.*` | 3 / off | |
| `dataPlane.service.*` | LoadBalancer, Local, ClientIP | see [architecture](../architecture.md#server-identity) |
| `dataPlane.service.loadBalancerSourceRanges` / `.allowPublicProxy` | [] / false | a `LoadBalancer` needs source ranges, `networkPolicy.proxyClientCIDRs` or `allowPublicProxy=true` (see [Exposing the proxy](#exposing-the-proxy)) |
| `clamav.enabled` / `clamav.replicas` | true / 2 | |
| `clamav.image.digest` | pinned | ClamAV image digest (tag kept for readability); `*.image.digest` also pins the AegisProxy images |
| `clamav.podSecurityContext` / `clamav.containerSecurityContext` | uid 100, read-only root fs, no capabilities, RuntimeDefault seccomp | clamd and freshclam run as the image's `clamav` user ("restricted" Pod Security Standard); `/tmp` and `/var/log/clamav` are emptyDirs |
| `networkPolicy.enabled` | true | requires a CNI that enforces NetworkPolicy |
| `networkPolicy.proxyClientCIDRs` | [] | restrict who may use the proxy |
| `networkPolicy.dns.namespace` / `.dns.podLabels` | `kube-system` / `k8s-app: kube-dns` | the only DNS servers (port 53) the components may query: the cluster DNS pods in their namespace, so a pod elsewhere carrying the same label is not a resolver |
| `networkPolicy.extraDnsEgress` | [] | additional DNS peers, e.g. NodeLocal DNSCache `[{ ipBlock: { cidr: 169.254.20.10/32 } }]` |
| `networkPolicy.dataPlaneEgressDeny` | private ranges, link-local (cloud metadata), `168.63.129.16/32` | remove ranges hosting whitelisted internal services; `168.63.129.16` is the Azure WireServer / host agent, a public address only reachable from Azure VMs |
| `networkPolicy.dataPlaneEgressIPv6` / `.clusterIPv6CIDRs` | false / [] | IPv6 egress (`::/0` minus `dataPlaneEgressDenyIPv6` and `clusterIPv6CIDRs`) is opt-in: pod, service and node addresses of IPv6 clusters are often global unicast (EKS, GKE) and would count as internet. Enabling it requires `clusterIPv6CIDRs` (the cluster's pod/service/node/VPC IPv6 ranges, `["fc00::/7"]` for unique-local ones) |
| `networkPolicy.dataPlaneEgressDenyIPv6` | ULA, link-local, NAT64, 6to4, … | always excluded from IPv6 egress |
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
  console unreachable from outside; proxy port open; data-plane egress to cluster ranges, cloud metadata and
  the Azure WireServer blocked, internet open; DNS only to the cluster DNS in `kube-system`, not to a pod
  elsewhere that carries the `k8s-app: kube-dns` label).
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
