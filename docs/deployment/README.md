# Deployment options

| Option | Control-plane | Storage | Availability | Typical use | Guide |
|---|---|---|---|---|---|
| **Docker Compose (single host)** | 1 container (API + console) | file | single node, automatic restarts | evaluation, small sites, branch offices | [docker-compose.md](docker-compose.md) |
| **Docker Compose HA** | 2+ containers behind HAProxy | PostgreSQL | active-active, survives replica failure | test the cluster mode, small on-prem HA | [high-availability.md](high-availability.md) |
| **Kubernetes (Helm)** | Deployment, N replicas | PostgreSQL (CloudNativePG or external) | rolling updates without downtime, PDBs, spread across nodes | production | [kubernetes.md](kubernetes.md) |
| **Linux VMs (systemd)** | native binary | file or PostgreSQL | via multiple VMs + load balancer | environments without containers | [linux.md](linux.md) |
| **Windows Server** | native Windows service | file or PostgreSQL | via multiple servers + load balancer | Windows-only datacenters | [windows.md](windows.md) |

The **console** can be bundled with the control-plane (default) or hosted separately (nginx container, CDN,
IIS, object storage) — see [separate-console.md](separate-console.md).

## Common prerequisites

1. **Public URL** of the console/API (`AEGIS_PUBLIC_URL`, https in production).
2. **Secrets**: `AEGIS_JWT_SECRET`, `AEGIS_DATAPLANE_KEY` (≥ 32 random characters, e.g. `openssl rand -hex 32`).
3. **Root CA**: generated automatically on a single node, or up front with `aegis-control-plane gen-ca <dir>`.
4. **Network**: servers reach the proxy port (8080); data-plane reaches the control-plane (8081), ClamAV (3310)
   and the internet; the control-plane reaches feed sources and webhooks (or uses `AEGIS_FEED_HTTP_PROXY`).
5. **Client rollout**: install the CA (`/api/public/ca/install-linux.sh`, `/api/public/ca/install-windows.ps1`)
   and set `http_proxy`/`https_proxy` (or WinHTTP) on the servers.

## Sizing guidance

| Component | Per instance | Scale on |
|---|---|---|
| Control-plane | 0.1–0.5 vCPU, 192 MiB–1 GiB RAM | number of admins / API clients; 2 replicas for HA |
| Data-plane | 0.25–2 vCPU, 384 MiB–2 GiB RAM | concurrent connections and inspected throughput (TLS interception + scanning is CPU bound) |
| ClamAV | 1.5–3 GiB RAM | download volume; 2 replicas for HA |
| PostgreSQL | 1 vCPU, 1–2 GiB RAM, 10 GiB | flow retention × request rate |

As a starting point, 3 data-plane workers with 1 vCPU each handle several hundred servers with mostly
package-manager traffic; scale out horizontally (`dataPlane.autoscaling`).
