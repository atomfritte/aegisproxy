# High availability

## Concept

| Component | HA mechanism |
|---|---|
| Control-plane | `AEGIS_STORAGE=postgres`; any number of active replicas behind a load balancer using `/readyz` (includes the database check). |
| Database | Replicated PostgreSQL: CloudNativePG (Kubernetes), Patroni, or a managed service (Azure Database for PostgreSQL Flexible Server with zone-redundant HA, Amazon RDS Multi-AZ / Aurora, Google Cloud SQL HA). |
| Data-plane | N stateless workers behind an L4 load balancer with **source-IP affinity**. |
| ClamAV | 2+ instances (each with its own signature database) behind a service/load balancer. |
| Console | Bundled in every control-plane replica, or separately hosted static files. |

Requirements for every control-plane replica: identical `AEGIS_JWT_SECRET`, `AEGIS_DATAPLANE_KEY`,
`AEGIS_DATABASE_URL`, `AEGIS_PUBLIC_URL` and the same root CA certificate (`CERTS_DIR`). `DATA_DIR` only holds
caches and may be ephemeral.

## Reference deployment (Docker Compose)

`deploy/compose/ha/` runs the complete topology on one Docker host — ideal to evaluate and test the cluster
mode before rolling it out on several hosts:

```
postgres ─┬─ control-plane-1 ─┐
          └─ control-plane-2 ─┼─ HAProxy :8081 (round robin, /readyz, retry on connection failure)
                              │       :8080 (TCP, balance source) ─┬─ data-plane-1 ─┐
console (nginx) :8082 ────────┘                                   └─ data-plane-2 ─┴─ clamav
```

```bash
cd deploy/compose/ha
install -m 600 ../../../.env.example .env && ../../../scripts/gen-secrets.sh >> .env
docker compose up -d --build   # trusts X-Forwarded-For only from the lb and console containers (AEGIS_TRUSTED_PROXY_HOSTS)
open http://127.0.0.1:8081          # console via load balancer
open http://127.0.0.1:8082          # separately hosted console
open http://127.0.0.1:8404/stats    # HAProxy statistics
```

Failover test:

```bash
docker stop aegis-ha-control-plane-1-1     # writes keep working via replica 2
docker start aegis-ha-control-plane-1-1    # rejoins with the current revision
```

> [!IMPORTANT]
> **PostgreSQL major upgrades.** The reference compose pins PostgreSQL 18. A data directory created by an
> earlier major (e.g. 17) will not start under a newer major — the server refuses to open an incompatible
> `pg-data`. To move an existing cluster forward, dump and restore (`pg_dump`/`pg_restore`) or run
> `pg_upgrade` against a 18 binary, then point the control-planes at the upgraded database; or start fresh
> on a new volume (the control-plane recreates its schema). On managed/operated databases
> (CloudNativePG, Patroni, RDS/Aurora, Azure, Cloud SQL) use the platform's major-version upgrade procedure.

## Production on multiple hosts / VMs

1. Provision PostgreSQL HA and create a database + user (`CREATE DATABASE aegis OWNER aegis`). The schema is
   created and migrated automatically (serialized by an advisory lock).
2. Create the root CA once: `aegis-control-plane gen-ca ./ca` and distribute `mitmproxy-ca-cert.pem` to all
   control-plane hosts and `mitmproxy-ca.pem` (private key!) to all data-plane hosts via your secret
   management.
3. Start the control-plane on 2+ hosts with the same environment; put an HTTP(S) load balancer in front
   (health check `GET /readyz`, retries on connection failures, SSE-friendly timeouts ≥ 1 h for
   `/api/flows/stream`).
4. Start the data-plane workers with `CONTROL_PLANE_URL` pointing at the control-plane load balancer; put an L4
   load balancer with source-IP affinity in front of port 8080 (health check `GET :9091/readyz`).
5. Point servers at the proxy load balancer.

## Behaviour during failures

| Failure | Effect |
|---|---|
| One control-plane replica | Load balancer removes it (`/readyz`); no impact. |
| All control-plane replicas | Workers keep enforcing the last policy for up to `AEGIS_POLICY_MAX_AGE` (default `10m`), then fail closed (503 `policy_stale`) until the control-plane is back; telemetry is spooled per worker (`flow-spool-1`/`-2` volumes, beyond the 20,000-flow memory queue) and retried; console unavailable. |
| Database | `/readyz` fails; control-plane writes are rejected (no silent loss); workers keep enforcing. |
| One data-plane worker | Clients on that worker reconnect to another worker (affinity re-hashes). |
| ClamAV | `av_fail_mode=open`: downloads pass with `AV_ERROR` events; `closed`: downloads are blocked (503). |

## Backups

- PostgreSQL: continuous archiving / PITR of your database platform (CloudNativePG `backup` to object storage,
  managed-service backups) plus regular `pg_dump -Fc aegis`.
- Root CA private key: offline copy in a vault — losing it means redistributing a new CA to every server.
