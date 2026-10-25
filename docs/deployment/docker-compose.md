# Docker Compose (single host)

The repository root contains a hardened `docker-compose.yml`:

| Service | Image | Notes |
|---|---|---|
| `ca-init` | `ghcr.io/atomfritte/aegisproxy-control-plane` (built locally) | One-shot: creates the root CA in the `aegis-ca` volume (key + certificate) and copies the certificate alone to `aegis-ca-public` (`gen-ca /certs /public`). |
| `control-plane` | same image as `ca-init` | API + bundled console, file storage in `aegis-data`, only the public CA certificate (`aegis-ca-public`, read-only); the CA key is mounted into the data-plane only. |
| `data-plane` | `ghcr.io/atomfritte/aegisproxy-data-plane` (built locally) | mitmproxy worker, port 8080, waits for a healthy control-plane. Traffic records not yet acknowledged by the control-plane are spooled in the `flow-spool` volume (`AEGIS_FLOW_SPOOL_DIR`), so they survive restarts and control-plane outages; the worker fails closed once its policy is older than `AEGIS_POLICY_MAX_AGE` (`.env`, default `10m`, `0` = no limit). |
| `clamav` | `clamav/clamav:1.5` (pinned by digest) | Antivirus, signatures in `clamav-db`; runs as the image's `clamav` user (UID 100) instead of the root `/init`. |

All AegisProxy containers run as non-root (UID 65532) and ClamAV as UID 100, all with a read-only root
filesystem, all Linux capabilities dropped and `no-new-privileges`.

The AegisProxy images are always built from the checkout (`pull_policy: build`): neither `docker compose up`
nor `docker compose pull` fetches them from a registry. They carry the names of the signed release images, so
`docker compose pull` cannot substitute an image from a registry namespace that AegisProxy does not control.
The third-party images (ClamAV, and PostgreSQL/HAProxy in the HA variant) are pinned by digest.

## Installation

```bash
install -m 600 .env.example .env          # holds every secret: owner read/write only
./scripts/gen-secrets.sh >> .env          # AEGIS_JWT_SECRET, AEGIS_DATAPLANE_KEY, AEGIS_DB_PASSWORD
$EDITOR .env                              # AEGIS_PUBLIC_URL, bind addresses, optional admin password
docker compose up -d --build
docker compose ps                         # control-plane and data-plane become "healthy"
```

Initial admin password (if `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` was left empty):

```bash
# the control-plane image is distroless (no shell), so read the volume with a helper container
docker run --rm -v aegisproxy_aegis-data:/data alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f \
  cat /data/secrets/initial-admin-password
```

Sign in at `AEGIS_PUBLIC_URL`, change the password (sidebar → RBAC → *Change my password*), then:

1. **Server Fleet** → create server groups (CIDRs) and register servers; rotate proxy tokens where needed.
2. **Path & Object Whitelist** → create ALLOW rules (or use the learning-session studio).
3. **Threat Protection** → review feeds and the protection policy.
4. Roll out the CA and proxy settings to the servers.

## TLS for the console

Publish the console only on localhost (`AEGIS_CONSOLE_BIND=127.0.0.1:8081`) and terminate TLS in a reverse
proxy (see `deploy/nginx/aegis-console.conf`), then set:

```
AEGIS_PUBLIC_URL=https://aegis.corp.example
AEGIS_TRUSTED_PROXIES=172.18.0.1/32      # exact address of the reverse proxy as seen by the container
```

A reverse proxy on the Docker host reaches the published port from the gateway of the compose network
(`docker network inspect aegisproxy_default --format '{{(index .IPAM.Config 0).Gateway}}'`). Trust exactly
that address, never a whole private range such as `172.16.0.0/12`: every container and host inside a trusted
range could otherwise set `X-Forwarded-For` and choose the client address used for login rate limits,
CIDR-bound service accounts and the audit trail. Without a reverse proxy leave it empty.

Alternatively mount a certificate and set `AEGIS_TLS_CERT_FILE`/`AEGIS_TLS_KEY_FILE`.

## Operations

```bash
docker compose logs -f control-plane data-plane
docker compose up -d --build                         # upgrade after updating the checkout (state, CA and spooled records live in volumes)
docker run --rm -v aegisproxy_aegis-data:/data -v "$PWD":/backup alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f \
  tar czf /backup/aegis-data-$(date +%F).tgz -C /data .  # backup
```

## Migrating from the 1.x compose file

1.x used bind mounts (`./certs`, `./control-plane/data`). Copy them into the volumes once:

```bash
docker compose up -d ca-init   # creates the volumes
docker run --rm -v aegisproxy_aegis-ca:/certs -v "$PWD/certs":/old:ro alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f \
  sh -c 'cp -a /old/. /certs/ && chown -R 65532:65532 /certs && chmod 600 /certs/mitmproxy-ca.pem'
docker run --rm -v aegisproxy_aegis-data:/data -v "$PWD/control-plane/data":/old:ro alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f \
  sh -c 'cp -a /old/. /data/ && chown -R 65532:65532 /data && chmod 600 /data/aegis_state.json'
docker compose up -d
```

On first start the state is migrated automatically (proxy tokens hashed, schema upgraded). 1.x never
persisted password hashes, so a bootstrap admin password is generated (see above) and other accounts need a
password reset by the admin. Set `AEGIS_DEMO_MODE=true` only if you want the 1.x demo personas back.
