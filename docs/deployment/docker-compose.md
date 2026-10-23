# Docker Compose (single host)

The repository root contains a hardened `docker-compose.yml`:

| Service | Image | Notes |
|---|---|---|
| `ca-init` | `aegisproxy/control-plane` | One-shot: creates the root CA in the `aegis-ca` volume (`gen-ca`). |
| `control-plane` | `aegisproxy/control-plane` | API + bundled console, file storage in `aegis-data`, CA mounted read-only. |
| `data-plane` | `aegisproxy/data-plane` | mitmproxy worker, port 8080, waits for a healthy control-plane. |
| `clamav` | `clamav/clamav:1.5` | Antivirus, signatures in `clamav-db`. |

All AegisProxy containers run as non-root (UID 65532), with a read-only root filesystem, all Linux
capabilities dropped and `no-new-privileges`.

## Installation

```bash
cp .env.example .env
./scripts/gen-secrets.sh >> .env          # AEGIS_JWT_SECRET, AEGIS_DATAPLANE_KEY, AEGIS_DB_PASSWORD
$EDITOR .env                              # AEGIS_PUBLIC_URL, bind addresses, optional admin password
docker compose up -d --build
docker compose ps                         # control-plane and data-plane become "healthy"
```

Initial admin password (if `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` was left empty):

```bash
# the control-plane image is distroless (no shell), so read the volume with a helper container
docker run --rm -v aegisproxy_aegis-data:/data alpine cat /data/secrets/initial-admin-password
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
AEGIS_TRUSTED_PROXIES=172.16.0.0/12      # address of the reverse proxy as seen by the container
```

Alternatively mount a certificate and set `AEGIS_TLS_CERT_FILE`/`AEGIS_TLS_KEY_FILE`.

## Operations

```bash
docker compose logs -f control-plane data-plane
docker compose pull && docker compose up -d          # upgrade (state + CA live in volumes)
docker run --rm -v aegisproxy_aegis-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/aegis-data-$(date +%F).tgz -C /data .  # backup
```

## Migrating from the 1.x compose file

1.x used bind mounts (`./certs`, `./control-plane/data`). Copy them into the volumes once:

```bash
docker compose up -d ca-init   # creates the volumes
docker run --rm -v aegisproxy_aegis-ca:/certs -v "$PWD/certs":/old:ro alpine \
  sh -c 'cp -a /old/. /certs/ && chown -R 65532:65532 /certs && chmod 600 /certs/mitmproxy-ca.pem'
docker run --rm -v aegisproxy_aegis-data:/data -v "$PWD/control-plane/data":/old:ro alpine \
  sh -c 'cp -a /old/. /data/ && chown -R 65532:65532 /data && chmod 600 /data/aegis_state.json'
docker compose up -d
```

On first start the state is migrated automatically (proxy tokens hashed, schema upgraded). 1.x never
persisted password hashes, so a bootstrap admin password is generated (see above) and other accounts need a
password reset by the admin. Set `AEGIS_DEMO_MODE=true` only if you want the 1.x demo personas back.
