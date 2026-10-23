# AegisProxy on Linux (systemd)

This guide covers a production installation of AegisProxy on Linux hosts without containers: the
control-plane and the mitmproxy data-plane as hardened systemd services, ClamAV for malware scanning, and nginx
as TLS-terminating reverse proxy. For container deployments see `docker-compose.yml`, `deploy/compose/ha/`
and `deploy/helm/`; the Windows counterpart is [`windows.md`](windows.md).

All configuration variables are documented in [`docs/configuration.md`](../configuration.md).

| Artefact | Purpose |
|---|---|
| `deploy/systemd/install-linux.sh` | Idempotent installer (users, directories, binary, venv, secrets, CA, units) |
| `deploy/systemd/aegis-control-plane.service` | Hardened unit for the control-plane |
| `deploy/systemd/aegis-dataplane.service` | Hardened unit for the mitmproxy worker |
| `deploy/systemd/control-plane.env.example`, `dataplane.env.example` | Templates for `/etc/aegis/*.env` |
| `deploy/systemd/aegis.logrotate` | Rotation of `audit.jsonl` (and optional log files) |
| `deploy/nginx/aegis-console.conf` | TLS reverse proxy for console + API on one origin |

---

## 1. Architecture

```
 Client servers (Linux / Windows)                           Administrators (browser)
 http(s)_proxy=http://<user>:<token>@proxy:8080                    │ HTTPS :443
 or source-IP identity                                             ▼
            │                                      ┌──────────────────────────────┐
            ▼                                      │ nginx (TLS, HSTS, SSE)       │
 ┌──────────────────────────────┐                  └──────────────┬───────────────┘
 │ aegis-dataplane.service      │  policy bundle (2 s, ETag),     ▼ 127.0.0.1:8081
 │ mitmdump 12.3.0 + addon      │  threat intel, flows   ┌──────────────────────────────┐
 │ :8080 proxy, 127.0.0.1:9091  │──────────────────────▶ │ aegis-control-plane.service  │
 │ user aegis-dp                │  HTTPS + data-plane key│ API + console, user aegis    │
 └──────┬───────────────┬───────┘                        │ /var/lib/aegis  |  PostgreSQL│
        │               │ unix socket / tcp 3310         └──────────────────────────────┘
        │               ▼
        │        clamd (clamav-daemon / clamd@scan)
        ▼
  Internet (upstream TLS always verified, TLS >= 1.2)
```

* **Control-plane** - static Go binary `/usr/local/bin/aegis-control-plane`: API, policy engine, threat
  intelligence, audit trail and (with `AEGIS_UI_DIR`) the web console. Logs to the journal.
* **Data-plane** - `mitmdump` from a Python virtualenv in `/opt/aegis/data-plane/venv` with the `aegis_dp`
  addon. Identifies servers (token or source IP), intercepts TLS with the enterprise CA, enforces the policy
  bundle, scans downloads via clamd. Answers `503` until the first policy sync (`AEGIS_FAIL_MODE=closed`), then
  keeps enforcing the last known policy if the control-plane is unavailable.
* **Secrets** never appear in environment files or unit files: they live in `/etc/aegis/secrets`
  (root:root 0600) and are handed to the services as **systemd credentials** (`LoadCredential=`, read via
  `AEGIS_*_FILE=%d/<name>`). The **CA private key** (`/etc/aegis/ca/mitmproxy-ca.pem`) is only given to the
  data-plane; the control-plane reads the public certificate from a read-only `/var/lib/aegis/certs`.

### Topologies

| Topology | Layout |
|---|---|
| All-in-one | control-plane, worker, clamd and nginx on one host (`install-linux.sh` default `--component all`) |
| Separated | control-plane host (+ nginx) and workers per network zone (`--component data-plane`), each worker with a local clamd |
| Cluster | ≥ 2 control-plane nodes with PostgreSQL behind a load balancer, ≥ 2 workers behind an L4 load balancer with source-IP affinity (section 9) |

### Port matrix

| Source | Destination | Port | Purpose |
|---|---|---|---|
| Client servers | worker | TCP 8080 | explicit proxy |
| Workers | control-plane / nginx / LB | TCP 443 (or 8081) | `CONTROL_PLANE_URL` |
| Administrators, client servers (block pages, CA) | nginx | TCP 443 (80 → redirect) | console, API, `/api/public/*` |
| nginx | control-plane | 127.0.0.1:8081 | upstream |
| Prometheus | nginx `/metrics` (ACL), worker ops | 443, 9091 | metrics (ops is loopback by default) |
| Control-plane nodes | PostgreSQL | TCP 5432 | cluster storage |

---

## 2. Prerequisites

| Item | Requirement |
|---|---|
| Distribution | Debian 12/13, Ubuntu 22.04/24.04, RHEL/Rocky/AlmaLinux 9/10 (x86_64 or arm64) |
| systemd | **≥ 248** (`LoadCredential=` + `%d`). RHEL 8 (systemd 239) is not supported natively - use the container images there |
| Python (workers) | **≥ 3.12** with `venv`: Ubuntu 24.04 / Debian 13 (`python3`, `python3-venv`), RHEL/Rocky 9 (`dnf install python3.12`). Debian 12 and Ubuntu 22.04 ship older versions: use a vendor/backport build and `--python`, or the container image |
| Control-plane binary | `CGO_ENABLED=0 go -C control-plane build -trimpath -ldflags "-s -w -X main.Version=2.1.0" -o aegis-control-plane .` (`GOARCH=arm64` for ARM) |
| Console | `npm --prefix frontend ci && npm --prefix frontend run build` → `frontend/dist` |
| Network | outbound access to PyPI (or an internal mirror) during installation; the port matrix above |
| Sizing (starting point) | control-plane 2 vCPU / 4 GB; worker 4 vCPU / 8 GB; measure with `/metrics` |

---

## 3. Installation

Copy the repository (or a release bundle containing `deploy/`, `data-plane/`, `frontend/dist` and the binary)
to the host and run the installer as root.

**All-in-one / control-plane host**

```bash
sudo ./deploy/systemd/install-linux.sh \
    --binary ./aegis-control-plane \
    --public-url https://aegis.corp.example \
    --ui-dir ./frontend/dist \
    --generate-metrics-token
```

**Data-plane-only host** (copy `dataplane.key` and `mitmproxy-ca.pem` from the control-plane host over SSH,
e.g. `sudo install -m 0600 /dev/stdin /root/dp.key`, and delete the copies afterwards):

```bash
sudo ./deploy/systemd/install-linux.sh --component data-plane \
    --control-plane-url https://aegis.corp.example \
    --dataplane-key-file /root/dataplane.key \
    --ca-file /root/mitmproxy-ca.pem \
    --clamd-address unix:///run/clamav/clamd.ctl
```

What the installer does (idempotent - a re-run upgrades and keeps secrets, CA, state and env files):

1. Checks root, systemd ≥ 248, distribution family (Debian/Ubuntu vs. RHEL/Rocky).
2. Creates the system users `aegis` (control-plane) and `aegis-dp` (data-plane) with `nologin` shells.
3. Creates `/etc/aegis` (0755), `/etc/aegis/secrets` (0700) and generates missing secrets with
   `openssl rand -hex 32` (`jwt.key`, `dataplane.key`, optionally `metrics-token`), root:root 0600. Imports
   `--dataplane-key-file`, `--jwt-secret-file`, `--database-url-file`, `--bootstrap-admin-password-file`,
   `--tls-cert/--tls-key`; refuses to replace a different existing secret without `--force`.
4. Generates the enterprise root CA with `aegis-control-plane gen-ca` into a temporary directory (or imports
   `--ca-file`), stores key+cert as `/etc/aegis/ca/mitmproxy-ca.pem` (0600) and publishes only the public
   certificates to `/etc/aegis/ca` and `/var/lib/aegis/certs`.
5. Installs the binary (atomic rename), the console to `/opt/aegis/console` (sets `AEGIS_UI_DIR`),
   `/etc/aegis/control-plane.env` from the template (sets `AEGIS_PUBLIC_URL`), the unit and a credentials drop-in
   `aegis-control-plane.service.d/10-credentials.conf` for the optional secrets that exist.
6. Data-plane: finds Python ≥ 3.12 (`--python`, `--install-deps` installs it with apt/dnf), creates the venv,
   `pip install mitmproxy==12.3.0 yara-x==1.22.0` plus the security overrides of `requirements-security.txt`
   (binary wheels, glibc ≥ 2.28; `--no-yara` skips the YARA
   engine) or `--requirements` with a **complete** hash-pinned lock file (see below),
   copies the addon, byte-compiles
   it, runs an import check, creates `/etc/aegis/dataplane.env` (`CONTROL_PLANE_URL`, `AEGIS_CLAMD_ADDRESS`) and
   installs the unit.
7. Installs `/etc/logrotate.d/aegis`; on SELinux hosts labels the venv `bin/` directory `bin_t` and restores
   file contexts.
8. Enables and (re)starts the services (unless `--no-start`), waits for `/healthz` (control-plane) and
   `/readyz` (worker), prints the CA fingerprint, key locations, admin password location and ClamAV,
   firewall and SELinux hints.

**Hash-pinned data-plane installation** (recommended for production, together with an internal mirror):

```bash
# on a build host with uv (its --override raises packages above declared upper bounds)
printf 'mitmproxy==12.3.0\nyara-x==1.22.0\n' > requirements.in
uv pip compile --python-version 3.12 --generate-hashes \
    --override data-plane/requirements-security.txt requirements.in -o requirements-lock.txt
sudo deploy/systemd/install-linux.sh --component data-plane --requirements requirements-lock.txt \
    --pip-args "--no-index --find-links /srv/wheels"
```

The installer installs the lock with `--require-hashes --no-deps` (the security baseline raises Brotli above
mitmproxy's declared upper bound, which pip's resolver would otherwise refuse), then aborts if a package is
below the baseline of `data-plane/requirements-security.txt` or if `pip check` reports anything other than
these deliberate overrides (an incomplete lock file).

Review `/etc/aegis/control-plane.env` and `/etc/aegis/dataplane.env` afterwards and apply changes with
`systemctl restart aegis-control-plane aegis-dataplane`. Settings in the env files override the unit's
`Environment=` defaults. **Never put secrets into the env files** - a plain `AEGIS_JWT_SECRET` would take
precedence over the credential.

**First login.** Sign in as `admin` with the password from
`/var/lib/aegis/data/secrets/initial-admin-password` (or the bootstrap password file you supplied), change it,
create personal accounts, and delete the password file(s) (then re-run the installer so the drop-in no longer
references a removed credential).

### Optional secrets

| File in `/etc/aegis/secrets` | Variable (set by the drop-in) | Purpose |
|---|---|---|
| `database-url` | `AEGIS_DATABASE_URL_FILE` | PostgreSQL DSN (cluster mode, `AEGIS_STORAGE=postgres`) |
| `bootstrap-admin-password` | `AEGIS_BOOTSTRAP_ADMIN_PASSWORD_FILE` | initial super-admin password |
| `metrics-token` | `AEGIS_METRICS_TOKEN_FILE` | bearer token for `/metrics` |
| `tls.crt`, `tls.key` | `AEGIS_TLS_CERT_FILE`, `AEGIS_TLS_KEY_FILE` | native HTTPS without nginx |

After adding or removing a file, re-run the installer (it regenerates the drop-in) - `LoadCredential=` fails
the unit if a referenced file is missing.

---

## 4. Service hardening

Both units run without any capabilities (`CapabilityBoundingSet=`), with `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, kernel/cgroup/clock protection, `RestrictNamespaces`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service ~@privileged @resources`,
`SystemCallArchitectures=native`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `RemoveIPC`,
`UMask=0077`, `LimitNOFILE=65536`, `Restart=on-failure` and `TimeoutStopSec=30`.
`systemd-analyze security` rates both units **1.2 / 1.3 ("OK")**.

| Decision | Reason |
|---|---|
| Static users `aegis` / `aegis-dp` instead of `DynamicUser=yes` | stable ownership of `/var/lib/aegis` for backups/restores, `su aegis aegis` in logrotate, CA provisioning before the first start; the remaining sandboxing matches what `DynamicUser` adds |
| `ReadOnlyPaths=/var/lib/aegis/certs` (control-plane) | a missing certificate makes the service fail loudly instead of silently generating a new, untrusted CA |
| CA key only via `LoadCredential=ca:` to the data-plane | the control-plane process cannot read the CA private key |
| CA staged to `/run/aegis-dataplane/confdir` by `ExecStartPre` | mitmproxy needs a writable confdir (it writes `mitmproxy-dhparam.pem`); tmpfs, 0700, removed on stop |
| `MemoryDenyWriteExecute=yes` (control-plane) | static Go binary, no W+X memory |
| **`MemoryDenyWriteExecute=no` (data-plane)** | mitmproxy's TLS layer uses pyOpenSSL callbacks created with cffi `ffi.callback()`, which need writable+executable memory with the pip-installed cffi wheels. With W^X enforced the worker stays "ready" but every intercepted TLS handshake fails with `MemoryError: Cannot allocate write+execute memory for ffi.callback()` (verified with mitmproxy 12.3.0 / cffi 2.1.1). CPython itself needs no W+X memory |
| `ProcSubset=pid` only on the control-plane | the Go binary needs nothing from `/proc` besides its own process |
| `KillSignal=SIGINT` (data-plane) | graceful mitmdump shutdown |

The hardening set was exercised end-to-end (control-plane healthy, worker policy sync, intercepted HTTPS request
allowed by a rule, denied request blocked) with transient systemd units using the same properties.

Ports below 1024 for the proxy need a drop-in with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. `AEGIS_PROXY_MODE=transparent` is not supported by these units.

---

## 5. TLS and nginx

Recommended: nginx terminates TLS and proxies console and API (same origin) to the control-plane on loopback.

```bash
sudo apt install nginx          # or: sudo dnf install nginx
sudo install -m 0644 deploy/nginx/aegis-console.conf /etc/nginx/conf.d/aegis-console.conf
sudo install -d -m 0750 /etc/nginx/tls
# place the certificate chain and key, adapt server_name and paths
sudo nginx -t && sudo systemctl enable --now nginx && sudo systemctl reload nginx
```

`/etc/aegis/control-plane.env` must match:

```
AEGIS_PUBLIC_URL=https://aegis.corp.example
AEGIS_LISTEN_ADDR=127.0.0.1:8081
AEGIS_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

The nginx configuration enforces TLS 1.2/1.3 with Mozilla *intermediate* ciphers, HSTS, `client_max_body_size 16m`,
`X-Forwarded-For`/`X-Forwarded-Proto`, disables buffering for the SSE stream `/api/flows/stream`
(`proxy_read_timeout 1h`), restricts `/metrics` to allowed networks and redirects HTTP to HTTPS. It uses
`listen 443 ssl http2` for compatibility with nginx < 1.25.1 (newer versions print a deprecation warning; switch
to `http2 on;` there). On Debian/Ubuntu, consider disabling the default site
(`/etc/nginx/sites-enabled/default`) so that unknown host names do not reach a default page.

Without nginx, place `tls.crt`/`tls.key` into `/etc/aegis/secrets` (`--tls-cert/--tls-key`), remove
`AEGIS_LISTEN_ADDR` (or set it to `0.0.0.0:8081`) and publish port 8081.

**Worker → control-plane trust.** Python uses the system trust store (`/etc/ssl/certs`,
`/etc/pki/tls/certs`). Add your internal CA there (`update-ca-certificates` / `update-ca-trust`) or set
`AEGIS_CONTROL_PLANE_CA_FILE` in `dataplane.env` (then *only* that bundle is used; the file must be readable by
`aegis-dp`).

---

## 6. Firewall

Allow the proxy port only from the server subnets and the console only from admin networks, workers and load
balancers.

```bash
# firewalld (RHEL/Rocky)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.20.0.0/16" port port="8080" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.10.0/24" service name="https" accept'
sudo firewall-cmd --reload

# ufw (Debian/Ubuntu)
sudo ufw allow from 10.20.0.0/16 to any port 8080 proto tcp
sudo ufw allow from 10.0.10.0/24 to any port 443 proto tcp
```

Keep the worker ops port on loopback (`AEGIS_OPS_ADDR=127.0.0.1:9091`) unless Prometheus or a load balancer
needs it; then bind `0.0.0.0:9091` and allow only those sources.

---

## 7. ClamAV

**Debian/Ubuntu**

```bash
sudo apt install clamav-daemon clamav-freshclam
sudo systemctl enable --now clamav-freshclam clamav-daemon
```

clamd listens on `/run/clamav/clamd.ctl` (mode 666) → `AEGIS_CLAMD_ADDRESS=unix:///run/clamav/clamd.ctl`
(default in `dataplane.env`). The socket stays reachable under `ProtectSystem=strict`.

**RHEL/Rocky (EPEL)**

```bash
sudo dnf install epel-release && sudo dnf install clamd clamav-update
sudo sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf /etc/freshclam.conf
# /etc/clamd.d/scan.conf:  TCPSocket 3310 / TCPAddr 127.0.0.1 / StreamMaxLength 100M
sudo freshclam
sudo systemctl enable --now clamav-freshclam clamd@scan
```

→ `AEGIS_CLAMD_ADDRESS=tcp://127.0.0.1:3310` (the installer's default on RHEL). The unix socket of
`clamd@scan` is group-restricted (`virusgroup`); TCP on loopback avoids extra group memberships.

**Settings for both:** `StreamMaxLength` ≥ the policy's `av_max_scan_bytes` (default 25 MiB; console → Threat
Protection → Protection Policy), `MaxScanSize`/`MaxFileSize` ≥ `StreamMaxLength`. Larger downloads are not
scanned (`av_oversize_action`). If freshclam must use a proxy, set `HTTPProxyServer`/`HTTPProxyPort` in
`freshclam.conf` and allow `database.clamav.net` (or use a private mirror). The worker reports
`aegis_dp_clamd_available` on `/metrics`.

---

## 8. Proxy authentication with per-server tokens

Workers identify the calling server by **token** (`Proxy-Authorization`), by a user name bound to the server's
IP/subnet, or by the **source IP/subnet** of the server object.

1. Console → *Fleet Inventory* → select the server → set the *proxy auth user* (e.g. `svc-db-01`) →
   **Rotate token**. The token is shown once, stored as a hash, and the previous token is revoked immediately.
2. Client configuration: `http://svc-db-01:<token>@aegis-proxy.corp.example:8080` (URL-encode special characters).
3. Distribute tokens with your configuration management (Ansible Vault, Puppet Hiera eyaml, Vault agent) into
   files readable only by the consuming service - **not** into `/etc/environment` (world-readable). Examples:
   `systemctl edit <service>` with `Environment=HTTPS_PROXY=...` in a 0600 drop-in, `/etc/apt/apt.conf.d/95proxy`
   with mode 0600, `~/.config/pip/pip.conf` of the service user.
4. Rotate periodically and after re-imaging a server.

The proxy hop is plain HTTP; keep workers in a segment that client servers reach without crossing untrusted
networks. Load balancers in front of workers must not SNAT client traffic unless all servers use tokens.

---

## 9. Cluster mode (PostgreSQL)

* PostgreSQL 14+ (reference: 17), highly available (Patroni, CloudNativePG, managed service). Create role and
  database (`CREATE ROLE aegis LOGIN PASSWORD '...'; CREATE DATABASE aegis OWNER aegis;`); the schema is
  created/migrated automatically under an advisory lock. Use `sslmode=verify-full`.
* **Identical secrets and CA on all control-plane nodes.** Node 1:
  ```bash
  printf '%s\n' 'postgres://aegis:***@pg.corp.example:5432/aegis?sslmode=verify-full' | sudo install -m 0600 /dev/stdin /root/db-url
  sudo ./deploy/systemd/install-linux.sh --component control-plane --public-url https://aegis.corp.example \
       --database-url-file /root/db-url && sudo shred -u /root/db-url
  ```
  Nodes 2..n additionally get `--jwt-secret-file`, `--dataplane-key-file` and `--ca-file` copied from node 1
  (`/etc/aegis/secrets/{jwt.key,dataplane.key}`, `/etc/aegis/ca/mitmproxy-ca.pem`).
* `DATA_DIR` is only a cache in cluster mode.
* **Control-plane load balancer** (or nginx `upstream` with all nodes): round robin, no stickiness (JWT sessions,
  change propagation via PostgreSQL `LISTEN/NOTIFY`), health check `GET /readyz` (includes the database), idle
  timeout ≥ 1 h for `/api/flows/stream`, `X-Forwarded-For` + `AEGIS_TRUSTED_PROXIES` on every node,
  `AEGIS_PUBLIC_URL` = load balancer URL.
* **Worker load balancer:** TCP with **source-IP affinity** - redirect-object grants (allowed `302` to a signed
  CDN object) are kept per worker, so the follow-up request must hit the same worker. Preserve the client IP
  (HAProxy `balance source` + `hash-type consistent` without SNAT, LVS/keepalived DR, or transparent mode) unless
  every server authenticates with a token. Health check: `GET /readyz` on the ops port. Reference:
  `deploy/compose/ha/haproxy.cfg`.
* Workers set `CONTROL_PLANE_URL` to the control-plane load balancer and share `dataplane.key` and CA.

---

## 10. Rolling out the CA and proxy settings to client servers

Verify the CA fingerprint printed by the installer (also `https://aegis.corp.example/api/public/ca/info`)
through a second channel.

**Linux servers**

```bash
curl -fsSL https://aegis.corp.example/api/public/ca/install-linux.sh | sudo bash
```

The script pins the CA fingerprint (it requires `curl` and `openssl`), installs the CA into the system trust
store (Debian/Ubuntu, RHEL/Rocky/Fedora, SLES) and exports `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`NODE_EXTRA_CA_CERTS` in `/etc/profile.d/aegis-proxy-ca.sh`. It does not configure proxy settings:

```bash
# login shells and many tools (no credentials here - world-readable)
sudo tee -a /etc/environment <<'EOF'
http_proxy=http://aegis-proxy.corp.example:8080
https_proxy=http://aegis-proxy.corp.example:8080
no_proxy=localhost,127.0.0.1,.corp.example
HTTP_PROXY=http://aegis-proxy.corp.example:8080
HTTPS_PROXY=http://aegis-proxy.corp.example:8080
NO_PROXY=localhost,127.0.0.1,.corp.example
EOF
# apt
echo 'Acquire::http::Proxy "http://aegis-proxy.corp.example:8080"; Acquire::https::Proxy "http://aegis-proxy.corp.example:8080";' \
  | sudo tee /etc/apt/apt.conf.d/95aegis-proxy
# dnf
echo 'proxy=http://aegis-proxy.corp.example:8080' | sudo tee -a /etc/dnf/dnf.conf
# systemd services (docker, containerd, kubelet, ...): drop-in with Environment=HTTPS_PROXY=... NO_PROXY=...
```

Java needs the CA in its `cacerts` (`keytool -importcert -cacerts -alias aegis -file aegis-enterprise-ca.crt`).
The worker also serves the CA and installers via the magic host: `curl -x http://proxy:8080 http://aegis.ca/`.

**Windows servers**: GPO (Trusted Root CA + `netsh winhttp set proxy`) or
`$env:AEGIS_PROXY='aegis-proxy.corp.example:8080'; iwr -UseBasicParsing https://aegis.corp.example/api/public/ca/install-windows.ps1 | iex`
- see [`windows.md`](windows.md#10-rolling-out-the-ca-and-proxy-settings-to-client-servers).

---

## 11. Upgrades

| Component | Procedure |
|---|---|
| Control-plane | `sudo ./deploy/systemd/install-linux.sh --component control-plane --binary <new>` (restarts the service; workers keep enforcing meanwhile) |
| Console | rebuild `frontend/dist`, re-run with `--ui-dir` (atomic directory swap) |
| Data-plane | re-run with `--component data-plane` and the new `data-plane` folder; a new Python minor version recreates the venv; mitmproxy upgrades via the pinned version / `--requirements` |
| Unit files | re-running the installer overwrites them; keep local changes in drop-ins (`systemctl edit ...`) |
| Cluster | one node at a time, wait for `/readyz`; control-plane before workers |

Version: `aegis-control-plane version`, `GET /api/public/meta`, `aegis_build_info` on `/metrics`.

---

## 12. Backup and restore

| Data | Path | Notes |
|---|---|---|
| State (file mode) | `/var/lib/aegis/data/aegis_state.json` (+ `.bak`) | written atomically (rename), safe to copy while running |
| Audit trail | `/var/lib/aegis/data/audit.jsonl` (+ rotated `*.gz`) | append-only; ship to the SIEM in real time |
| Secrets | `/etc/aegis/secrets/` | JWT, data-plane key, DSN, TLS key, ... |
| CA | `/etc/aegis/ca/` (`mitmproxy-ca.pem` = private key) | loss = new CA on every client |
| Configuration | `/etc/aegis/*.env`, `/etc/systemd/system/aegis-*` | |
| PostgreSQL | database `aegis` | `pg_dump -Fc -d aegis -f aegis-$(date +%F).dump` |

```bash
sudo tar --numeric-owner -czf /backup/aegis-$(date +%F).tgz /etc/aegis /var/lib/aegis/data /var/lib/aegis/certs
```

Encrypt backups (they contain the CA key) and test restores. Restore: `systemctl stop aegis-control-plane`,
extract with `--numeric-owner` (UIDs of `aegis` must match, or `chown -R aegis:aegis /var/lib/aegis`), re-run the
installer, start, verify `/healthz` and the CA fingerprint. Cluster: `pg_restore -c -d aegis <dump>` plus
`/etc/aegis` on every node.

---

## 13. Monitoring and logs

* Control-plane: `/healthz`, `/readyz` (DB in cluster mode), `/metrics` (bearer token from
  `/etc/aegis/secrets/metrics-token`; nginx additionally restricts `/metrics`).
* Worker: `http://127.0.0.1:9091/{healthz,readyz,metrics}` (`AEGIS_OPS_ADDR`).
* Logs: `journalctl -u aegis-control-plane -u aegis-dataplane` (JSON lines for the control-plane). Retention via
  `journald.conf` (`SystemMaxUse=`), forwarding via your log shipper. `audit.jsonl` is rotated monthly
  (24 months) by `/etc/logrotate.d/aegis` by renaming (`nocreate`, the control-plane reopens the file) and
  additionally by size inside the control-plane (`AEGIS_AUDIT_ROTATE_MB`, default 256 MB); see
  [Operations → audit trail](../operations.md).

```yaml
scrape_configs:
  - job_name: aegis-control-plane
    scheme: https
    authorization: { credentials_file: /etc/prometheus/aegis-metrics.token }
    static_configs: [{ targets: ['aegis.corp.example'] }]
  - job_name: aegis-dataplane
    static_configs: [{ targets: ['dp-01.corp.example:9091', 'dp-02.corp.example:9091'] }]
```

Suggested alerts: target down; worker `/readyz` failing; `aegis_dp_policy_sync_age_seconds > 300`;
`increase(aegis_dataplane_auth_failures_total[5m]) > 0`; `aegis_dp_clamd_available == 0`;
`aegis_threatintel_feed_age_seconds` too old; rising `aegis_security_events_open`; systemd unit in `failed` state
(node_exporter `node_systemd_unit_state`).

---

## 14. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| Clients: `certificate verify failed` / `unable to get local issuer certificate` | CA not trusted, or runtime with own trust store | `install-linux.sh` from `/api/public/ca/`; Java `cacerts`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` |
| All proxied requests return **503** | worker has no policy yet (fail-closed) | `curl -s 127.0.0.1:9091/readyz`; `journalctl -u aegis-dataplane`; control-plane log `rejected data-plane request with invalid key` (**401**) → `dataplane.key` differs; re-run with the correct `--dataplane-key-file` |
| Worker cannot reach the control-plane | firewall, URL, untrusted certificate | `curl -v https://aegis.corp.example/healthz` as root; `AEGIS_CONTROL_PLANE_CA_FILE` |
| Security events `AV_ERROR` | clamd down/unreachable, socket permissions, `StreamMaxLength` exceeded | `systemctl status clamav-daemon` / `clamd@scan`; check `AEGIS_CLAMD_ADDRESS`; align limits; `av_fail_mode` decides allow+event vs. 503 |
| Unit fails with `status=243/CREDENTIALS` | a `LoadCredential=` source file is missing | re-run the installer (regenerates the drop-in) or restore the secret |
| Control-plane fails: `read-only file system` / CA errors | `/var/lib/aegis/certs/mitmproxy-ca-cert.pem` missing (read-only by design) | re-run the installer (republishes the public certificate) |
| `status=203/EXEC` on RHEL | SELinux label of the venv | `semanage fcontext -a -t bin_t '/opt/aegis/data-plane/venv/bin(/.*)?' && restorecon -RF /opt/aegis` |
| nginx `502` and AVC denials | SELinux blocks nginx → 8081 | `semanage port -a -t http_port_t -p tcp 8081` or `setsebool -P httpd_can_network_connect 1` |
| TLS handshakes through the worker fail while `/readyz` is 200 | `MemoryDenyWriteExecute=yes` added to the data-plane unit | remove it (section 4) |
| Allowed URL blocked for one server | server not identified (NAT, missing IP/subnet, wrong token) | check the flow in the console; fix identity; no SNAT at load balancers |
| Console loads but live traffic does not update | proxy buffering on the SSE stream | use the provided nginx location for `/api/flows/stream` |

Run the control-plane in the foreground with its configuration for debugging:

```bash
sudo systemctl stop aegis-control-plane
sudo systemd-run --pty --uid=aegis --gid=aegis -p EnvironmentFile=/etc/aegis/control-plane.env \
     -p LoadCredential=jwt:/etc/aegis/secrets/jwt.key -p LoadCredential=dataplane:/etc/aegis/secrets/dataplane.key \
     -p StateDirectory=aegis -E DATA_DIR=/var/lib/aegis/data -E CERTS_DIR=/var/lib/aegis/certs \
     /bin/sh -c 'AEGIS_JWT_SECRET_FILE=$CREDENTIALS_DIRECTORY/jwt AEGIS_DATAPLANE_KEY_FILE=$CREDENTIALS_DIRECTORY/dataplane AEGIS_LOG_FORMAT=text exec /usr/local/bin/aegis-control-plane'
```

---

## 15. Security hardening checklist

- [ ] `AEGIS_PUBLIC_URL` is `https://`; nginx (or native TLS) with a PKI certificate; HSTS active.
- [ ] `AEGIS_LISTEN_ADDR=127.0.0.1:8081` behind a local nginx; `AEGIS_TRUSTED_PROXIES` lists exactly the proxies/LBs.
- [ ] Admin password changed, password files removed, personal accounts with least privilege, `AEGIS_DEMO_MODE=false`.
- [ ] `/etc/aegis/secrets` 0700 and files 0600 root; `/etc/aegis/ca/mitmproxy-ca.pem` 0600 root; no secrets in `*.env`.
- [ ] Units unchanged or changed only via drop-ins; `systemd-analyze security aegis-control-plane aegis-dataplane` reviewed.
- [ ] Firewall: proxy port only from server subnets, console only from admin networks/workers/LBs, ops/metrics only from monitoring.
- [ ] `/metrics` protected (token + nginx ACL).
- [ ] Data-plane installed from a hash-pinned, mirrored package set (`--requirements`, `--pip-args "--no-index --find-links ..."`).
- [ ] SELinux enforcing (RHEL) with the documented labels; AppArmor/SELinux denials monitored.
- [ ] `AEGIS_FAIL_MODE=closed`; Protection Policy reviewed (threat intel and AV `block`, `block_private_destinations`, `block_raw_tcp`, `allowed_ports`).
- [ ] ClamAV signatures auto-updated; `StreamMaxLength` ≥ `av_max_scan_bytes`.
- [ ] CA fingerprint verified out-of-band; CA key backed up encrypted and offline.
- [ ] Audit log forwarded to the SIEM; backups encrypted; restore tested.
- [ ] Proxy tokens distributed via configuration management in non-world-readable files and rotated.
- [ ] OS patching and time synchronisation (chrony/systemd-timesyncd) active on all hosts.
