# AegisProxy Enterprise

Zero-trust **egress gateway for server fleets** — a default-deny HTTP(S) proxy built on mitmproxy with
path-level whitelisting, self-service access requests, layered threat protection and a highly available Go
control-plane.

```
servers ──http(s)_proxy──▶ data-plane (mitmproxy + Aegis addon) ──▶ internet
                               │ policy, threat intel, telemetry
                               ▼
                         control-plane (Go, 1..N replicas) ◀── console (React) / API
                               │
                         file storage  or  PostgreSQL (HA)
```

## Features

**Policy management** ([guide](docs/policy-management.md))
- **Policy sets**: versioned rule collections per server group, server or the whole fleet (baseline), with owners,
  tags, priorities and recertification dates.
- **Change management**: drafts, rule-level diffs, impact simulation against recorded traffic, optional
  **four-eyes review** via change requests, emergency publish, version history and one-click rollback.
- **Access request workflow**: SLA, assignment, discussion, bulk review, granted durations, extend and revoke.
- **Fleet management**: labels and label-based dynamic groups, onboarding snippets, CSV import/export,
  discovery of unregistered sources, effective-policy view per server, **quarantine** for incident response.
- **Branded block pages** per group (logo, colors, texts in English/German, support contacts, offered
  self-service options) with live preview.

**Fine-grained egress policy**
- Default deny; ALLOW/BLOCK rules with host + path patterns (`github.com/microsoft/**`), method lists,
  companions and expiry.
- **Redirect lineage**: an allowed request that redirects to a CDN object (`objects.githubusercontent.com/…`)
  authorizes exactly that object for two minutes — no need to open the whole CDN.
- **Learning sessions**: record a reference server, compile the traffic into rules, publish to whole groups.
- **TLS no-break exceptions** for pinned/mTLS endpoints, scoped by group, never for strict-isolation tiers.

**Self-service with verified identity**
- Browser block page and CLI message with a **data-plane–signed block token**; access requests are routed to
  InfoSec / Team Leads (Microsoft Teams, Slack) and approved with RBAC.

**Threat protection** ([details](docs/threat-protection.md))
- Threat-intelligence feeds (abuse.ch, Spamhaus DROP, Emerging Threats, URLhaus domains, …) + custom IOCs
  for domains, URLs, IPs/CIDRs and file hashes — checked on host names, URLs, **resolved IPs** and downloads.
- Your threat-intelligence platform via **TAXII 2.1 / MISP**, and **Microsoft Defender for Endpoint** indicators.
- **ClamAV**, **YARA** (YARA-X) and **ICAP** to commercial antivirus, sandbox and DLP engines; **download control**
  by file type, **DLP** for secrets in outbound requests, anomaly detection for block bursts.
- **Defender device risk / isolation** and SOAR playbooks quarantine compromised servers at the proxy.
- Protocol guard: no raw TCP through CONNECT, Host/SNI consistency (domain fronting), DNS-rebinding
  protection with IP pinning, cloud-metadata and internal ranges blocked, IP-literal and port policy.

**Enterprise operations**
- **Identity** ([details](docs/identity.md)): single sign-on with Microsoft Entra ID or any OIDC provider (PKCE,
  group-based roles and scopes, just-in-time provisioning), alerted break-glass accounts, expiring and
  CIDR-restricted **service accounts** for automation.
- RBAC (Super Admin, InfoSec, Team Lead, Auditor), tamper-evident audit trail with complete export, secrets
  encrypted at rest (AES-256-GCM, key rotation), **security posture** score, interception CA issued by the
  corporate PKI.
- **Log export** ([details](docs/log-export.md)): audit, traffic ("browsing") and security records to syslog
  (rsyslog, syslog-ng, QRadar LEEF, ArcSight CEF), OpenTelemetry (OTLP), Splunk HEC, Elasticsearch/OpenSearch,
  Microsoft Sentinel, Datadog, Grafana Loki, signed webhooks and files — batched, with a durable spool
  (at-least-once). Squid-format access logs on every worker. Microsoft Sentinel solution (Bicep, ASIM parsers,
  analytics rules, workbook, quarantine playbook) and a Splunk CIM add-on.
- Active-active control-plane on PostgreSQL, stateless data-plane workers, Prometheus metrics, health probes,
  graceful draining.
- Deployment options: Docker Compose, Compose HA, Kubernetes (Helm + CloudNativePG), Linux (systemd),
  Windows Server (native service) — console bundled or hosted separately.

## Quick start (Docker Compose)

```bash
cp .env.example .env
./scripts/gen-secrets.sh >> .env
docker compose up -d --build
docker run --rm -v aegisproxy_aegis-data:/data alpine cat /data/secrets/initial-admin-password
```

Open http://127.0.0.1:8081 and sign in as `admin`. Then point a test server at `http://<host>:8080` and install
the CA with `curl -fsSL http://<host>:8081/api/public/ca/install-linux.sh | sudo bash`.

Want sample data? Set `AEGIS_DEMO_MODE=true` on a fresh volume (public demo credentials — evaluation only).

## Documentation

| Topic | Document |
|---|---|
| Architecture, policy evaluation, HA design, data storage | [docs/architecture.md](docs/architecture.md) |
| Policy sets, change management, requests, fleet, block pages | [docs/policy-management.md](docs/policy-management.md) |
| Log export to SIEM / observability platforms | [docs/log-export.md](docs/log-export.md) |
| Deployment options and sizing | [docs/deployment/](docs/deployment/README.md) |
| Docker Compose · HA · Kubernetes · Linux · Windows · separate console | [compose](docs/deployment/docker-compose.md) · [HA](docs/deployment/high-availability.md) · [Kubernetes](docs/deployment/kubernetes.md) · [Linux](docs/deployment/linux.md) · [Windows](docs/deployment/windows.md) · [console](docs/deployment/separate-console.md) |
| Configuration reference (all environment variables) | [docs/configuration.md](docs/configuration.md) |
| Threat protection: threat intel, TAXII/MISP, Defender, YARA, ICAP, DLP, quarantine | [docs/threat-protection.md](docs/threat-protection.md) |
| Identity: single sign-on, break-glass accounts, service accounts | [docs/identity.md](docs/identity.md) |
| Security model, encryption at rest, fixed findings, hardening checklist | [docs/security.md](docs/security.md) |
| Threat model (STRIDE) | [docs/threat-model.md](docs/threat-model.md) |
| Compliance mapping (ISO 27001, NIST SP 800-53, BSI IT-Grundschutz, SOC 2) and auditor checklist | [docs/compliance.md](docs/compliance.md) |
| Operations: rollout, monitoring, audit trail, posture, backup, upgrades, key rotation, corporate PKI, troubleshooting | [docs/operations.md](docs/operations.md) |
| API reference | [docs/api.md](docs/api.md) |
| Tests and verification | [docs/testing.md](docs/testing.md) |

## Repository layout

```
control-plane/        Go control-plane (API, store, threat intel, auth)
data-plane/           mitmproxy addon (aegis_dp package), entrypoint, tests
frontend/             React/TypeScript console (+ nginx image for separate hosting)
deploy/compose/ha/    HA reference deployment (PostgreSQL, HAProxy, 2+2 replicas)
deploy/helm/          Helm chart
deploy/systemd/       Linux units, env templates, installer
deploy/windows/       Windows service installers, WinSW template, IIS config
deploy/nginx/         TLS reverse-proxy example
docs/                 documentation
scripts/              helper scripts (secret generation)
```

## Development

```bash
make test                      # Go (race), Python, frontend build, Helm lint
make build                     # binaries + console
make images                    # container images
npm --prefix frontend run dev  # console dev server on :5173 (proxies /api to :8081)
```

Requirements: Go ≥ 1.26, Python ≥ 3.12 with mitmproxy 12.3 (data-plane), Node ≥ 22, Docker.
