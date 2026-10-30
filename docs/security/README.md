# Security scanning & evidence

This directory is the auditable record of how AegisProxy is scanned for security and quality issues,
what the scanners found, and what we did about each finding. Everyone on the team (and external
reviewers) can reproduce every scan from the commands below and compare against the saved reports in
[`scans/`](scans/).

**Last full run:** 2026-10-31 · against `main` at the 3.0.0 line.

## TL;DR

| Tool | Scope | Result |
|---|---|---|
| **govulncheck** | Go control-plane, reachable CVEs | ✅ No vulnerabilities |
| **staticcheck** | Go control-plane, correctness | ✅ Clean (3 findings fixed, see below) |
| **gosec** | Go control-plane, security | 172 raised → **0 real** (all false-positive / by-design, [triaged](gosec-triage.md)) |
| **npm audit** | console dependencies | ✅ 0 vulnerabilities |
| **pip-audit** | data-plane / CI / e2e locked deps | ✅ No known vulnerabilities |
| **Trivy** | repo filesystem: deps, secrets, IaC | ✅ 0 CVEs, 0 committed secrets; only sandbox-image hardening notes |
| **SonarQube** | multi-language | ⏳ config ready; server run blocked in this environment — see [below](#sonarqube) |

**Net:** no vulnerabilities and no committed secrets across six scanners. Three real correctness findings
(staticcheck) were fixed. Everything else is documented as accepted-by-design with a rationale.

## How to reproduce

All versions match `.github/workflows/ci.yml` (the same gates run in CI). Run from the repo root.

```bash
# Go — reachable vulnerabilities, correctness, security
go -C control-plane run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go -C control-plane run honnef.co/go/tools/cmd/staticcheck@2026.2.2 -checks inherit,-ST1003,-ST1005 ./...
go -C control-plane run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -fmt=text ./...

# Console dependencies
npm --prefix frontend audit

# Python locks (--disable-pip audits the pinned set directly; the data-plane lock carries a
# deliberate tornado/mitmproxy override that a resolver would reject)
pip-audit --disable-pip --require-hashes -r data-plane/requirements-lock.txt
pip-audit --disable-pip --require-hashes -r .github/requirements-audit.txt
pip-audit --disable-pip --require-hashes -r frontend/e2e/requirements.txt

# Repo filesystem: dependency CVEs, secrets, IaC misconfig (Trivy pinned by digest, as in CI)
docker run --rm -v "$PWD:/repo:ro" -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  aquasec/trivy:0.75.0 fs --scanners vuln,secret,misconfig \
  --skip-dirs node_modules --skip-dirs .claude --skip-dirs frontend/dist --skip-dirs certs /repo
```

Raw outputs are saved in [`scans/`](scans/): `govulncheck.txt`, `staticcheck.txt`, `gosec.txt`,
`npm-audit.json`, `pip-audit.txt`, `trivy-fs.txt`.

## Findings and fixes

### Fixed (3, staticcheck)

| File | Finding | Fix |
|---|---|---|
| `internal/sandbox/runner/archive.go` | `archive/tar.TypeRegA` deprecated (SA1019) | match only `tar.TypeReg` (the reader already normalizes the deprecated flag) |
| `internal/sandbox/runner/manifest.go` | loop that only appends (S1011) | `append(..., exportsEntrypoints(...)...)` |
| `internal/store/packages.go` | `packageFirewallRawLocked` unused (U1000) | removed the dead function |

## Accepted findings (reviewed, not a vulnerability)

Each was read in context and confirmed safe. The detailed, rule-by-rule gosec triage is in
[gosec-triage.md](gosec-triage.md); the highlights:

- **gosec G402 / G704 "InsecureSkipVerify / SSRF":** the only `InsecureSkipVerify=true` is the
  loopback liveness probe in `main.go healthcheck` (already `//nolint`-annotated); the "SSRF" hits are the
  log-export drivers posting to the **operator-configured** SIEM/webhook URL — that is their job, and the
  destination is set by a trusted admin.
- **gosec G124 "insecure cookie":** the session cookie **does** set `HttpOnly`, `Secure` and `SameSite`
  (`auth_handlers.go setSessionCookie`); gosec flags it only because `Secure`/`SameSite` are configurable
  (they must be relaxable for plain-HTTP localhost dev, enforced in production via config).
- **gosec G705 "XSS":** the block-page **preview** response is served under a strict
  `Content-Security-Policy: default-src 'none'` (scripts disabled, `form-action 'none'`), and the input is
  the authenticated admin's own template.
- **gosec G401 / G505 "SHA-1":** the only SHA-1 is the RFC 7515-mandated `x5t` certificate thumbprint for
  OIDC `private_key_jwt` (the SHA-256 `x5t#S256` is also provided).
- **gosec G101 "hardcoded credentials" (LOW):** all are non-secret constants — an issuer name, a token
  **prefix**, the redaction mask `••••••`, the OAuth method name `private_key_jwt`.
- **gosec G703 "path traversal" (static files):** the console handler uses the safe
  `filepath.Join(root, filepath.Clean("/"+urlPath))` rooting pattern, which neutralizes `..`.
- **Trivy secret — local CA private key:** Trivy scans the working tree and sees the **locally generated**
  dev CA at `certs/mitmproxy-ca.pem`. It is **git-ignored** (`certs/`, `*.pem`, `*.key`) and never
  committed — `git ls-files` confirms **zero** tracked key/cert files in the repo.
- **Trivy misconfig DS-0002 (sandbox images run as root):** the npm/PyPI/NuGet/PowerShell sandbox images
  run the behaviour-analysis runner, which installs and executes **untrusted** package code and needs root
  for package installs and `strace`/ptrace. Isolation is the disposable, network-isolated container /
  Firecracker microVM boundary, not the in-container user. Tracked as a future hardening: drop privileges
  before invoking the untrusted install/load hooks. The production images (control-plane, data-plane,
  console) already run as non-root (`USER 65532`) with a `HEALTHCHECK`.
- **Trivy misconfig DS-0026 (no HEALTHCHECK on sandbox/wine images):** these are run-once throwaway images;
  a healthcheck is not meaningful.

## SonarQube

`sonar-project.properties` (repo root) is ready for a full multi-language analysis (Go control-plane,
Python data-plane addon, TypeScript console). To run it against a local SonarQube:

```bash
# A SonarQube server + its database (SonarQube 25+ requires PostgreSQL)
docker network create sonar-net
docker run -d --name sonar-db --network sonar-net \
  -e POSTGRES_USER=sonar -e POSTGRES_PASSWORD=sonar -e POSTGRES_DB=sonar postgres:17-alpine
docker run -d --name sonar --network sonar-net -p 9000:9000 \
  -e SONAR_JDBC_URL=jdbc:postgresql://sonar-db:5432/sonar \
  -e SONAR_JDBC_USERNAME=sonar -e SONAR_JDBC_PASSWORD=sonar sonarqube:community
# Wait for http://localhost:9000 to report {"status":"UP"}, log in (admin/admin), set a password,
# create a token under My Account → Security, then:
docker run --rm --network sonar-net -v "$PWD:/usr/src" \
  -e SONAR_HOST_URL=http://sonar:9000 -e SONAR_TOKEN=<token> sonarsource/sonar-scanner-cli
```

> **Status in this environment:** a fresh SonarQube could not start because the host disk is at ~92 %
> and Elasticsearch refuses shard allocation above its 90 % watermark; a pre-existing local
> `sonarqube-server` is healthy but its admin password was changed and is unknown (we do not reset a
> shared instance without the owner). Free disk below 90 % (or supply the existing instance's token) and
> run the commands above; then triage the issues/hotspots the same way as the gosec triage here.

## Continuous scanning

These are not one-offs — the same gates run on every change in `.github/workflows/ci.yml`
(govulncheck + staticcheck gate the Go build; pip-audit gates the Python locks; Trivy scans the release
images) and Dependabot keeps the dependencies current (`.github/dependabot.yml`). See also
[docs/security.md](../security.md) and [SECURITY.md](../../SECURITY.md).
