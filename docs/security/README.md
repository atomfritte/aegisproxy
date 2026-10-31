# Security scanning & evidence

This directory is the auditable record of how AegisProxy is scanned for security and quality issues,
what the scanners found, and what we did about each finding. Everyone on the team (and external
reviewers) can reproduce every scan from the commands below and compare against the saved reports in
[`scans/`](scans/).

All scans below run against `main` at the 3.0.0 line (see Git history for when
each was last refreshed).

## TL;DR

| Tool | Scope | Result |
|---|---|---|
| **govulncheck** | Go control-plane, reachable CVEs | ✅ No vulnerabilities |
| **staticcheck** | Go control-plane, correctness | ✅ Clean (3 findings fixed, see below) |
| **gosec** | Go control-plane, security | 172 raised → **0 real** (all false-positive / by-design, [triaged](gosec-triage.md)) |
| **npm audit** | console dependencies | ✅ 0 vulnerabilities |
| **pip-audit** | data-plane / CI / e2e locked deps | ✅ No known vulnerabilities |
| **Trivy** | repo filesystem: deps, secrets, IaC | ✅ 0 CVEs, 0 committed secrets; only sandbox-image hardening notes |
| **SonarQube** | multi-language (Go/Python/TS) | ✅ **0 bugs, 0 vulnerabilities, 0 hotspots** (Security A · Reliability A · Maintainability A); 1224 maintainability smells tracked as backlog |

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

### Results (SonarQube 26.8, project `aegisproxy`, 94,402 ncloc)

Full summary in [`scans/sonarqube-summary.txt`](scans/sonarqube-summary.txt). After the fixes and
false-positive triage below: **Security A · Reliability A · Maintainability A**, 0.0 % duplication.

| | Raised | Open after triage | How handled |
|---|---:|---:|---|
| **Bugs** | 33 | **0** | 23 fixed in code (missing sort comparators, `S2871`); 10 marked false-positive (a11y `S1082`) |
| **Vulnerabilities** | 8 | **0** | all false-positive / by-design (see below), marked with a justification in SonarQube |
| **Security hotspots** | 0 | 0 | — |
| **Code smells** | 1224 | 1224 | maintainability/style backlog (see below) — not security or reliability |

- **Bugs fixed (`S2871`, 23):** `.sort()` on string arrays (team/OS/tag/actor/category lists) now use an
  explicit `String(a).localeCompare(String(b))` comparator for reliable, locale-correct ordering.
- **Bugs — false positive (`S1082`, 10 a11y):** "clickable element needs a keyboard listener" — these are
  items inside keyboard-navigable widgets (`Menu`, `Select`, `CommandPalette`, `TagInput`) that handle keys
  at the **container** level (roving focus + `aria-activedescendant` + container `onKeyDown` for
  Arrow/Enter/Space, per WAI-ARIA), or mouse propagation guards around already-accessible controls. Adding
  element-level handlers would be inert. Marked false-positive in SonarQube with that justification.
- **Vulnerabilities — all false positive / by-design (8):** TLS cert+hostname verification is **on by
  default** (`ssl.create_default_context`), disabled only on explicit operator opt-in for a self-signed
  local ICAP endpoint (`icap.py`); the `controlplane.py` context is the secure default (FP); the `http://`
  URLs are the **CA-bootstrap** help text (you cannot use HTTPS before trusting the CA — integrity is via
  out-of-band SHA-256) and the forward-**proxy URL** convention (`http://proxy:8080`, even for HTTPS via
  CONNECT). Consistent with govulncheck / gosec / Trivy all finding no real issue.
- **Code smells (1224):** maintainability/style only — nested ternaries (272), cognitive complexity > 15
  (337 across Go/TS/Python), duplicated string literals (83), array-index React keys, etc. The sqale
  rating is **A** (low debt ratio), there are **0.0 %** duplicated lines, and none is a security or
  reliability defect. Refactoring 1224 opinionated findings would be high-churn, high-risk change against
  an already-A-rated codebase, so they are kept as a tracked maintainability backlog rather than force-fixed.

> The scan ran against a dedicated SonarQube+PostgreSQL stack (`aegis-sonar` + `aegis-sonar-db` on the
> `aegis-sonar-net` network, console on `http://localhost:9001`); your pre-existing `sonarqube-server` was
> left untouched. Remove the stack with `docker rm -f aegis-sonar aegis-sonar-db && docker network rm
> aegis-sonar-net`, or re-run anytime with the commands above.

## Continuous scanning

These are not one-offs — the same gates run on every change in `.github/workflows/ci.yml`
(govulncheck + staticcheck gate the Go build; pip-audit gates the Python locks; Trivy scans the release
images) and Dependabot keeps the dependencies current (`.github/dependabot.yml`). See also
[docs/security.md](../security.md) and [SECURITY.md](../../SECURITY.md).
