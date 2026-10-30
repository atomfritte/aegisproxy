# Changelog

All notable changes to AegisProxy are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] — unreleased

### Added

- **Package firewall** — transparent approval of npm, PyPI, NuGet and PowerShell
  Gallery packages. Clients keep using the public registries through the proxy;
  the data-plane filters registry metadata to approved versions and delivers only
  approved, hash-pinned artifacts (packages are never re-hosted).
  - Full transitive **dependency-graph resolution** with per-version risk state
    (new / update / approved / blocked).
  - **Advisory checks** (OSV and ecosystem feeds) with CVSS scoring, plus
    **signature and provenance verification** (npm registry signatures, Sigstore
    attestations, PyPI PEP 740).
  - **Behavior analysis** in a throwaway Docker/Firecracker sandbox that records
    every web URL, host, DNS name and system call a package makes while
    installing and loading, plus processes, file writes and decoy-credential
    access.
  - **Rules with a waiting period (Karenz)** and auto-approve / review / block
    actions.
  - **Periodic re-audit** that revokes approvals on new qualifying advisories or
    malware verdicts and **alerts Slack, Teams or a webhook**, linking to exactly
    which servers already pulled the affected version.
  - **Incident recall**: which servers obtained a given package version,
    reconstructed from flow telemetry (including gateway cache hits).
- Concept document for extending the firewall to **container images (OCI/Docker)**
  (`docs/docker-image-firewall-concept.de.md`), design only.

### Changed

- Adopted the **PolyForm Noncommercial License 1.0.0** (see [LICENSE](LICENSE));
  commercial use requires a separate license (licensing@broeer.org).

## [2.1.0]

- Zero-trust egress control: default-deny proxy with path-level rules, server
  identity, self-service access requests, change management, threat protection
  (threat intel, ClamAV, YARA-X, ICAP, DLP), a hash-chained audit trail, SSO/SCIM,
  SIEM export and active-active HA on PostgreSQL.

[3.0.0]: https://github.com/atomfritte/aegisproxy/tree/main
[2.1.0]: https://github.com/atomfritte/aegisproxy/tree/aegisproxy-2.1
