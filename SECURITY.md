# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | security fixes |
| 2.0.x | security fixes until 2027-04-30 |
| < 2.0 | no — upgrade (1.x contained critical defects, see docs/security.md) |

## Reporting a vulnerability

Please report vulnerabilities privately to the product security team (security contact of your AegisProxy
support agreement, or a private GitHub security advisory for this repository). Do not open public issues.
Include affected version, component (control-plane, data-plane, console, deployment artifact), reproduction
steps and impact. We acknowledge within 2 business days and provide a fix or mitigation plan within 30 days
for high/critical issues.

## Release integrity

Release images are built in CI from tagged sources, signed with Sigstore cosign (keyless), and published
with SBOM and SLSA build-provenance attestations:

```bash
cosign verify ghcr.io/<owner>/aegisproxy-control-plane:v2.1.0 \
  --certificate-identity-regexp 'https://github.com/<owner>/.*/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/<owner>/aegisproxy-control-plane:v2.1.0 --owner <owner>
```

Releases are signed with cosign 3 (Sigstore bundle format); verify with cosign 3.0 or newer.

Dependencies are monitored with Dependabot, govulncheck, pip-audit, npm audit and Trivy in CI. Every GitHub
Action is pinned to a commit SHA (Dependabot proposes updates), analysis tools run in pinned versions and the
Trivy scanner image is pinned by digest. Pull requests fail on fixable critical/high vulnerabilities in any of the
four images. The data-plane image ships without pip/setuptools. Where mitmproxy's version bounds exclude a
security fix of a dependency, `data-plane/requirements-security.txt` installs the fixed release (currently
Brotli 1.2.1, CVE-2026-111497) in the image, in both installers and in the CI audit environment.
