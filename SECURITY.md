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

Release images are built in CI from tagged sources (BuildKit pinned by digest), scanned again after the push
(Trivy, the pushed digest must have no fixable critical/high vulnerability before it is signed), signed with
Sigstore cosign (keyless), and published with SBOM and SLSA build-provenance attestations. They are published
only under `ghcr.io/atomfritte/aegisproxy-<component>` (`control-plane`, `control-plane-api`, `data-plane`,
`console`); images of the same name in any other registry or namespace are not ours. A published release tag
is never pushed again.

Every GitHub release carries two assets, both attested by the release workflow:
`aegisproxy-vX.Y.Z-image-digests.txt` (one `ghcr.io/atomfritte/aegisproxy-<component>@sha256:<digest>` line per
image) and `aegisproxy-X.Y.Z.tgz` (the Helm chart with `controlPlane.image.digest`, `dataPlane.image.digest` and
`console.image.digest` filled in). Verify the exact signer, the release workflow of this repository at the
release tag (an identity regexp that accepts any `v*` tag, or `--owner`, would also accept a workflow that a
writer changed for another tag), then deploy by the digest you verified, not by tag:

```bash
cosign verify ghcr.io/atomfritte/aegisproxy-control-plane@sha256:<digest> \
  --certificate-identity https://github.com/atomfritte/aegisproxy/.github/workflows/release.yml@refs/tags/vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/atomfritte/aegisproxy-control-plane@sha256:<digest> --repo atomfritte/aegisproxy \
  --signer-workflow atomfritte/aegisproxy/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
gh attestation verify aegisproxy-X.Y.Z.tgz --repo atomfritte/aegisproxy \
  --signer-workflow atomfritte/aegisproxy/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
```

The Helm chart supports pinning images with `*.image.digest`; the chart attached to the release has the digests
filled in (docs/deployment/kubernetes.md#images). Docker Compose never pulls AegisProxy images: it builds them
from the checkout (`pull_policy: build`) and pins every third-party image by digest.

Releases are signed with cosign 3 (Sigstore bundle format); verify with cosign 3.0 or newer.

Dependencies are monitored with Dependabot, govulncheck, pip-audit, npm audit and Trivy in CI. Every GitHub
Action is pinned to a commit SHA (Dependabot proposes updates), analysis tools run in pinned versions, and the
Trivy scanner image, the BuildKit image and the charts/manifests downloaded by the Kubernetes CI job are pinned
by digest or SHA-256. Pull requests fail on fixable critical/high vulnerabilities in any of the four images.
The data-plane image ships without pip/setuptools. `data-plane/requirements-lock.txt` pins every Python
dependency of the data-plane (including transitive ones) with SHA-256 hashes; the Linux installer installs from
it with `--require-hashes` by default, and the CI audit runs pip-audit (itself installed hash-locked) against the
installed environment and against every pin of the lock, including the Windows, macOS and CPython 3.12/3.13-only
entries, and of the console regression suite's lock (`frontend/e2e/requirements.txt`).
Where mitmproxy's version bounds exclude a security fix of a dependency, `data-plane/requirements-security.txt`
installs the fixed release (currently Brotli 1.2.1, CVE-2026-111497) in the image, in both installers and in the
lock.

### Repository settings required for release integrity

The signer identity proves that an image was built by `.github/workflows/release.yml` for a given tag, not who
wrote that workflow or tag: anyone with write access can change the workflow on a branch and push a `v*` tag,
and the release workflow's own checks (tag matches the product version, image tag not yet published) can be
edited away the same way. These repository settings are the actual controls. On a private repository, tag
rulesets, protected branches and environment reviewers need a paid GitHub plan (Pro, Team or Enterprise);
without them the release integrity rests on who has write access.

- **Tag ruleset for `refs/tags/v*`**: only release managers (bypass list) may create tags; update (moving a tag)
  and deletion are blocked for everyone.
- **Branch protection** (or a branch ruleset) for the release branches (`aegisproxy-2.1`, the default branch):
  pull requests with at least one approving review and the CI checks required, no force pushes, no deletion,
  administrators included.
- **Environment `release`** with required reviewers (other than the person who pushed the tag, "Prevent
  self-review"), and its deployment restricted to tags `v*`. The publish and release-asset jobs run in it, so
  nothing is pushed, signed or released before a second person approved the run.
- **Actions**: default workflow permissions read-only (the workflows declare what they need), and GitHub
  Actions may not create or approve pull requests.
