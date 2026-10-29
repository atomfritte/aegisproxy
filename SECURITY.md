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

### Building images yourself

An image contains what its build context contains, so build only from a checkout that nobody else can write to,
ideally a fresh clone at a verified tag. Release and CI images are built from a fresh checkout. Three measures
keep unreviewed files out of self-built images:

- The `.dockerignore` files of the four build contexts are allowlists of the tracked files
  (`scripts/gen-dockerignore.sh`, enforced in CI). A file that git does not track, for example one hidden from
  `git status` by `.gitignore` or `.git/info/exclude`, never reaches the builder: a `vendor/` directory or
  `go.work`, a package directory or extension module that Python would import instead of a reviewed module, a
  `postcss.config.js`/`.npmrc`, or a file under `frontend/public/` that Vite would copy into the console.
- The Go builds run with `GOFLAGS=-mod=readonly GOWORK=off`: only the modules verified against `go.sum` are
  compiled.
- `make images` builds from the committed tree (`git archive HEAD`, or `IMAGE_REV=<tag>`), never from the working
  copy, and refuses `.dockerignore` files that do not match that tree. Uncommitted changes are reported and not
  built.

Changes to tracked files are not covered by any of this. `docker build <dir>` and `docker compose build` send the
working copy, so run `git status` first and expect it to be clean, or use `make images`.

Releases are signed with cosign 3 (Sigstore bundle format); verify with cosign 3.0 or newer.

Dependencies are monitored with Dependabot, govulncheck, pip-audit, npm audit and Trivy in CI. Every GitHub
Action is pinned to a commit SHA (Dependabot proposes updates), analysis tools run in pinned versions, and the
Trivy scanner image, the BuildKit image and the charts/manifests downloaded by the Kubernetes CI job are pinned
by digest or SHA-256. Pull requests fail on fixable critical/high vulnerabilities in any of the four images.
The data-plane image ships without pip/setuptools. `data-plane/requirements-lock.txt` pins every Python
dependency of the data-plane (including transitive ones) with SHA-256 hashes; the Linux installer installs from
it with `--require-hashes` by default, and the CI audit runs pip-audit (itself installed hash-locked) against the
installed environment and against every pin of the lock, including the Windows, macOS and CPython 3.12/3.13-only
entries, of the image overrides (`requirements-image.txt`, `requirements-extra.txt`) and of the console regression
suite's lock (`frontend/e2e/requirements.txt`). It also audits the package directories copied out of the built
data-plane image (`scripts/audit-image-python.sh`), so the packages of the mitmproxy base image are covered and a
medium, low or unrated advisory fails the build, not only the fixable critical/high findings that Trivy gates on.
`npm audit` covers the build toolchain of the console as well as its runtime dependencies.
Where mitmproxy's version bounds exclude a security fix of a dependency, `data-plane/requirements-security.txt`
installs the fixed release (currently Brotli 1.2.1 for CVE-2026-111497 and tornado 6.6 for CVE-2026-116577, CVE-2026-115927 and
CVE-2026-116578; tornado serves only mitmweb, which the worker does not run) in the image, in both installers and in the
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
