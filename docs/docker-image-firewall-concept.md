# AegisProxy: container-image firewall (OCI/Docker)

This document is a product and architecture concept. It describes extending the
**package firewall** shipped in AegisProxy 3.0 (npm, PyPI, NuGet, PowerShell
Gallery) to **container images** (Docker Hub, GHCR, GCR, ECR, Quay, Azure CR,
private registries). The image features are not yet implemented. The starting
point is the existing 3.0 engine (`internal/packages`, `internal/coordinator`,
`internal/sandboxworker`, and the data-plane gate
`data-plane/aegis_dp/packages.py`) and the shipped
[package firewall](package-firewall.md).

## The idea holds up — an image is a bundle of packages

A container image is not a new problem but an aggregation of familiar ones: it
consists of one or more **base images**, a stack of **layers**, and the
**software inventory** inside them — operating-system packages (apk/dpkg/rpm)
and language packages (exactly the npm/PyPI/NuGet we already resolve and
assess). The approval decision is the same as for libraries: pull a concrete,
immutable version, inspect its artifacts, and decide which projects may use it
under which conditions. Images are even better built for this than libraries,
because they are **content-addressed**: every pull references a `sha256:…`
digest. "Only approved digests are pullable" is a sharper and more honest
statement than metadata filtering on npm.

The retrospective product goal stays the same and becomes especially valuable:
**which hosts/clusters have pulled an image (or a layer) that is now
affected?** The 3.0 receiver view (`/packages/receivers`) is extended with
image digests and layer digests to answer this.

## What we reuse — and what is new

| Building block | Status |
|---|---|
| Assessment model, advisory/CVSS (`internal/packages/advisory`), rules + grace period (`rules.go`), approvals/blocks, receiver view, review console | **reusable**, image as another "ecosystem" (`oci`) |
| Language-package resolver (npm/PyPI/NuGet) for the image's contents | **reusable** |
| Sigstore verifier (`internal/packages/provenance`) | **reusable** → cosign image signatures and attestations, same public-good trust root |
| Sandbox worker with the Docker driver (`internal/sandboxworker`), URL/syscall/file capture | **reusable** — the unit of analysis here *is* a container |
| Re-audit/watch loop + alerts (`internal/coordinator`) | **reusable** — re-check digests against current advisories |
| Registry-v2 gate (intercept manifest/blob fetches, approve per digest) | **new** |
| OS-package resolver (apk / dpkg / rpm) + SBOM generation | **new** |
| Base-image/layer graph and its presentation | **new** |

Roughly 60–70 % of the engine carries over; what is genuinely new is the gate
path, the OS-package inventory, and the image-graph resolution.

## The gate: intercepting OCI Distribution (registry v2) transparently

The client pulls an image over the standardized registry API, and those same
hosts already route through the proxy:

1. `GET /v2/<name>/manifests/<ref>` — manifest list (multi-arch) or image
   manifest. `<ref>` is a tag **or** a digest.
2. `GET /v2/<name>/manifests/<digest>` — the platform-specific manifest (config
   digest + layer digests).
3. `GET /v2/<name>/blobs/<digest>` — config blob (JSON) and layer blobs
   (compressed tarballs).

The gate decides **per digest**: an approved image is the set of its approved
config and layer digests. The enforcement mode is "allow the pull of an approved
digest, reject everything else" — not metadata rewriting as with npm, but an
allow/deny decision at the manifest/blob level. Because tags are mutable, the
policy pins **digests**; tags are only resolved as a request form and logged.
Unknown digests (as with libraries) raise a request or are rejected, depending
on the mode (`off` / `monitor` / `enforce`).

Practical points we must plan for honestly:

- **Authentication:** registries use bearer-token flows (`WWW-Authenticate` →
  token endpoint). The gate must pass the flow through, not break it.
- **Size:** layers are large (often hundreds of MB). The existing streaming
  hash-pin and the size limits of the 3.0 artifact check must be raised and
  made streaming-capable for images; blobs are hashed in transit, not buffered.
- **Multi-arch:** a manifest list points to several platform-specific
  manifests; approvals apply per platform digest.
- **Mirrors/pull-through:** many environments use registry mirrors; the
  per-ecosystem host configuration (`hosts`/`file_hosts`) covers this.

## The image graph: base images, layers, contents

Analogous to a library's dependency graph, for an image we resolve:

- **Base image(s)** via the `org.opencontainers.image.base.name` /
  `…base.digest` labels, or the `history`/`rootfs` fields of the image config.
  This makes "this app image inherits a vulnerable `debian:bookworm` layer"
  visible.
- **Layers** as content-addressed nodes (digest, size, originating build step).
- **Software in the image** via SBOM: OS packages (apk/dpkg/rpm — **new
  resolvers/parsers**) and language packages (**existing resolvers**). Generated
  either by a built-in scanner pass or, if present, a shipped SBOM attestation
  (SPDX/CycloneDX via cosign).

The result is a graph whose nodes map exactly onto the existing
`PackageAssessment` — CVEs per component, severity/CVSS, malware verdict.

## Inspection: advisories, signatures, date, behavior

- **Advisories/scan:** the SBOM inventory is checked against the configured
  sources (OSV covers OS and language ecosystems). Established image scanners
  can additionally be plugged in (Trivy, Grype, Syft/Scout, Clair) — their
  findings map onto the same advisory model. OS-distro advisories
  (Debian/Alpine/RHEL security trackers) supply the correct "fixed-in" context.
- **Signatures/provenance:** cosign signatures and attestations (keyless/Fulcio
  or keyed), SLSA provenance, and SBOM attestations — verified via the existing
  Sigstore verifier. Docker Content Trust (Notary v1) optional for older setups.
- **Date/grace:** the image config carries a `created` date; the existing grace
  logic for "new tag/digest" applies unchanged. Rule: auto-approve new image
  versions, but only after the grace period and only with no open findings.
- **Behavior (sandbox):** the sandbox worker's Docker driver runs the image in a
  controlled way and records — as for packages — all **web URLs/DNS/
  connections**, **syscalls**, processes, and file accesses. For images this is
  especially natural, since the unit of analysis is a container anyway. Stated
  honestly: a quiet run is not exculpatory evidence (time-/trigger-driven
  malware).

## Traceability: who pulled which image/layer?

The data plane writes one telemetry record per pull with the image reference,
resolved digest, layer digests, and a stable server/workload identity. The
receiver query then answers: "which hosts pulled `repo@sha256:…` or a layer
`sha256:…`?" — including hits from pull-through caches. Same caveat as in 3.0:
the in-memory window is bounded; the full history lives in the log export/SIEM.

## What protection we actually achieve — and what we do not

| Threat | What the image firewall contributes |
|---|---|
| Known vulnerable OS/language component in the image | Check SBOM against current advisories; block affected digests; re-audit existing approvals |
| Malicious/compromised base or app image | Verify signature/provenance, assess contents, observe behavior, serve only approved digests |
| Mutated tag (`:latest` suddenly points elsewhere) | Policy pins digests; a new digest behind a known tag forces a fresh approval |
| Runtime fetch of binary code | Egress rules + sandbox capture of URLs/syscalls; approval ≠ runtime carte blanche |
| Post-incident investigation | Receiver view: which hosts/clusters pulled the affected digest/layer |

What the image firewall does **not** do: it does not remove an already-running
image, stop a running container, or replace runtime security (admission
controllers, in-cluster runtime sensors). It controls **acquisition** and makes
exposure traceable — in-cluster enforcement (e.g. "only approved digests may
start") is a complementary, separate integration (OPA/Gatekeeper, Kyverno,
admission webhook) that can build on the same approval data.

## Proposed stages

1. **MVP — visibility (monitor):** detect registry-v2 traffic and record pulls
   as telemetry (image/layer digests, receivers). SBOM + advisory scan per
   pulled digest. Console: image requests, graph (base/layer/contents),
   findings. No blocking yet.
2. **Enforcement:** digest-based allow/deny at the gate; approvals/blocks/rules
   + grace period for images; cosign verification.
3. **Behavior + operations:** sandbox run of the image (URLs/syscalls/files),
   re-audit/watch + alerts (existing loop infrastructure), optional
   admission-controller export of the approval list for Kubernetes.

## Open decisions

- Own scanner pass vs. a mandatory Trivy/Grype integration (licensing/operational
  cost, offline capability).
- Enforcement granularity: per image digest, per layer digest, or both (layer
  blocks hit many images at once — powerful, but with broad blast radius).
- Handling very large layers in the sandbox/hash path (timeouts, size caps,
  streaming).
- Relationship to existing registry/mirror systems (Harbor, Artifactory, ECR
  pull-through): sit in front of vs. integrate with.
- Kubernetes enforcement: export approval data only, or ship an own admission
  webhook.
