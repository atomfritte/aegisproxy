# provenance

Offline verification of registry signatures and Sigstore provenance for the package firewall
(`require_signature`, `require_provenance` in `models.PackageRule`), with the standard library only
(`crypto/x509`, `crypto/ecdsa`, `crypto/ed25519`, `encoding/asn1`).

| Function | Input | Checks |
|---|---|---|
| `ParseNPMKeys` | `GET https://registry.npmjs.org/-/npm/v1/keys` | ECDSA P-256 SPKI keys, expiry |
| `VerifyNPMRegistrySignature` | `dist.signatures`, `dist.integrity`, publish time (`time[<version>]`) | what `npm audit signatures` checks |
| `VerifyNPMAttestations` | `GET https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>` | publish attestation (registry key) and SLSA provenance (Fulcio) |
| `VerifyBundle` | Sigstore bundle v0.1 / v0.2 / v0.3 with a DSSE envelope | Fulcio-signed in-toto statement for a digest |
| `VerifyPyPIProvenance` | `GET https://pypi.org/integrity/<project>/<version>/<file>/provenance` (`Accept: application/vnd.pypi.integrity.v1+json`) | PEP 740 attestations and the Trusted Publisher |

`Options{Now: …}` injects the clock (the package functions use `time.Now`). Every error wraps one of the
`Err*` sentinels (`errors.Is`), e.g. `ErrNoSignature`, `ErrUnknownKey`, `ErrKeyExpired`, `ErrInvalidSignature`,
`ErrSubjectMismatch`, `ErrIdentityMismatch`, `ErrUnsupported`, `ErrLimit`.

## What is verified

npm registry signatures: ECDSA P-256 / SHA-256 over `<name>@<version>:<integrity>` with the key named by `keyid`.
As in npm (pacote), every listed signature must verify, at least one is required, and a key only verifies versions
published strictly before its `expires`; an unknown publish time counts as expired for an expiring key.

Sigstore bundles (and PEP 740 attestations, which are v0.3 bundles in another shape), in this order:

1. **Transparency log** (every entry, 1–10): the log ID must name a Rekor log of the trusted root whose key was
   valid at the integrated time; the integrated time must not lie more than 5 minutes in the future
   (`Options.Now`). The **signed entry timestamp** (ECDSA over the canonical JSON
   `{"body","integratedTime","logID","logIndex"}`) is required, because it is the only signature over the
   integrated time. The **inclusion proof** (RFC 6962 / RFC 9162 audit path from `SHA-256(0x00 || body)`) and its
   **checkpoint** (signed note: origin, tree size, root hash; signature line `— <name> <base64(key hint ||
   signature)>`, key hint SHA-256(DER key)[:4] for Rekor v1, the C2SP key ID for Ed25519 logs) must verify when
   present and are required for bundles v0.2 and later; the checkpoint must commit to the proof's tree size and
   root hash.
2. **Certificate**: the leaf (`verificationMaterial.certificate` or the first certificate of
   `x509CertificateChain`; other chain certificates are ignored) must chain to a Fulcio CA of the trusted root
   whose validity window contains the integrated time, with `x509.Verify` at the integrated time (Fulcio
   certificates live 10 minutes), EKU codeSigning, key usage digitalSignature, not a CA.
3. **SCT**: at least one embedded SCT must verify with a CT log of the trusted root valid at the SCT time
   (RFC 6962 precertificate entry: the TBSCertificate without the SCT list extension and SHA-256 of the issuer's
   SubjectPublicKeyInfo).
4. **Log entry ↔ bundle**: the entry body (`dsse` 0.0.1 or `intoto` 0.0.2, matching `kindVersion`) must name the
   SHA-256 of the envelope payload, exactly the envelope's signature (intoto 0.0.2 stores the base64 signature text
   base64-encoded again) and exactly the leaf certificate (or the registry key) as PEM.
5. **DSSE**: exactly one signature, payload type `application/vnd.in-toto+json`, signature over
   `PAE = "DSSEv1 <len(type)> <type> <len(body)> <body>"` with the leaf key (ECDSA P-256/P-384/P-521 with
   SHA-256/384/512, or Ed25519).
6. **Statement**: `_type` in-toto Statement v0.1 or v1; a subject must carry the expected digest
   (`DigestFromSRI` converts npm's base64 SRI into the hex sha512 that statements use). npm additionally requires the
   subject name `pkg:npm/<name>@<version>` (scope `@` percent-encoded, as npm-package-arg does), PyPI exactly one
   subject named like the file.
7. **Result**: predicate type and predicate, subjects, integrated time, log index and ID, the certified
   `Identity` (SAN, issuer and the Fulcio extensions 1.3.6.1.4.1.57264.1.1–.22, unknown ones in `Other`) and, for
   SLSA v0.2 / v1 predicates, builder ID, build type, repository, ref, workflow, commit, invocation and event.
   `Identity.Source()` is the authoritative origin (certificate); the SLSA fields are claims signed by the build.

npm attestations: the publish attestation must be signed with the npm registry key named by
`verificationMaterial.publicKey.hint`, valid at the integrated time, and its predicate must name the package and
version; the provenance must be Fulcio-signed. The listed predicate type must equal the signed one. Each present
attestation must verify; unknown predicate types are ignored.

PyPI: every attestation of every bundle must verify, have the predicate type `https://docs.pypi.org/attestations/
publish/v1` or SLSA v1, and match its bundle's Trusted Publisher with the policies of
[pypi-attestations](https://github.com/pypi/pypi-attestations) (which PyPI applies on upload), compared exactly:

- GitHub: issuer (extension .8) `https://token.actions.githubusercontent.com`, source repository URI
  `https://github.com/<repository>`, Build Config URI
  `https://github.com/<repository>/.github/workflows/<workflow>@<source digest or ref>`. The Build Config URI is
  the top-level workflow; for workflows without a reusable workflow it equals the SAN, otherwise the SAN names the
  reusable workflow (semver's npm provenance is an example).
- GitLab: issuer `https://gitlab.com`, source repository, Build Config URI
  `https://gitlab.com/<repository>//<workflow_filepath>@<digest or ref>`.
- Google: issuer `https://accounts.google.com` and the email SAN. CircleCI: issuer, optional VCS origin and ref,
  Build Signer URI of the project and pipeline definition. Other kinds: `ErrUnsupported`.
- The publisher `environment` is reported but not in the certificate, so not checked (as in pypi-attestations).

## What is not verified

- **TUF**: the trusted root is static (embedded, updated with releases). The TUF update protocol (root rotation,
  expiry, rollback and freeze protection) is not implemented; a key revoked through TUF stays trusted until the
  next release.
- **RFC 3161 timestamps and Rekor v2**: `timestampVerificationData` is ignored and timestamp authorities are not
  parsed. Since an inclusion proof does not cover the integrated time, an entry without a signed entry timestamp
  (Rekor v2 entries, `dsse`/`hashedrekord` 0.0.2) is rejected with `ErrUnsupported` instead of trusting an
  unsigned time. All npm and PyPI attestations so far (fixtures up to October 2026) are Rekor v1 entries with SETs.
- **Envelope hashes** in the log entry (`envelopeHash` of dsse 0.0.1, `hash` of intoto 0.0.2) are not
  recomputed: they hash the client's JSON serialization of the envelope, which differs between clients. The payload
  hash and the identical signature bind the content (the signature covers payload type and payload).
- **Online checks**: no Rekor lookup, no consistency proofs between checkpoints (split-view detection), no
  witnesses. The proof is checked against the checkpoint in the bundle.
- **Revocation**: Fulcio certificates are not revocable; they are short-lived and checked at the integrated time.
- Message-signature bundles (`hashedrekord`), envelopes with several signatures, RSA keys and certificates without
  a URI or email SAN are not supported.
- **Policy**: `VerifyBundle` and `VerifyNPMAttestations` establish *who* signed (`Identity`); requiring a
  particular repository or workflow for npm is the caller's policy.

## Trusted root

`trusted_root.json` is `targets/trusted_root.json` of the Sigstore public-good TUF repository
(https://tuf-repo-cdn.sigstore.dev, maintained in https://github.com/sigstore/root-signing).

| | |
|---|---|
| Downloaded | 2026-10-30 |
| TUF metadata | timestamp v821 → snapshot v166 → targets v14 (expires 2036-05-09) |
| SHA-256 | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` (6787 bytes) |
| Cross-check | identical to `targets/trusted_root.json` on the `main` branch of sigstore/root-signing |
| Contents | Fulcio CAs 2021-03-07–2022-12-31 and since 2022-04-13; Rekor `rekor.sigstore.dev` (ECDSA P-256, since 2021-01-12) and `log2025-1.rekor.sigstore.dev` (Rekor v2, Ed25519, since 2025-09-23; parsed, its entries are rejected, see above); CT logs `ctfe.sigstore.dev/test` (2021-03-14–2022-10-31) and `/2022` (since 2022-10-20); TSA (ignored) |

Update (as part of a release):

```sh
d=$(mktemp -d)
curl -sS https://tuf-repo-cdn.sigstore.dev/timestamp.json -o $d/timestamp.json   # -> snapshot version
curl -sS https://tuf-repo-cdn.sigstore.dev/<snapshot>.snapshot.json -o $d/snapshot.json  # -> targets version
curl -sS https://tuf-repo-cdn.sigstore.dev/<targets>.targets.json -o $d/targets.json      # -> trusted_root.json sha256
curl -sS https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.trusted_root.json -o $d/trusted_root.json
sha256sum $d/trusted_root.json   # must equal the hash in targets.json
curl -sS https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json | sha256sum
```

Prefer a TUF client that verifies the metadata chain from a known root (e.g. `cosign initialize` or
sigstore-python's TUF cache) over the manual download, review the diff (new or ended keys and CAs against the
Sigstore announcements), copy the file here, update the table above and run the tests.

npm's registry keys are also distributed through the same TUF repository (delegated role `registry.npmjs.org`,
target `registry.npmjs.org/keys.json`); this package takes them from the registry's keys endpoint like the npm CLI.

## Limits

Documents and bundles ≤ 4 MiB (`MaxDocumentSize`), ≤ 10 attestations per document (`MaxAttestations`), ≤ 10
certificates in a chain (`MaxCertificates`), ≤ 10 log entries per bundle, ≤ 10 registry or checkpoint signatures,
≤ 64 audit path hashes, ≤ 1024 statement subjects, ≤ 64 npm keys, checkpoints ≤ 64 KiB, ≤ 16 SCTs.

## Test fixtures

Real registry responses, downloaded 2026-10-30 (`testdata/`):

| File | Source |
|---|---|
| `npm/keys.json` | https://registry.npmjs.org/-/npm/v1/keys |
| `npm/<pkg>-<version>.json` | https://registry.npmjs.org/<name>/<version> (version document with `dist`) for `left-pad@1.3.0` (registry signature, no provenance), `semver@7.6.3` (bundles v0.2, intoto entries, SLSA v1, reusable workflow), `sigstore@1.5.0` (bundles v0.1 without inclusion proof, SLSA v0.2), `@sigstore/core@4.0.1` (scoped, v0.2 publish + v0.3 provenance, dsse entries, non-expiring key) |
| `npm/<pkg>-<version>.attestations.json` | https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version> |
| `npm/published.json` | `time[<version>]` of the full packuments |
| `pypi/<file>.provenance.json` | https://pypi.org/integrity/<project>/<version>/<file>/provenance for `sampleproject-4.0.0` (sdist, wheel), `sigstore-4.5.1` (sdist, wheel), `pip_audit-2.10.1` wheel (environment `release`) |
| `pypi/<project>-<version>.json` | https://pypi.org/pypi/<project>/<version>/json (the sha256 digests) |

The tests tamper with copies of these (digests, names, certificates, SETs, proofs, checkpoints, signatures,
publishers, limits) and add a synthetic Sigstore deployment (`synthetic_internal_test.go`) for what real bundles
cannot reach: a consistently logged invalid DSSE signature, missing or untrusted SCTs, CA / log / certificate
validity windows, Ed25519 checkpoints and P-384 / Ed25519 leaves. Fuzzing:

```sh
go -C control-plane test -run '^$' -fuzz '^FuzzVerifyBundle$' -fuzztime 20s -fuzzminimizetime 0 ./internal/packages/provenance/
go -C control-plane test -run '^$' -fuzz '^FuzzVerifyDocuments$' -fuzztime 20s -fuzzminimizetime 0 ./internal/packages/provenance/
go -C control-plane test -run '^$' -fuzz '^FuzzParsers$' -fuzztime 20s -fuzzminimizetime 0 ./internal/packages/provenance/
```
