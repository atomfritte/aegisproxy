# gosec triage

`gosec` raised **172 findings** across the Go control-plane (183 files, ~57k lines). Every rule category
was reviewed in context. **None is a real vulnerability** — they are the expected pattern noise a
security-focused linter produces on code that deliberately does file I/O, crypto, subprocess execution and
operator-configured networking. The raw output is in [`scans/gosec.txt`](scans/gosec.txt).

Disposition legend: **FP** = false positive · **by-design** = intentional and safe in context.

| Rule | Count | What gosec flags | Disposition & rationale |
|---|---:|---|---|
| G104 | 57 | Unhandled error | by-design — deferred `Close()` on reads, best-effort writes to an already-failed response, and explicit `_ =` ignores. None drops an error that changes a security decision. |
| G115 | 29 | Integer overflow on conversion | FP — DB `revision`/sequence `int64↔uint64`, byte/size conversions in parsers and the DNS/wire encoders, all within domain-bounded ranges. |
| G304 | 28 | File path from a variable | by-design — CA/cert/UI/config/sandbox paths that come from the operator's configuration or a cleaned, root-scoped request path, not from untrusted free input. |
| G301 / G302 / G306 | 23 | Dir/file permission bits | by-design — `0700/0600` for secrets and data dirs, `0755/0644` for public assets; deliberate. |
| G115 (HIGH subset) | — | int↔uint on DB rows | FP — `aegis_config`/`aegis_package_work` revisions and audit `seq` are monotonic small integers. |
| G124 | 5 | Cookie missing Secure/HttpOnly/SameSite | FP — the session cookie sets all three (`setSessionCookie`); `Secure`/`SameSite` are **configurable** (relaxable for localhost dev, enforced in prod) so gosec can't prove the constant. |
| G101 | 5 | Potential hardcoded credentials (LOW) | FP — non-secret constants: `tokenIssuer`, the `aegis_scim_` token **prefix**, the `••••••` mask, `private_key_jwt`, an OIDC header name. |
| G704 | 4 | SSRF via taint | by-design — the log-export drivers POST to the **operator-configured** SIEM/webhook; the loopback healthcheck `GET`s `127.0.0.1`. Destinations are set by a trusted admin. |
| G703 | 3 | Path traversal via taint | FP/by-design — static files use `filepath.Join(root, Clean("/"+path))` (neutralizes `..`); the others read operator-configured file paths. |
| G404 | 3 | Weak RNG (math/rand) | by-design — demo-traffic generation and retry jitter, never for tokens/keys (those use `crypto/rand`). |
| G204 | 3 | Subprocess launched with a variable | by-design — the sandbox worker launches `docker`/`firecracker`/the runner with **argument slices** (no shell), with controlled image/path args. |
| G705 | 2 | XSS via taint | by-design — block-page **preview** served under `Content-Security-Policy: default-src 'none'`; input is the authenticated admin's own template. |
| G402 | 2 | InsecureSkipVerify | by-design — one loopback liveness probe (already `//nolint`); one operator opt-in for a self-signed SIEM endpoint. |
| G710 | 1 | Open redirect | FP — in `oidc/oidctest` (a **test** mock IdP), not production code. |
| G505 / G401 | 2 | SHA-1 import / weak primitive | by-design — RFC 7515-mandated `x5t` certificate thumbprint for OIDC `private_key_jwt` (`x5t#S256` SHA-256 is also emitted). |
| G203 | 1 | HTML not auto-escaped | by-design — block-page rendering of operator-authored templates; output is served with the restrictive block-page CSP. |
| G122 | 1 | Symlink TOCTOU in `filepath.Walk` | by-design — inside the disposable sandbox analysing untrusted code; the isolation boundary is the throwaway container/microVM. Noted as a possible `os.Root` hardening. |
| G118 | 1 | `context.Background` in a goroutine | by-design — the long-lived audit-verify background loop is not request-scoped. |
| G117 | 1 | Marshaled field matches a secret pattern | FP — `signature()` marshals the export-sink struct only to SHA-256 it for a config signature; the bytes are never logged or returned. |
| G110 | 1 | Decompression bomb | FP — gunzips the control-plane's **own** gzip output back to the client, not untrusted input. |

## Why not add 172 `#nosec` comments?

Peppering the code with suppressions would hurt readability and hide future real findings. The findings
above are documented here instead, as an auditable record. The genuinely actionable issues surfaced by the
Go toolchain are caught by **staticcheck** and **govulncheck**, which gate the build in CI and are kept at
zero (the three staticcheck findings from this run were fixed — see [README.md](README.md)).

If a team wants gosec in CI with a clean baseline, run it with
`-exclude=G104,G115,G301,G302,G306` (the bulk, by-design categories) and review anything new in the
remaining rules against this document.
