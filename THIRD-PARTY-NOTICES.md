# Third-party notices

AegisProxy's own source code is licensed under the [PolyForm Noncommercial
License 1.0.0](LICENSE). The components below are **not** covered by that
license — they are third-party software that AegisProxy depends on, bundles, or
runs alongside, and each remains under its own license held by its respective
authors. This file is a good-faith summary; the authoritative, complete lists
live in the dependency manifests referenced per section.

Running or distributing third-party components (for example the ClamAV or
PostgreSQL container images) is subject to their licenses, independently of
AegisProxy's license.

## Control plane — Go (`control-plane/go.mod`, `go.sum` are authoritative)

| Component | License |
|---|---|
| `github.com/jackc/pgx/v5` and `jackc/*` helpers | MIT |
| `golang.org/x/net`, `x/sys`, `x/sync`, `x/text` | BSD-3-Clause |

## Data plane — Python (`data-plane/requirements.txt` is authoritative)

| Component | License |
|---|---|
| mitmproxy (HTTPS interception engine) | MIT |
| yara-x (YARA-X Python bindings) | BSD-3-Clause |
| mitmproxy's transitive dependencies (asgiref, msgpack, pylsqpack, wcwidth, …) | respective OSI licenses (MIT / BSD / Apache-2.0) |

## Console — npm (`frontend/package.json`, `package-lock.json` are authoritative)

| Component | License |
|---|---|
| React, React DOM | MIT |
| lucide-react (icons) | ISC |
| Tailwind CSS, `@tailwindcss/vite` | MIT |
| Vite, `@vitejs/plugin-react` | MIT |
| TypeScript | Apache-2.0 |

## Runtime / container images (optional, pulled at deploy time)

| Image | Project license |
|---|---|
| `clamav/clamav` (antivirus engine, used over ICAP) | GPL-2.0 — run as a separate service, not linked into AegisProxy |
| `postgres` (optional cluster storage) | PostgreSQL License |
| `haproxy` (HA example topology) | GPL-2.0 with OpenSSL exception / LGPL-2.1 |
| `golang`, `gcr.io/distroless`, `alpine` (build/base images) | respective BSD / MIT / other OSI licenses |

ClamAV (GPL-2.0) and PostgreSQL run as **separate processes/containers** that
AegisProxy communicates with over a network protocol (ICAP, the PostgreSQL wire
protocol). AegisProxy does not statically or dynamically link their code into
its own binaries; this is mere aggregation, and their licenses apply only to
those components.

To regenerate a precise bill of materials, use `go list -m -json all`
(control plane), `pip-licenses` / the hash-locked `requirements.txt`
(data plane), and `npm ls --all` / an SBOM tool such as Syft (console).
