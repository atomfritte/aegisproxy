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

## Data plane — Python (`data-plane/requirements-lock.txt` is authoritative)

| Component | License |
|---|---|
| mitmproxy (HTTPS interception engine) | MIT |
| `mitmproxy-rs`, `mitmproxy-linux` (native helpers) | MIT |
| yara-x (YARA-X Python bindings, optional) | BSD-3-Clause |
| mitmproxy's transitive dependencies (asgiref, msgpack, pylsqpack, wcwidth, Brotli, …) | respective OSI licenses (MIT / BSD / Apache-2.0) |
| **`ldap3`** 2.9.1 | **LGPL-3.0** — see weak-copyleft note below |
| **`urwid`** 4.0.13 | **LGPL-2.1** — see weak-copyleft note below |
| **`certifi`** (CA bundle) | **MPL-2.0** — see weak-copyleft note below |
| `publicsuffix2` | MIT OR MPL-2.0 — AegisProxy elects the **MIT** terms |

Windows-only transitive packages (`mitmproxy-windows`, `pydivert`; both LGPL)
carry `os_name == 'nt'` / `sys_platform == 'win32'` environment markers and are
**not installed into the Linux data-plane image**, so they are not distributed.

### Weak-copyleft components (LGPL / MPL)

`ldap3` (LGPL-3.0), `urwid` (LGPL-2.1) and `certifi` (MPL-2.0) are distributed
**unmodified** inside the data-plane container image as ordinary, independently
installed Python packages (dynamically imported at runtime, not statically
linked or combined into AegisProxy's own source). This is exactly the use these
licenses are written for, and it keeps AegisProxy's own code under its own
license. To honour the LGPL/MPL obligations we:

- reproduce this notice and each component's license text with the distribution;
- make the **complete corresponding source** of these three packages available
  for the versions shipped (they are published on PyPI at the pinned versions in
  `requirements-lock.txt`; on request we also provide an archive or a written
  offer valid for three years);
- impose no restriction on a recipient **replacing** these packages with a
  modified version — because they are standard pip-installed modules, a recipient
  can `pip install` a different build of `ldap3`/`urwid`/`certifi` into the image
  and re-run it; and
- for MPL-2.0 (`certifi`), make the source of that file-level component available
  under the MPL; AegisProxy's own files are "Larger Work" files under MPL §3.3 and
  remain under the PolyForm Noncommercial license.

No strong-copyleft component (GPL or AGPL) is statically or dynamically linked
into, or combined with, any AegisProxy binary, image, or source file.

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

## Threat-intelligence feeds (downloaded at runtime, not distributed by AegisProxy)

AegisProxy ships a catalogue of optional threat-intel feeds
(`control-plane/internal/threatintel/catalog.go`). The **feed data** is fetched
by the operator's own deployment from its upstream source at runtime; AegisProxy
does not redistribute any feed's contents. Feeds whose upstream terms are
non-commercial or copyleft (e.g. `CC BY-NC 4.0`, `GPL-3.0`, `CERT.PL` terms)
ship **disabled by default** — enforced by a unit test
(`threatintel_test.go`) — so a commercial deployment never silently pulls a
restrictively licensed list. Operators must review an individual feed's upstream
terms before enabling it. Feeds enabled by default are permissively licensed
(CC0-1.0, Unlicense, MIT, ET Open / BSD, or free Spamhaus DROP terms).

To regenerate a precise bill of materials, use `go list -m -json all`
(control plane), `pip-licenses` / the hash-locked `requirements.txt`
(data plane), and `npm ls --all` / an SBOM tool such as Syft (console).
