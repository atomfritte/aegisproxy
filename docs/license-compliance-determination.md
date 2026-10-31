# License-compliance determination — can AegisProxy be sold commercially?

**Date:** 2026-10-31 · **Scope:** AegisProxy 3.0.0 (`main`) · **Question:** May we
dual-license AegisProxy and sell it under a commercial license?

## Determination

**Yes.** AegisProxy can be offered under a paid commercial license and sold. No
strong-copyleft component (GPL or AGPL) is linked into, combined with, or bundled
inside any shipped AegisProxy artifact. Every dependency that *is* shipped is
either permissive (MIT / BSD / ISC / Apache-2.0 / PostgreSQL) or weak-copyleft
(LGPL / MPL) used in a way those licenses explicitly allow. All of AegisProxy's
own code is first-party, so we are free to license it under both the PolyForm
Noncommercial 1.0.0 terms and a separate commercial license.

The obligations below are the standard, fully satisfiable conditions that come
with redistributing OSS commercially. None is a blocker; most are already met by
the way the product is built.

## How we checked

Per shipped artifact — because an obligation only attaches to code we actually
distribute:

| Artifact | What we ship | License posture |
|---|---|---|
| Control-plane binary | Go deps in `control-plane/go.mod` / `go.sum` | **100% permissive** — `jackc/pgx` + helpers MIT, `golang.org/x/*` BSD-3-Clause, test-only deps ISC/Apache-2.0. No copyleft. |
| Console bundle | npm deps in `frontend/package-lock.json` | **100% permissive** — React/React-DOM/scheduler MIT, lucide-react ISC, Tailwind/Vite MIT, TypeScript Apache-2.0. "UNLICENSED" in `package.json` is our *own* root package, not a dependency. |
| Data-plane image | Python deps in `data-plane/requirements-lock.txt` | Permissive + **weak-copyleft** (LGPL `ldap3`, `urwid`; MPL `certifi`). **No GPL/AGPL.** Windows-only LGPL packages (`pydivert`, `mitmproxy-windows`) are gated out by env markers. |
| Runtime services | ClamAV, HAProxy, PostgreSQL images | Run as **separate processes**, operator-pulled; mere aggregation. |
| Threat-intel feeds | feed *data*, fetched at runtime | Not redistributed by us; non-commercial/copyleft feeds ship **disabled by default** (test-enforced). |

First-party code we own (the control-plane, the data-plane addon, the console,
sandbox runners, docs) carries no inbound third-party license, so we can
dual-license it at will. The `CONTRIBUTING.md` CLA keeps future contributions
compatible with commercial relicensing.

## Obligations to satisfy (all standard, none a blocker)

1. **LGPL (`ldap3` LGPL-3.0, `urwid` LGPL-2.1) in the data-plane image.**
   Ship them unmodified as ordinary pip packages (dynamically imported, not
   combined into our source — already the case); include the notice + license
   text; make the corresponding source available for the shipped versions
   (they are on PyPI at the pinned versions, plus a 3-year written offer on
   request); and impose no barrier to a recipient swapping in a modified build
   (trivially true for pip modules). → documented in `THIRD-PARTY-NOTICES.md`.

2. **MPL-2.0 (`certifi`).** File-level copyleft: make that component's source
   available under the MPL; our own files are MPL §3.3 "Larger Work" files and
   stay under our license. `publicsuffix2` is dual MIT-or-MPL — we elect MIT.
   → documented in `THIRD-PARTY-NOTICES.md`.

3. **GPL runtime services (ClamAV GPL-2.0, HAProxy GPL-2.0).** Keep them as
   **separate processes** reached over a network/IPC protocol (ICAP, the
   PostgreSQL wire protocol) and pulled as their own images — never statically
   or dynamically linked into an AegisProxy binary. This is mere aggregation and
   does not extend GPL to our code. → already the architecture; keep it so.

4. **Threat-intel feeds.** Keep non-commercial / copyleft feeds
   (`CC BY-NC 4.0`, `GPL-3.0`, `CERT.PL`) disabled by default (enforced by
   `control-plane/internal/threatintel/threatintel_test.go`), and tell commercial
   operators to review a feed's upstream terms before enabling it. We redistribute
   no feed data, so the obligation is the operator's at enable-time, not ours at
   ship-time.

5. **Notices with the distribution.** Ship `THIRD-PARTY-NOTICES.md` and the
   bundled components' license texts with the product (image layer / release
   archive). → file maintained; wire it into the release artifact.

## What would have been a blocker (and isn't present)

- **AGPL** anywhere in a shipped artifact — none.
- **GPL linked/combined** into an AegisProxy binary — none (ClamAV/HAProxy are
  separate services; no GPL Go/Python module is imported).
- **A "non-commercial" or "no-derivatives" license on code we ship** — none; the
  only non-commercial terms are on *optional threat-feed data* that ships disabled
  and that we do not redistribute.
- **Third-party code inside our own source** under an incompatible license —
  none; our code is first-party.

## Bottom line

Selling AegisProxy under a commercial license is clear. The only standing duties
are the ordinary redistribution notices and source-availability for the LGPL/MPL
Python packages, keeping the GPL services as separate processes, and keeping
restrictive threat feeds off by default — all already in place or captured in
`THIRD-PARTY-NOTICES.md`. This is an engineering determination recorded for
diligence, not a legal opinion; have counsel confirm before a commercial launch.
