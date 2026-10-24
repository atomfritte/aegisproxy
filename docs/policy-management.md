# Policy management

This guide covers the day-to-day management workflows introduced in AegisProxy 2.1: policy sets, change
management with four-eyes review, recertification, the access request workflow, fleet management
(labels, dynamic groups, quarantine, onboarding, bulk import) and branded block pages.

## Concepts at a glance

| Concept | What it is |
|---|---|
| **Policy set** | A named, versioned collection of ALLOW/BLOCK rules with an owner, tags, a priority and an assignment. Rules inherit the assignment of their set. |
| **Baseline set** | A policy set that applies to every registered server (and every source that belongs to a group). Typical use: global guardrails (paste sites, tunnels) and universally allowed patch sources. Only InfoSec and Super Admins manage baseline sets. |
| **Standard set** | Assigned to server groups and/or individual servers. Team Leads can manage sets of their own groups. |
| **Approvals set** | System-managed, one per group (`approvals-<group>`): every approved access request adds a rule here. Revoking or extending the request changes the rule. |
| **Draft** | The working copy of a set. Drafts are never enforced. |
| **Version** | An immutable snapshot created on every publish (the last 30 per set are kept). Rollback publishes — or prepares as a draft — an earlier version. |
| **Change request** | A frozen draft submitted for review, including a rule-level diff and an impact simulation against recorded traffic. |
| **Recertification** | Each set has a review interval (default 90 days). Owners periodically confirm the set is still needed; overdue sets are highlighted on the overview page. |
| **Dynamic group** | A server group with a label selector (`match_labels`); every server whose labels match becomes a member automatically. |
| **Quarantine** | Incident-response switch that blocks every destination for one server. |
| **Block page template** | Branding, texts, contact data and self-service options of the page (and CLI text) shown when a request is blocked. Assigned per group. |

The policy engine and the data-plane still enforce one flat, compiled rule list (`GET /api/rules`). Policy
sets are the editing model on top: publishing a set recompiles the effective rules and every worker picks
up the new revision within seconds.

## Policy sets

### Creating a set

Console → **Policy sets → New policy set**:

1. Choose the kind (standard or baseline), name, description, owner team and tags.
2. Assign server groups and/or servers (standard sets). Groups can be static or label-based.
3. Set the priority (higher sets are listed and evaluated first; BLOCK rules always win regardless of
   priority) and the recertification interval.
4. Add rules in the draft — or clone the rules of an existing set as a starting point.

A new set has version 0 until it is published for the first time.

### Rules

| Field | Notes |
|---|---|
| Action | `ALLOW` or `BLOCK`. BLOCK rules are guardrails and always take precedence. Team Leads cannot create, change or remove BLOCK rules — they can still edit ALLOW rules in a set that contains InfoSec guardrails. |
| Host pattern | `github.com`, `*.ubuntu.com`, an IP address. Catch-all `*` ALLOW rules require a Super Admin; Team Leads cannot use top-level wildcards (`*.com`). |
| Path pattern | `/microsoft/**` (`/microsoft` and everything below), `/simple/*` (exactly one segment below `/simple`), `/repos/*/releases/**`, exact paths — see [Path patterns](#path-patterns). |
| Methods | Default `GET, HEAD` (least privilege). |
| Follow redirects | Authorizes the exact object a matching response redirects to (e.g. GitHub release assets on a CDN) for two minutes — for the server that made the request only (the grant belongs to its server identity, not to its source address), and never for members of strict-isolation groups. |
| Redirect targets | Optional with *Follow redirects* (`redirect_hosts`): host patterns (`objects.githubusercontent.com`, `*.cdn.example`) the redirect may lead to. Empty = any public host; internal destinations never receive a grant. Set it for rules on sites whose redirects the destination operator (or its users) can steer. |
| Companion rules | Additional `host/path` patterns that belong to the same purpose (`codeload.github.com/acme/**`). |
| Expiry | Optional; expired rules are ignored by the engine. |

### Path patterns

The path of a request is canonicalized before matching: the query string and fragment are ignored,
percent-encoding is decoded, dot-segments (`/a/../b`) and repeated slashes are resolved and a trailing slash is
dropped; malformed paths (NUL bytes, backslashes, broken escapes) never match. The pattern is canonicalized the
same way. Then:

| Pattern element | Matches | Example |
|---|---|---|
| `/**` as a whole segment | zero or more segments | `/acme/**` matches `/acme`, `/acme/x`, `/acme/x/y`, not `/acmex`; `/a/**/b` matches `/a/b` and `/a/x/y/b` |
| `*` as a whole segment | exactly one non-empty segment | `/simple/*` matches `/simple/requests` and `/simple/requests/`, not `/simple`, `/simple/` or `/simple/a/b` |
| `*` inside a segment | any characters except `/` | `/v*.json` matches `/v1.json`, not `/v1/x.json` |
| `**` inside a segment | any characters including `/` | `/release-asset-**` matches `/release-asset-2e65/9981/x.tar.gz` |
| no wildcard | the exact path | `/simple` matches `/simple`, `/simple/` and `/simple?x=1` |

`/**`, `*` and an empty pattern cover the whole host. Only such domain-wide BLOCK rules can block an HTTPS tunnel
at `CONNECT`; path-specific BLOCK rules are enforced on the decrypted requests. Control-plane and data-plane run
the same matcher (shared test vectors in `testdata/path_vectors.json`); matching takes linear time, so hostile
request paths cannot slow it down.

**Changed in 2.1.** Earlier releases treated a trailing `/*` like `/**` (the prefix and every deeper path) and a
trailing `x*` as a plain prefix. The first start of 2.1 rewrites such patterns to `/**` and `x**`, which keeps
every rule's meaning, in published sets, drafts, the version history (so a rollback restores the same meaning),
change requests, pending access requests and learning-session candidates. The audit event
`POLICY_PATH_PATTERNS_MIGRATED` lists every rewritten pattern (before → after). Patterns with a `*` elsewhere in
the path (`/repos/*/releases`) were compared literally before and are wildcards now; they are listed with
`review: true` in the same event — check them. The rule editor flags a pattern ending in `/*` with its one-segment
meaning.

### Publishing and four-eyes review

Settings → **Governance** controls the workflow:

| Setting | Effect |
|---|---|
| `require_policy_review` = off (default) | Authors publish their drafts directly. Every publish is versioned and audited. |
| `require_policy_review` = on | Drafts are published only through an approved **change request**. The submitter — and whoever last edited the draft — cannot approve. Super Admins can publish an **emergency change** with a written justification; it is flagged in the version history and the audit trail. |

Workflow with review enabled:

```
edit draft ──► submit (title, description) ──► change request (diff + impact, draft locked)
                                                 │ approve (second person) ──► published as new version
                                                 │ reject ──► draft unlocked for rework
                                                 └ withdraw (author / InfoSec) ──► draft unlocked
```

Reviewers see:

- **Diff** — added, removed and modified rules (field by field) and changed set settings.
- **Impact** — the recorded traffic window replayed against the current and the proposed policy:
  how many requests would be newly allowed or newly blocked, on how many servers, with samples. Only
  requests decided by rules are replayed (threat-protection verdicts do not change with rules).
- **Discussion** — comments from any role, including auditors.

Further governance settings:

| Setting | Default | Effect |
|---|---|---|
| `request_sla_hours` | 24 | review deadline of new access requests |
| `default_review_interval_days` | 90 | recertification interval pre-filled for new policy sets (0 on a set = no recertification) |
| `max_temporary_access_days` | 30 | longest access a Team Lead can grant |
| `daily_digest` | on | once per day (after 08:00 server time) a Teams/Slack summary: pending and overdue requests, changes awaiting review, overdue recertifications, temporary access expiring within 24 hours, quarantined servers |
| `prune_expired_after_days` | 7 | expired temporary access is removed from approvals sets after this grace period (audited as `APPROVALS_PRUNED`; 0 = keep) |

A change request whose set changed in the meantime (for example because an access request added a rule to
an approvals set) becomes **superseded** on approval; the author resubmits.

### History, comparison and rollback

The **History** tab lists every kept version with author, time, change request and summary. Any two versions
can be compared. **Rollback** publishes the selected version directly — or, with review enabled, loads it into
the draft so it goes through a change request like any other change. Deleting a set keeps its versions in the
audit trail.

### Policy as code

Policy sets can be kept in Git and promoted between installations (test → production):

```bash
# export all sets (or ?id=ps-…&id=ps-… for a selection)
curl -s -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/policy-sets/export > policy-sets.json
# review the plan, then apply: changes become drafts that are published or submitted for review as usual
jq '{dry_run: true, bundle: .}' policy-sets.json | curl -s -H "$J" -H "Authorization: Bearer $TOKEN" \
  https://aegis-test.corp.example/api/policy-sets/import -d @-
```

Sets are matched by ID, then by name; the plan shows a rule-level diff per set (`create`, `update`,
`unchanged`). Imports are all-or-nothing and subject to the same validation and RBAC as edits in the console;
with four-eyes review enabled a second person still approves every imported change.

Bundles exported by 2.1 carry `"path_syntax": 2`. A bundle without it (exported by an earlier release) is treated
as written for the old path syntax: patterns ending in `/*` or `x*` are rewritten to `/**` and `x**` on import, so
they keep their meaning, and the plan diff shows the result. Add `"path_syntax": 2` to bundles you write by hand.

### Recertification

Each set shows `review state`: **ok**, **due soon** (14 days) or **overdue**. Owners open the set and choose
**Recertify** (optionally with a comment); the confirmation is recorded in the audit trail and the next due date
is calculated from the set's interval. Approvals sets are recertified the same way; temporary access expires on
its own.

## Access requests

Requests come from the block page or the CLI one-liner and are attested by the data-plane (signed block
token). The inbox (Console → **Access requests**) supports:

| Feature | Details |
|---|---|
| SLA | `due_at` = creation + `request_sla_hours` (governance). Overdue requests are counted on the overview page and in the navigation badge. |
| Assignment | Assign a request to a reviewer who can approve for its groups; "assigned to me" filter. |
| Discussion | Comments are kept with the request. |
| Review | Adjust host/path patterns, methods, redirect following, target groups and the **granted duration** (`1h 8h 24h 7d 30d 90d permanent`) before approving. Team Leads can grant at most `max_temporary_access_days` and never permanent access. |
| Bulk review | Approve or reject many requests with their requested scope and duration. |
| Extend / revoke | Approved requests can be extended (new expiry) or revoked (rules removed immediately). |
| Notifications | New requests, decisions and change requests are posted to Teams/Slack with deep links into the console. |

Approval adds one rule per target group to the group's **approvals set** and publishes it immediately — the
approval itself is the review. Learning-session requests start a 15-minute session for the server instead.

## Fleet management

### Labels and dynamic groups

Servers carry free-form labels (`env=prod`, `tier=web`, `compliance=pci`). A group with
`match_labels: {compliance: pci}` contains every server labelled `compliance=pci` in addition to its statically
assigned members; `*` as value matches any value of the key. Effective memberships are shown per server
(static and dynamic separately) and are what the engine, RBAC and the data-plane use.

### Onboarding

**Servers → Register** creates the inventory entry; **Rotate token** issues the proxy token (shown once) and
copy-paste snippets for Linux (CA trust, `/etc/aegis-proxy.env`, apt/dnf proxy, verification) and Windows (CA
trust, machine-wide proxy variables, WinHTTP). Set `AEGIS_PROXY_ADDRESS` to the address servers use as their
proxy so the snippets are correct. WinHTTP cannot send credentials — register the server IP for Windows
services that rely on WinHTTP.

### Proxy tokens and shared addresses

A server is identified by its proxy token when the client sends one, otherwise by its registered IP address
(details in [architecture.md](architecture.md#server-identity)). Proxy credentials that identify no server — an
unknown, rotated or mistyped token, a token sent with another server's user name, a user name from an address that
is not the server's — are refused with **HTTP 407** (`Proxy-Authenticate: Basic`, verdict `AUTH_FAILED`, block
reason `invalid_proxy_token`) and a block page/CLI text explaining how to fix the proxy URL. The request is never
attributed to the source address instead; the attempt is recorded as a medium security event.

Learning sessions and redirect grants belong to the server ID. Servers behind one NAT address therefore cannot use
each other's grants once they authenticate with their own tokens; a client behind that address **without** a
token is still identified as the server registered for the address. Groups with **Require proxy token**
(`require_proxy_token`) close that gap: their members are identified only by a valid token. A request from a
member's address without a token is treated as unregistered (default deny), a proxy user name alone is refused
with 407 (`proxy_token_required`), and the group cannot have CIDR ranges. Issue tokens (**Onboard** /
**Rotate token**) before enabling it; the group form lists members that have none.

Strict isolation also binds temporary grants: learning sessions and redirect grants never open anything for a
member of a strict-isolation group, even a session started before the server joined the group.

### Discovery

**Servers → Discovered** lists sources seen in traffic that are not registered (unknown sources and
`srv-auto-*` CIDR matches) with first/last seen, request and block counts, top destinations and user agents.
Register them with one click (prefilled ID and IP).

### Import and export

Bulk registration from a CMDB: CSV with the header
`id,hostname,ip,subnet_cidr,proxy_auth_user,group_ids,labels,os,department,owner_team,description`
(`group_ids` separated by `;`, `labels` as `k=v;k=v`; only `hostname` is required). Always run the
**dry run** first: it shows per row whether the server would be created or updated and every validation error.
Imports are all-or-nothing. Exports (CSV/JSON) never contain token digests; free-text columns are
protected against spreadsheet formula injection.

### Effective policy

The server detail page answers "what may this server do?": effective groups, every policy set that applies and
why (baseline, group, direct assignment), its rules with hit counters, the TLS exceptions in scope, the block
page template and the blocked file types.

### Quarantine

For incident response, **Quarantine** blocks every destination of one server immediately (verdict
`QUARANTINED`, no self-service on the block page, security event and Teams/Slack alert). Team Leads can
quarantine servers of their groups; only InfoSec and Super Admins can release a quarantine. Both actions
require a reason and are audited.

## Block pages

Console → **Block pages** contains the template designer with a live preview (browser page and CLI text,
English and German, policy block and threat block, desktop and phone width).

| Section | Options |
|---|---|
| Branding | company name, logo (PNG/JPEG/GIF/WebP/SVG ≤ 200 KB, embedded as data URL), primary and accent color, theme (auto/light/dark) |
| Texts | title, message, threat message, footer; blank lines create paragraphs; variables `{company} {hostname} {ip} {url} {host} {method} {trace_id} {groups} {verdict} {reason}` |
| Help | support contact (label, e-mail, phone, URL) and up to six links (intranet policy, service desk) |
| Self-service | request form on/off, offered scopes and durations (enforced by the request API for servers using the template) |
| Sections | technical details, suggested rule, root CA installation |
| CLI | header and footer lines for terminal clients (`curl`, `apt`, `pip`, …) |
| Language | default locale; the browser's `Accept-Language` selects English or German when available |

Assign templates to groups in the group editor; servers without an assigned template use the default
template. Threat-protection and quarantine blocks always use the "threat" variant without a request form.

Security properties: templates are rendered by the control-plane with contextual escaping; workers only insert
HTML-escaped request values in a single pass; pages are served with a per-response nonce CSP that only allows
the inline form script and connections to the control-plane; links must be `http(s)`.

## Roles and permissions

| Action | Super Admin | InfoSec | Team Lead | Auditor |
|---|---|---|---|---|
| Baseline sets | ✓ | ✓ | – | read |
| Standard sets of own groups (ALLOW rules) | ✓ | ✓ | ✓ | read |
| BLOCK rules | ✓ | ✓ | – | read |
| Approve change requests | ✓ (not own) | ✓ (not own) | ✓ for own groups (not own) | comment |
| Emergency publish | ✓ | – | – | – |
| Governance settings, block pages, groups, servers | ✓ | ✓ | – | read |
| Quarantine / release | ✓ / ✓ | ✓ / ✓ | own groups / – | – |
| Approve requests | ✓ | ✓ | own groups, temporary only | – |

## Migrating from 2.0

On the first start, 2.1 converts the flat rule list into policy sets (schema version 3):

- rules with a `*` scope become the **Global baseline** set,
- rules created by approved access requests become the approvals set of their group,
- all other rules are grouped by identical scope into sets named after their groups or servers,
- hit counters are preserved, every migrated set is published as version 1 and tagged `migrated`.

Review the generated sets afterwards: rename them, merge sets with related purposes, set owners and tags.
See [operations.md](operations.md#upgrading-from-20) for the upgrade procedure.

Schema version 4 (2.1) then rewrites path patterns to the new wildcard syntax (`/x/*` → `/x/**`, `x*` → `x**`)
and records `POLICY_PATH_PATTERNS_MIGRATED`; see [Path patterns](#path-patterns).
