# API reference

Base URL: `AEGIS_PUBLIC_URL`. All bodies are JSON (`Content-Type: application/json`, max 1 MiB; 16 MiB for
data-plane and IOC endpoints). Errors: `{"error": "message"}` with 400/401/403/404/409/413/429/503.

## OpenAPI specification

The complete, machine-readable description of this API (OpenAPI 3.1: every route, request and response
schemas, error codes, security schemes and the required role of each operation) is served by every
control-plane without authentication:

```bash
curl -s https://aegis.corp.example/api/openapi.yaml -o aegisproxy-openapi.yaml   # ETag / If-None-Match supported
```

The document lives in the repository at `control-plane/internal/api/openapi.yaml` and is embedded into the
binary, so it always matches the running version. Generate clients with any OpenAPI 3.1 capable generator,
for example:

```bash
openapi-generator-cli generate -i aegisproxy-openapi.yaml -g python -o aegis-client-python
openapi-generator-cli generate -i aegisproxy-openapi.yaml -g go -o aegis-client-go --package-name aegis
```

Use the `serviceAccountKey` security scheme (`Authorization: Bearer aegis_sa_…`) for integrations.
`control-plane/internal/api/openapi_test.go` fails when a route is registered without being documented (or
the document lists a route that does not exist) and checks that every `$ref` resolves, so the specification
cannot drift from the code. The tables below are a condensed overview.

## Authentication

| Client | Mechanism |
|---|---|
| Web console | `POST /api/auth/login` with header `X-Requested-With` → HttpOnly session cookie `aegis_session`. Every state-changing request must carry `X-Requested-With` (CSRF protection). |
| Single sign-on | Browser navigation to `GET /api/auth/sso/login` → IdP → `GET /api/auth/sso/callback` → session cookie ([identity.md](identity.md#single-sign-on)). |
| Automation (recommended) | **Service account** key: `Authorization: Bearer aegis_sa_…` ([identity.md](identity.md#service-accounts)). No CSRF header needed. |
| IdP provisioning (SCIM 2.0) | `Authorization: Bearer aegis_scim_…`, accepted only by `/api/scim/v2/*` (which accepts nothing else) ([identity.md](identity.md#scim-provisioning)). |
| API clients with a user account | `POST /api/auth/login` **without** `X-Requested-With` → response contains `token`; send `Authorization: Bearer <token>`. |
| Data-plane workers | `X-Aegis-DataPlane-Key: <AEGIS_DATAPLANE_KEY>` |
| Prometheus | `Authorization: Bearer <AEGIS_METRICS_TOKEN>` (if configured) |

Roles are re-checked against the live user record on every request; password changes, resets, role changes
and logouts revoke sessions. Service-account keys are checked for expiry, disabled state and the source CIDR
allowlist on every request; their actions are audited as `sa:<name>`.

## Operational

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | – | liveness |
| GET | `/readyz` | – | readiness (state + storage, draining) |
| GET | `/metrics` | metrics token | Prometheus |

## Public (anonymous, rate limited)

| Method | Path | Description |
|---|---|---|
| GET | `/api/public/meta` | product, version, demo mode, public URL, `local_login_enabled`, `sso {enabled, provider, label, login_url, local_login_enabled}` |
| GET | `/api/public/request-options[?bt=<block token>]` | what the self-service form may offer for the requesting server: `{verified, server_hostname, url, verdict, request_form, allowed_scopes, allowed_durations, company_name, support, default_locale}`; without a token the TCP source address identifies the server; 400 for an invalid or expired token |
| GET | `/api/public/ca/info` | CA subject, validity, SHA-256 fingerprint, PEM, SHA-256 of the download files (`pem_sha256`, `der_sha256`), installer hashes |
| GET | `/api/public/ca/aegis-ca.crt` · `.pem` · `.der` | CA certificate |
| GET | `/api/public/ca/install-linux.sh` | fingerprint-pinned Linux trust installer |
| GET | `/api/public/ca/install-windows.ps1` | fingerprint-pinned Windows trust installer (optional proxy setup via `$env:AEGIS_PROXY`) |
| POST | `/api/public/requests` | access request: `{block_token, requester, reason, requested_scope, duration}` (`requested_url`, `method` only without token). 201 created / 200 duplicate pending. CORS `*` without credentials. |

## Session

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | `{username, password}` → `{user, expires_at[, token]}`; 429 + `Retry-After` when throttled |
| POST | `/api/auth/logout` | revokes the session |
| GET | `/api/auth/me` | `{user, expires_at}`; with a service-account key `{service_account: {id, name, role, allowed_groups}}` |
| GET | `/api/auth/sso/login[?next=/path&login_hint=]` | starts single sign-on (302 to the IdP; 404 when SSO is disabled); `next` must be a local console path |
| GET | `/api/auth/sso/callback` | IdP redirect target; on success 302 to the console with a session cookie, otherwise to `/login?sso_error=<code>` |
| GET | `/api/auth/sso/jwks.json` | public JWKS of the `private_key_jwt` client keys (active, staged, retired within the 7-day grace period) for IdPs configured with a JWKS URL; cacheable 5 minutes |
| POST | `/api/auth/password` | `{current_password, new_password}` |

## Console API (authenticated)

JSON field names follow the Go models in `control-plane/internal/models/models.go` (snake_case).

### State and live data

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/state[?exclude_flows=1]` | any | complete console state: `groups`, `servers` (with `effective_group_ids`, `labels`, quarantine fields), `rules` (effective, compiled from policy sets), `policy_sets`, `change_requests`, `governance`, `block_pages`, `requests`, `sessions`, `tls_bypass`, `users`, `audit_events`, `security`, `bandwidth`, `stats`, `overview` (work-queue counters), `data_planes`, `proxy_address`, `me` |
| GET | `/api/flows/stream` | any | Server-Sent Events: live flows; `event: session_expired` |
| POST | `/api/simulate/request` | any | side-effect-free policy simulation `{server_ip, proxy_auth_user, method, full_url}` |

`overview` counters: `pending_requests`, `overdue_requests`, `assigned_to_me`, `open_change_requests`,
`changes_to_review`, `recertification_overdue`, `recertification_due_soon`, `drafts`, `quarantined_servers`,
`stale_servers` (missing keys mean 0; Team Leads only count requests of their groups).

### Policy sets

A **policy set** is a named, versioned collection of rules assigned to server groups and/or servers
(`kind: standard`), to every registered server (`kind: baseline`), or managed by the request workflow
(`kind: approvals`, one per group, id `approvals-<group id>`). Rules inside a set carry no scope of their own —
the set's assignment applies. Editing happens in a **draft**; publishing creates an immutable version
(the last 30 are kept). The engine and the data-plane enforce the compiled effective rule list (`GET /api/rules`).

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/rules` | any | effective (compiled) rules with `policy_set_id`, `policy_set_name`, `hit_count` |
| GET | `/api/policy-sets` | any | all sets with computed `review_due_at`, `review_state` (`ok`/`due_soon`/`overdue`) |
| POST | `/api/policy-sets` | scoped | create `{kind, spec}` → set whose content is in `draft` (version 0 = never published) |
| GET | `/api/policy-sets/export[?id=…&id=…]` | any | policy-as-code bundle `{format: "aegisproxy.policy-sets/v1", exported_at, exported_by, policy_sets[{id, kind, …spec}]}` (published content) |
| POST | `/api/policy-sets/import` | scoped | `{dry_run, bundle}` → `{results[{id, name, action: create|update|unchanged|skip|error, diff, error}]}`; sets are matched by id, then by name; changes land in **drafts** (publish or submit them as usual); all-or-nothing (422 with per-set errors); approvals sets are skipped |
| GET | `/api/policy-sets/{id}` | any | `{policy_set, versions, change_requests, draft_diff}` |
| DELETE | `/api/policy-sets/{id}?reason=` | InfoSec | delete (versions are kept) |
| PUT | `/api/policy-sets/{id}/draft` | scoped | replace the draft `{spec}`; 400 while the draft is in review |
| DELETE | `/api/policy-sets/{id}/draft` | scoped | discard the draft |
| POST | `/api/policy-sets/{id}/publish` | scoped | `{comment, emergency}` publish the draft. 409 when four-eyes review is required; `emergency: true` is allowed for Super Admins with a justification (≥ 10 characters) |
| POST | `/api/policy-sets/{id}/submit` | scoped | `{title, description}` → change request (draft is locked until decided) |
| POST | `/api/policy-sets/{id}/simulate` | any | `{spec?}` (default: draft, else published) → impact summary against the recorded traffic window |
| GET | `/api/policy-sets/{id}/diff?from=&to=` | any | references: version number, `published`, `draft` or `empty` (defaults: published → draft) |
| GET | `/api/policy-sets/{id}/versions` | any | version summaries (newest first) |
| GET | `/api/policy-sets/{id}/versions/{n}` | any | full version incl. `spec` |
| POST | `/api/policy-sets/{id}/rollback` | scoped | `{version, comment}` → `{policy_set, published}`; published directly, or prepared as a draft when review is required |
| POST | `/api/policy-sets/{id}/recertify` | scoped | `{comment}` confirm the set is still needed (resets the review due date) |

`spec` = `{name, description, owner_team, tags[], priority, enabled, group_ids[], server_ids[], review_interval_days, rules[]}`;
a rule = `{id?, name, description, action: ALLOW|BLOCK, host_pattern, path_pattern, methods[], follow_redirects, redirect_hosts[]?, companion_rules[], enabled, expires_at?}`
(`redirect_hosts`: optional host patterns redirect grants of the rule may target; omitted/empty = any public host).
Rule ids are kept across edits (send them back unchanged); new rules get an id on save. `review_interval_days: 0` disables recertification
for the set (the console pre-fills the governance default).

Impact summary: `{flows_evaluated, newly_allowed, newly_blocked, unchanged, affected_servers, target_servers, samples[{server_hostname, server_ip, method, url, before, after, rule_name}], computed_at}`.

Diff: `{metadata[] (changed set fields), rules[{op: added|removed|modified, rule_id, before?, after?, fields[]}], added, removed, modified}`.

### Change requests (four-eyes review)

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/change-requests[?status=open]` | any | newest first |
| GET | `/api/change-requests/{id}` | any | incl. `spec`, `diff`, `impact`, `reviews[]` |
| POST | `/api/change-requests/{id}/review` | scoped | `{decision: approve|reject|comment, comment}`. Approval publishes the change. The author — and whoever last edited the draft — cannot approve. Auditors may comment. 409 + `change_request` when the set changed meanwhile (status `superseded`) |
| POST | `/api/change-requests/{id}/withdraw` | author / InfoSec | unlocks the draft |
| GET · PUT | `/api/settings/governance` | any · InfoSec | `{require_policy_review, request_sla_hours, default_review_interval_days, max_temporary_access_days, daily_digest, prune_expired_after_days, last_digest_at (read-only)}` |

### Access requests

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/requests` | any | newest first; filters `status` (`pending`, `approved`, `rejected`, `revoked`, …), `assigned_to`, `server_id`, `group_id`, `overdue=true` (pending and past `due_at`), `limit` (default 500, max 5000) → `{requests, total}` (`total` = matches before `limit`) |
| GET | `/api/requests/{id}` | any | one request incl. comments; 404 when unknown |
| POST | `/api/requests/{id}/review` | scoped | `{approve, comment, host_pattern?, path_pattern?, follow_redirects, target_group_ids?, duration?, methods?}` → `{request, rules}`. Approval adds one rule per target group to that group's approvals set. Durations: `1h 8h 24h 7d 30d 90d permanent`; Team Leads are limited to `max_temporary_access_days` and cannot grant permanent access |
| POST | `/api/requests/bulk-review` | scoped | `{ids[], approve, comment}` → `{results[{id, status?, error?}]}` (requested scope/duration) |
| POST | `/api/requests/{id}/comments` | scoped | `{text}` |
| POST | `/api/requests/{id}/assign` | scoped | `{assignee}` (username, `""` = unassign; must be able to approve the request) |
| POST | `/api/requests/{id}/extend` | scoped | `{duration}` new expiry for an approved request |
| POST | `/api/requests/{id}/revoke` | scoped | `{reason}` removes the granted rules (status `revoked`) |

Request fields added in 2.1: `assigned_to`, `due_at` (SLA), `comments[]`, `created_rule_ids[]`, `expires_at`, `revoked_by`, `revoked_at`.

### Learning sessions

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/api/sessions` | scoped | start `{name, description, server_id, duration_minutes, mode}` |
| POST | `/api/sessions/{id}/stop` | scoped | stop; 409 when the session already ended |
| POST | `/api/sessions/{id}/publish` | scoped | `{candidates[], rule_prefix, policy_set_id? | new_set_name + target_group_ids[] + target_server_ids[], publish}` → `{published_count, policy_set, published}`; without `publish` (or when review is required) the rules stay in the set's draft. **409** while the session is still recording — stop it first |

Team Leads may start sessions on servers whose effective groups (static or label-selected) are in their scope.

### Fleet

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/servers` | any | inventory (last-seen refreshed from traffic) |
| POST · DELETE | `/api/servers`, `/api/servers/{id}` | InfoSec | register/update (`labels`, `description`, `owner_team`, `group_ids`, …) / decommission (also removed from policy sets) |
| POST | `/api/servers/{id}/rotate-token` | InfoSec | new proxy token (returned once) + `onboarding: {linux, windows, proxy_url, no_proxy, proxy_address}` snippets |
| POST | `/api/servers/{id}/quarantine` | InfoSec; Team Lead to quarantine own servers | `{quarantined, reason}` — quarantined servers are denied every destination (verdict `QUARANTINED`) |
| POST | `/api/servers/quarantine` | same | for SOAR/EDR playbooks: `{hostname | ip, quarantined (default true), reason}` (reason required when quarantining) → server. Host names match the FQDN or a unique short name (ambiguous short names → 400); unknown → 404 |
| GET | `/api/servers/{id}/effective-policy` | any | effective groups (static + dynamic), applied policy sets and rules, TLS exceptions, block page template, blocked file types |
| GET | `/api/servers/discovered` | any | unregistered sources seen in traffic with suggested ids, matched CIDR groups, top hosts |
| POST | `/api/servers/import` | InfoSec | `{dry_run, csv}` or `{dry_run, servers[]}` → `{results[{row, id, hostname, action: create|update|error, error}]}`; all-or-nothing (422 with per-row errors) |
| GET | `/api/servers/export?format=csv|json` | any | CSV columns: `id,hostname,ip,subnet_cidr,proxy_auth_user,group_ids,labels,os,department,owner_team,description` (`group_ids` `;`-separated, `labels` `k=v;k=v`) |
| POST · DELETE | `/api/groups`, `/api/groups/{id}` | InfoSec | groups incl. `match_labels` (dynamic membership; value `*` = any value) and `block_page_template_id` |

### Block pages

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/block-pages` | any | `{templates, default_template_id, group_templates, locales, variables}` |
| POST · PUT · DELETE | `/api/block-pages`, `/api/block-pages/{id}` | InfoSec | create / update / delete a template (the default cannot be deleted; assigned templates cannot be deleted) |
| POST | `/api/block-pages/preview` | any | `{template, locale, variant: request|threat}` → `{html, cli}` rendered with sample data (unsaved templates; for an `<iframe sandbox srcdoc>`) |
| GET | `/api/block-pages/{id}/preview?locale=&variant=&format=html|cli` | any | standalone preview of a saved template (scripts disabled) |

Template fields: `name, is_default, company_name, logo_data_url (PNG/JPEG/GIF/WebP/SVG data URL ≤ 200 KB), primary_color,
accent_color, theme (auto|light|dark), title, message, threat_message, footer_text, support{label,email,phone,url},
links[{label,url}] (≤ 6, http/https), show_request_form, show_ca_section, show_technical_details, show_suggested_rule,
allowed_scopes[], allowed_durations[], default_locale (en|de), cli_header, cli_footer`. Texts may use the variables
`{company} {hostname} {ip} {url} {host} {method} {trace_id} {groups} {verdict} {reason}`; blank lines separate paragraphs.
The browser language selects the locale when supported. Allowed scopes/durations are enforced by
`POST /api/public/requests` for servers using the template.

### Log export

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/integrations/exports` | InfoSec | `{sinks (secrets redacted, has_secret/has_client_key flags, header names with empty values), status[] (this replica: state ok/idle/retrying/error, queued, spool_records, spool_bytes, sent, failed, dropped, last_success_at, last_error), types[] (catalog: label, description, formats, endpoint_hint, secret_label, fields), export_dir, can_edit}` |
| POST | `/api/integrations/exports` | Super Admin | create a destination |
| PUT | `/api/integrations/exports/{id}` | Super Admin | update; omitted/empty `secret`, `client_key_pem` and header values keep the stored values; `clear_secret: true` removes the secret; omitting a header removes it |
| DELETE | `/api/integrations/exports/{id}` | Super Admin | delete (its spool is discarded) |
| POST | `/api/integrations/exports/test` | InfoSec | send one synthetic audit record with the given (possibly unsaved) configuration → `{ok, error?}`; secrets of the stored destination with the same `id` are used when omitted |

Destination fields: `name, type (syslog|otlp|splunk_hec|elasticsearch|sentinel|datadog|loki|webhook|file), enabled,
streams[] (audit|traffic|security), format (json|ecs|cef|leef; fixed for structured types), traffic_filter
(all|blocked|security|allowed), min_severity (low|medium|high|critical), redact_query, endpoint, transport
(udp|tcp|tls), syslog_protocol (rfc5424|rfc3164), syslog_facility, syslog_framing (octet-counting|newline), index,
source_type, labels{}, username, tenant_id, client_id, dcr_immutable_id, stream_name, authority_url,
tls_skip_verify, ca_cert_pem, client_cert_pem, secret, client_key_pem, headers{}, batch_size, flush_seconds,
spool_mb`. See [log-export.md](log-export.md).

### Identity

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/api/settings/entra` | Super Admin (person) | single sign-on configuration `{enabled, provider: entra|oidc, display_name, tenant_id, client_id, client_secret (write-only; empty or masked keeps the stored one), issuer_url, redirect_uri, scopes[], username_claim, groups_claim, group_role_map{group: role}, group_scope_map{group: [server group ids]}, allow_local_login}` → stored configuration without secret (`has_client_secret`). Read via `GET /api/state` → `entra_config` |
| POST | `/api/settings/sso/test` | Super Admin | `{}` (stored) or an unsaved configuration → `{ok, issuer, redirect_uri, signing_keys, token_endpoint_auth_methods[], jwks_uri?, warnings[]?, note}` or `{ok: false, error}` (discovery and endpoint validation) |
| GET | `/api/settings/sso/client-keys` | any role | `private_key_jwt` client keys without private keys `{keys[{kid, alg, status: active\|next\|retired, certificate_pem, x5t, x5t_s256, not_after, published_until}], jwks_uri, grace_period_hours, can_edit}` |
| POST | `/api/settings/sso/client-keys` | Super Admin (person) | `{alg: RS256\|ES256, activate?}` → 201 `{key, jwks_uri}`; the first key becomes active, later ones are staged |
| POST | `/api/settings/sso/client-keys/{kid}/activate` | Super Admin (person) | rotation: the staged key signs, the previous one is retired (private key erased, published 7 days) |
| DELETE | `/api/settings/sso/client-keys/{kid}` | Super Admin (person) | delete a staged or retired key (not the active one while `private_key_jwt` is in use) |
| GET | `/api/settings/sso/client-certificate[?kid=&format=pem\|cer]` | any role | self-signed certificate of a key (default: active) for the Entra ID upload; header `X-Certificate-Thumbprint-SHA1` |
| GET | `/api/settings/scim` | InfoSec | SCIM status `{status{enabled, tokens[], users, active_users, groups, changes, last_sync_at, last_request_at}, base_url, can_edit, docs_url?}` |
| POST | `/api/settings/scim` | Super Admin (person) | `{enabled}` |
| POST | `/api/settings/scim/tokens` | Super Admin (person) | `{name, expires_at?}` → 201 `{token, secret, base_url}` — shown once; at most 5 tokens, ≤ 730 days |
| POST | `/api/settings/scim/tokens/{id}/rotate` | Super Admin (person) | → `{token, secret}`; the old value stops working immediately |
| DELETE | `/api/settings/scim/tokens/{id}` | Super Admin (person) | revoke |
| GET | `/api/service-accounts` | InfoSec | list (no key material; `key_prefix`, `expires_at`, `last_used_at`, `last_used_ip`) |
| POST | `/api/service-accounts` | Super Admin (person) | `{name, description, role: INFOSEC_APPROVER|TEAM_LEAD_APPROVER|OPERATOR_AUDITOR, allowed_groups[], allowed_cidrs[], expires_at (≤ 730 days, default 365)}` → 201 `{service_account, api_key, note}` — the key is shown once |
| PUT | `/api/service-accounts/{id}` | Super Admin | same fields plus `disabled` |
| POST | `/api/service-accounts/{id}/rotate` | Super Admin | → `{service_account, api_key}`; the old key stops working immediately |
| DELETE | `/api/service-accounts/{id}` | Super Admin | delete |
| POST/DELETE | `/api/users`, `/api/users/{id}`, `/api/users/{id}/reset-password` | Super Admin | user management incl. `break_glass` (Super Admins only); temporary passwords are returned once; roles of SSO users (`auth_provider: oidc`) come from the IdP mapping |

### SCIM 2.0 provisioning (`/api/scim/v2`, SCIM token)

| Method | Path | Description |
|---|---|---|
| GET | `/ServiceProviderConfig`, `/ResourceTypes[/{id}]`, `/Schemas[/{id}]` | discovery (PATCH, filter ≤ 200 results, ETags; no bulk/sort/password change) |
| GET | `/Users`, `/Groups` | list with `filter` (e.g. `userName eq "a@corp.example"`, `externalId eq "…"`, `emails[type eq "work"].value eq "…"`, `displayName eq "…"`), `startIndex`, `count`, `attributes`, `excludedAttributes` |
| POST | `/Users`, `/Groups` | create (201, `Location`, `ETag`); `409 uniqueness` for a taken `userName` / group `displayName` |
| POST | `/Users/.search`, `/Groups/.search`, `/.search` | search with a `SearchRequest` body |
| GET / PUT / PATCH / DELETE | `/Users/{id}`, `/Groups/{id}` | read, replace, modify (`add`/`replace`/`remove`, Entra ID and Okta shapes), delete (204); `If-Match` / `If-None-Match` |

`active: false`, `DELETE` or the loss of the last mapped group disables the console account and revokes its
sessions immediately. Details and IdP setup: [identity.md](identity.md#scim-provisioning).

### Threat protection and integrations

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/api/security/policy` | InfoSec | threat-protection policy (full object, incl. `yara_*` and `icap_*` fields — see [configuration.md](configuration.md#security-policy-console--threat-protection--protection-policy)) |
| POST/DELETE | `/api/security/feeds`, `/api/security/feeds/{id}` | InfoSec | feeds: `{name, url, format: domains|hosts|urls|ips|sha256|taxii21|misp, category, enabled, refresh_minutes, match_subdomains, auth_header_name, auth_header_value (write-only), lookback_days, ca_cert_pem}` (built-ins: enable/refresh/auth only) |
| GET | `/api/security/yara` | any | `{rule_sets[{id, name, description, source, enabled, created_at, updated_at, updated_by}], data_planes[] (incl. yara_status)}` |
| POST · PUT · DELETE | `/api/security/yara`, `/api/security/yara/{id}` | InfoSec | create / update / delete a rule set (≤ 256 KiB each, ≤ 2 MiB and 100 sets in total, no `include`) |
| GET | `/api/integrations/defender` | InfoSec | `{config (secret redacted, has_client_secret, last_sync_at, last_sync_error, last_sync_devices, matched_servers), can_edit, permissions[]}` |
| PUT | `/api/integrations/defender` | Super Admin (person) | `{enabled, tenant_id, client_id, client_secret, api_base_url, authority_url, import_indicators, indicator_actions[], device_sync, sync_minutes (1–1440, default 5), quarantine_on_risk: off|high|medium, quarantine_on_isolation, auto_release}` |
| POST | `/api/integrations/defender/test` | InfoSec | stored or submitted configuration → `{ok, indicators | indicators_error, devices | devices_error}` |
| POST | `/api/integrations/defender/sync` | InfoSec | device sync and indicator refresh now → `{config}`; 502 with the error when Defender fails |
| GET | `/api/system/posture` | InfoSec | `{score, generated_at, checks[{id, category, title, status: pass|warn|fail|info, detail, remediation, doc_link}]}` ([operations.md](operations.md#security-posture)) |

### Other administration

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/api/tls-bypass` · `/{id}/toggle`; DELETE `/{id}` | InfoSec | TLS no-break exceptions |
| POST | `/api/settings/notifications` · `/notifications/test` | InfoSec | Teams/Slack webhook settings (URLs write-only, masked in responses) |
| GET | `/api/audit/verify` | any | `{valid, events_checked[, error]}` for the events in memory |
| GET | `/api/audit/export` | any | the **complete** audit trail as JSON Lines, oldest first (cluster: database; file mode: `audit.jsonl` and its rotated generations), streamed |
| POST | `/api/security/feeds/refresh` | InfoSec | `{id}` or `{}` for all |
| POST/DELETE | `/api/security/indicators`, `/{id}` | InfoSec | custom IOCs |
| POST/DELETE | `/api/security/exceptions`, `/{id}` | InfoSec | false-positive exceptions |
| POST | `/api/security/events/{id}/ack` | InfoSec / Team Lead (own groups) | acknowledge an event |
| POST | `/api/security/lookup` | any | `{value}` → matches across all sources |

"scoped": Super Admin / InfoSec for all groups, Team Lead for the assigned groups (no BLOCK rules, no
catch-all hosts, no baseline sets, unchanged guardrails of other roles stay untouchable).

Removed in 2.1: `POST /api/rules`, `DELETE /api/rules/{id}` and `POST /api/audit/{id}/rollback` — rules are
edited through policy sets; rollback uses policy set versions.

## Data-plane API

| Method | Path | Description |
|---|---|---|
| GET | `/api/dataplane/bundle` | policy bundle (ETag `rev-<revision>-<threat version>`, 304 when unchanged): effective rules, servers with effective groups and `quarantined`, sessions, TLS exceptions, security policy, `yara_rule_sets` and `block_pages` (template shells per locale, see [threat-protection.md](threat-protection.md#block-pages)). Headers `X-Aegis-DataPlane-ID`, `-Version`, `X-Aegis-ClamAV`, `X-Aegis-YARA`, `X-Aegis-ICAP` report the worker heartbeat (shown as `data_planes[]` with `yara_status`, `icap_status`). |
| GET | `/api/dataplane/threatintel` | compiled threat-intel snapshot (gzip, ETag) |
| POST | `/api/dataplane/evaluate` | server-side evaluation (fallback / tooling) |
| POST | `/api/dataplane/flows/batch` | `{flows: [...]}` up to 1,000 per batch |

## Examples

```bash
# Service-account key (Settings → Identity; shown once) — or a user token from POST /api/auth/login
J='Content-Type: application/json'
TOKEN=aegis_sa_…

# block a domain everywhere
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/security/indicators \
  -d '{"type":"domain","value":"evil.example","category":"malware","reason":"INC-4711"}'

# create a policy set for CI runners (GitHub organisation incl. release downloads) and publish it
SET=$(curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/policy-sets -d '{
  "kind":"standard","spec":{"name":"CI: source hosting","enabled":true,"group_ids":["grp-ci-runners"],
  "review_interval_days":90,"rules":[{"name":"GitHub: acme org","action":"ALLOW","host_pattern":"github.com",
  "path_pattern":"/acme/**","methods":["GET","HEAD"],"follow_redirects":true,"enabled":true,
  "companion_rules":["codeload.github.com/acme/**","api.github.com/repos/acme/**"]}]}}' | jq -r .id)
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/policy-sets/$SET/simulate -d '{}'
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/policy-sets/$SET/publish -d '{"comment":"CHG-1234"}'
# with four-eyes review enabled: submit instead of publish, a second person approves
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/policy-sets/$SET/submit -d '{"title":"CI: GitHub acme"}'

# quarantine a compromised server (by id, or by host name / IP for SOAR playbooks)
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/servers/srv-web-17/quarantine \
  -d '{"quarantined":true,"reason":"INC-4711 beaconing to C2"}'
curl -s -H "$J" -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/servers/quarantine \
  -d '{"hostname":"web-17.corp.example","reason":"INC-4711 beaconing to C2"}'

# overdue access requests for the ITSM queue
curl -s -H "Authorization: Bearer $TOKEN" 'https://aegis.corp.example/api/requests?status=pending&overdue=true' | jq '.total'

# complete audit trail for the auditors
curl -s -H "Authorization: Bearer $TOKEN" https://aegis.corp.example/api/audit/export > audit.jsonl

# bulk-register servers from a CMDB export (dry run first)
jq -Rs '{dry_run:true, csv:.}' servers.csv | curl -s -H "$J" -H "Authorization: Bearer $TOKEN" \
  https://aegis.corp.example/api/servers/import -d @-
```
