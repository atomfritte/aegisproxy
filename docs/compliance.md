# Compliance mapping

This page maps AegisProxy capabilities to common control frameworks and tells auditors where to find the
evidence. It is a **mapping aid, not a certification or attestation**: AegisProxy supports controls that your
organization operates; whether a control is effective depends on your configuration, processes and scope.

## Evidence sources

| Evidence | Where | Format |
|---|---|---|
| Audit trail of every administrative action, tamper-evident (keyed HMAC-SHA256 hash chain, complete-trail verification) | console **Audit**, `GET /api/audit/export`, `GET /api/audit/verify`, SIEM via log export (audit stream) | JSON Lines, CEF/LEEF/ECS/OTLP in the SIEM |
| Policy versions, diffs and publish history (who, when, change request, emergency flag) | policy set → History, `GET /api/policy-sets/{id}/versions`, `/diff` | JSON |
| Change requests with four-eyes decisions | **Changes**, `GET /api/change-requests` | JSON |
| Recertification of policy sets | policy set review state, `review_due_at`, `POST …/recertify` audit events | JSON / audit |
| Access requests: requester, justification, reviewer, duration, expiry, revocation, SLA | **Requests**, `GET /api/requests` | JSON |
| Policy as code (current published policy) | `GET /api/policy-sets/export` | `aegisproxy.policy-sets/v1` bundle |
| Users, roles, scopes, break-glass flags, last login | **Settings → Identity**, `GET /api/state` → `users` | JSON |
| Service accounts, expiry, last use | `GET /api/service-accounts` | JSON |
| SCIM provisioning: provisioned/deprovisioned accounts, group syncs, token lifecycle, last sync | **Settings → Single sign-on → Provisioning**, `GET /api/settings/scim`, audit events `USER_*_SCIM`, `GROUP_*_SCIM`, `SCIM_TOKEN_*` | JSON / audit |
| Security events (threat intel, malware, DLP, quarantine, break-glass logins) | console **Threat Protection** (events), SIEM (security stream) | JSON / SIEM |
| Traffic records ("browsing logs") | SIEM (traffic stream), data-plane access logs | JSON, Squid, ECS, … |
| Configuration baseline and gaps | security posture, `GET /api/system/posture` | JSON |
| Software supply chain | signed release images, SBOM and provenance attestations (`SECURITY.md`) | OCI attestations |

## ISO/IEC 27001:2022 Annex A

| Control | AegisProxy contribution | Evidence |
|---|---|---|
| 5.15 Access control | Default-deny egress per server group; RBAC for the console (four roles, group scopes) | policy sets, users and roles |
| 5.16 Identity management | SSO with just-in-time provisioning; SCIM 2.0 lifecycle management from Entra ID / Okta (joiner, mover, leaver with immediate session revocation); service accounts as distinct non-human identities | users (`auth_provider`, `external_id`, `scim`), service accounts, `USER_PROVISIONED_SSO` / `USER_PROVISIONED_SCIM` / `USER_DEPROVISIONED_SCIM` / `LOGIN_SSO_DENIED` audit events |
| 5.17 Authentication information | Password policy, PBKDF2 hashing, hashed proxy tokens, API keys and SCIM tokens, write-only encrypted integration secrets, secret-less SSO client authentication (`private_key_jwt`) | [security.md](security.md#encryption-at-rest), posture |
| 5.18 Access rights | Group-to-role mapping from the IdP, expiring service-account keys, temporary access grants with expiry and revocation, recertification of policy sets | requests, policy set review state, posture (stale accounts, expiring keys) |
| 5.26 Response to information security incidents | Server quarantine (manual, SOAR by host name, Defender-driven), security events with notifications | `SERVER_QUARANTINED` audit events, security events |
| 5.28 Collection of evidence | Complete, hash-chained audit export; SIEM forwarding | audit export + verification |
| 8.2 Privileged access rights | Super Admin limited to people; 2–5 Super Admins checked; break-glass accounts alerted; SSO/log export/Defender configuration Super Admin only | posture, `BREAK_GLASS_LOGIN` events |
| 8.5 Secure authentication | OIDC with PKCE and strict token validation (MFA and conditional access enforced by the IdP), login throttling, session revocation | SSO configuration, [identity.md](identity.md) |
| 8.7 Protection against malware | Threat intelligence (feeds, TAXII/MISP, Defender indicators), ClamAV, YARA, ICAP to commercial engines, file-type control | threat-protection policy, security events |
| 8.9 Configuration management | Versioned policy sets, policy as code, posture checks | versions, export bundle, posture |
| 8.12 Data leakage prevention | DLP detectors for secrets in outbound traffic, ICAP REQMOD to enterprise DLP, upload size limit | DLP events, policy |
| 8.15 Logging | Audit trail, traffic and security records, data-plane access logs, export to SIEM with durable spool | log export configuration, SIEM |
| 8.16 Monitoring activities | Security events, anomaly detection (block bursts), Prometheus metrics, SIEM analytics rules (Sentinel package) | events, `deploy/sentinel/analytics` |
| 8.20 Networks security | Single controlled egress path for servers, Host/SNI consistency, no raw TCP tunnels, DNS-rebinding protection | protection policy |
| 8.21 Security of network services | TLS inspection with upstream certificate validation always on, TLS no-break exceptions explicit and audited | TLS bypass list, audit |
| 8.22 Segregation of networks | Per-group policies, strict-isolation (zero-internet) groups, internal destinations only by explicit rule | groups, effective policy per server |
| 8.23 Web filtering | Path-level allow lists, threat-intel blocking, block pages with request workflow | policy sets, traffic records |
| 8.24 Use of cryptography | AES-256-GCM for stored secrets with key rotation, interception CA from the corporate PKI, TLS ≥ 1.2 | [operations.md](operations.md#encryption-key), [corporate PKI](operations.md#corporate-pki-subordinate-ca) |
| 8.32 Change management | Drafts, impact simulation, four-eyes review, emergency publish with justification, rollback | change requests, versions, audit |

## NIST SP 800-53 Rev. 5

| Control | AegisProxy contribution |
|---|---|
| AC-2 Account Management | SSO provisioning/deprovisioning, automated account lifecycle via SCIM 2.0 (AC-2(1), AC-2(3) disable on leave, AC-2(4) audited), service-account lifecycle (expiry, disable, rotate), stale-account posture check |
| AC-3 Access Enforcement | RBAC with group scopes enforced server-side on every request; default-deny egress enforcement on every worker |
| AC-4 Information Flow Enforcement | Egress allow lists per server group, destination hygiene, DLP and ICAP REQMOD on outbound data |
| AC-6 Least Privilege | Team Leads limited to their groups and to temporary grants; service accounts never Super Admin; approved requests default to `GET/HEAD` |
| AU-2 / AU-12 Event Logging / Audit Record Generation | Audit events for every administrative action; traffic and security records for every request |
| AU-3 Content of Audit Records | Actor, role, action, entity, before/after state, timestamp, affected groups; traffic records with server identity, URL, verdict, rule |
| AU-6 Audit Record Review, Analysis, and Reporting | SIEM export (CEF, LEEF, ECS, OTLP, …), Sentinel analytics rules and workbook, Splunk CIM add-on |
| AU-9 Protection of Audit Information | keyed HMAC-SHA256 hash chain (key stored encrypted, not derivable from the database), complete-trail verification endpoint, append-only `audit.jsonl`, database table without automatic deletion, read-only Auditor role |
| CM-3 Configuration Change Control | Change requests with four-eyes review, impact simulation, versioning and rollback |
| CM-5 Access Restrictions for Change | Only scoped roles can edit; reviewers cannot approve their own changes; service accounts cannot approve |
| IA-2 Identification and Authentication (Organizational Users) | OIDC SSO (IdP-enforced MFA), break-glass accounts with alerting |
| IA-5 Authenticator Management | Password policy and hashing, key expiry and rotation for service accounts and SCIM tokens, write-only secrets, asymmetric SSO client credentials (`private_key_jwt`) with staged rotation |
| IR-4 Incident Handling | Quarantine (manual, API, Defender-driven), security events and notifications |
| SC-7 Boundary Protection | Managed egress proxy as the only path to the internet for server fleets |
| SC-8 Transmission Confidentiality and Integrity | TLS between components (HTTPS, `icaps://`, TLS syslog), upstream certificate validation |
| SC-12 / SC-28 Key Management / Protection of Information at Rest | AES-256-GCM sealed secrets with key rotation; CA key restricted to the data-plane |
| SI-3 Malicious Code Protection | ClamAV, YARA, ICAP engines, malicious-hash intelligence |
| SI-4 System Monitoring | Traffic and security telemetry, anomaly detection, metrics, SIEM integration |

## BSI IT-Grundschutz (Kompendium)

| Module | AegisProxy contribution |
|---|---|
| ORP.4 Identitäts- und Berechtigungsmanagement | Roles and scopes, SSO with group mapping, deprovisioning, service accounts, recertification of policy sets |
| OPS.1.1.3 Patch- und Änderungsmanagement | Controlled policy changes (drafts, four-eyes review, versions, rollback) |
| OPS.1.1.4 Schutz vor Schadprogrammen | Threat intelligence, ClamAV, YARA, ICAP to existing antivirus products |
| OPS.1.1.5 Protokollierung | Audit trail, traffic logs, central forwarding (syslog, SIEM) |
| CON.1 Kryptokonzept | Encryption of stored secrets, key rotation, interception CA from the corporate PKI |
| NET.1.1 Netzarchitektur und -design | Central egress control, segmentation by server group, strict isolation for zero-internet tiers |
| NET.3.2 Firewall | Application-level egress filtering complementing the network firewall (only the proxy may reach the internet) |
| DER.1 Detektion von sicherheitsrelevanten Ereignissen | Security events, anomaly detection, SIEM content |
| DER.2.1 Behandlung von Sicherheitsvorfällen | Quarantine, Defender and SOAR integration |

## SOC 2 (Trust Services Criteria 2017)

| Criterion | AegisProxy contribution |
|---|---|
| CC6.1 Logical access security | RBAC, SSO, encrypted secrets, default-deny egress |
| CC6.2 / CC6.3 Registration, authorization and removal of access | JIT provisioning and deprovisioning, role mapping, access requests with approval and expiry |
| CC6.6 Protection against threats from outside the system boundary | Threat intelligence, destination hygiene, TLS inspection |
| CC6.7 Restriction of data transmission | Egress allow lists, DLP, ICAP REQMOD, upload limits |
| CC6.8 Prevention and detection of malicious software | ClamAV, YARA, ICAP, malicious-hash intelligence |
| CC7.2 / CC7.3 Monitoring and evaluation of security events | Security events, anomaly detection, SIEM export and analytics rules |
| CC7.4 Incident response | Quarantine, SOAR and Defender integration |
| CC8.1 Change management | Change requests, four-eyes review, versions, impact simulation, rollback |

## Evidence collection checklist for auditors

1. Request an account with the **Auditor** role (`OPERATOR_AUDITOR`, read-only) — via an IdP group mapped to the
   role, or a service account with that role for scripted collection.
2. Export the complete audit trail (`GET /api/audit/export`) for the audit period and run
   `GET /api/audit/verify`; recompute the hash chain offline if required
   ([operations.md](operations.md#audit-trail)). Compare a sample with the SIEM copy.
3. Export the published policy (`GET /api/policy-sets/export`) and, for sampled sets, the version history and
   diffs (`/api/policy-sets/{id}/versions`, `/diff?from=&to=`).
4. List change requests for the period (`GET /api/change-requests`) and check that every publish outside an
   emergency has an approving reviewer different from the author and last editor; review every publish flagged
   **emergency** and its justification.
5. Check recertification: no policy set with `review_state: overdue`; `POLICY_SET_RECERTIFIED` audit events for
   the period.
6. Sample access requests (`GET /api/requests?status=approved`): justification, reviewer, granted duration,
   expiry or revocation.
7. Review users and service accounts: roles, scopes, break-glass flags, last login / last use, key expiry;
   `BREAK_GLASS_LOGIN` events and their follow-up.
8. Obtain the security posture report (`GET /api/system/posture`) and the threat-protection policy
   (`GET /api/state` → `security.policy`).
9. Verify that log export to the SIEM was active during the period (destination status, SIEM ingestion).

## Customer responsibilities

- Operate the IdP securely (MFA, conditional access, joiner/mover/leaver process).
- Ensure servers can reach the internet only through AegisProxy (network firewall, routing).
- Protect and back up `AEGIS_ENCRYPTION_KEY`, the CA private key and the database.
- Review security events and access requests within your SLAs; act on posture findings.
- Define retention for audit and traffic data in the SIEM according to your legal requirements (traffic records
  contain personal data such as URLs; use `redact_query` where appropriate).
