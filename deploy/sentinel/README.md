# Microsoft Sentinel content for AegisProxy

| File | Purpose |
|---|---|
| `aegisproxy-sentinel.bicep` / `.json` | Custom table `AegisProxy_CL`, data collection endpoint and rule, role assignment (Monitoring Metrics Publisher) for the identity AegisProxy uses. Outputs the endpoint, DCR immutable ID and stream name for the console. |
| `parsers/ASimWebSessionAegisProxy.kql` | ASIM WebSession parser: AegisProxy traffic in all ASIM web-session content. |
| `parsers/ASimAuditEventAegisProxy.kql` | ASIM AuditEvent parser for administration events. |
| `analytics/*.yaml` | Scheduled analytics rules (malware download, threat-intel destinations, beaconing bursts, DLP, break-glass logins, emergency changes, quarantines). |
| `workbooks/aegisproxy-workbook.json` | Overview workbook (verdicts, top blocked destinations and servers, security and admin events). |
| `playbooks/quarantine-host.json` | Logic App: quarantines the hosts of an incident through the AegisProxy API (service-account key in Key Vault) and comments on the incident. |

Setup and details: [docs/log-export.md](../../docs/log-export.md#microsoft-sentinel).
