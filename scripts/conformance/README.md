# Conformance tests without vendor licenses or tenants

`run.sh <work-dir>` checks AegisProxy's integrations against independent reference implementations and the
vendors' own SDKs and API definitions. It needs Docker, Go, Python 3 and outbound HTTPS, but **no Splunk
license and no Microsoft tenant**; nothing is sent to a vendor except unauthenticated requests with made-up
identifiers (see the last row).

| Area | Reference | What is checked |
|---|---|---|
| Splunk HEC | OpenTelemetry Collector contrib 0.162.0 `splunk_hec` receiver (TLS, token); Vector 0.59.0 `splunk_hec` source with **indexer acknowledgement** | test record, untrusted certificate, wrong token (shortened error for non-administrators), structured events, `index` from the `{stream}` pattern, `sourcetype`/`source`/`host`/`time`, 120 events in batches, request channel + acknowledgement polling, receiver outage → spool → complete delivery after recovery (23 checks) |
| Microsoft Sentinel (Logs Ingestion API) | official Python SDKs `azure-identity` 1.26.0, `azure-monitor-ingestion` 1.1.0, `msal` 1.39.0 against a local TLS capture server; the official OpenAPI definition from `Azure/azure-rest-api-specs` (commit pinned, SHA-256 checked) | AegisProxy's token requests (client secret, workload identity) are identical to the SDKs'; upload path, `api-version`, headers, gzip, body schema, `x-ms-client-request-id`, no undocumented headers, 1 MB limit with automatic splitting, token caching (16 checks) |
| Entra ID, Defender for Endpoint, Datadog (public endpoints) | `go test -tags live -run Live` in `internal/oidc`, `internal/defender`, `internal/export` | Entra discovery, JWKS and token auth methods, PKCE authorization URL; `AADSTS90002` for an unknown tenant reported without the secret; the Defender API (current, regional and legacy hosts) rejects an invalid token with 401; Datadog's EU intake rejects an invalid key with 403 (permanent error) |

The Defender client itself is covered by unit tests modelled on Microsoft's API documentation
(`internal/defender/defender_test.go`: token scope per cloud, `$top`/`$skip` paging, 404 without devices,
429 with `Retry-After`, foreign `nextLink` refused). Real tenants are covered by
[`scripts/integration-tests/live_microsoft.py`](../integration-tests/README.md).

```bash
scripts/conformance/run.sh /tmp/aegis-conformance
```

Ports used on 127.0.0.1: 18089/18090/18133 (receivers), 18443/18080 (capture server), 18791/18792 (control-plane).
