# Live integration tests

These tests exercise integrations that need a real third-party tenant and therefore cannot run in the
regular CI pipeline. They run through a running AegisProxy control-plane (the same code paths the console
uses) and only need Python 3 (standard library).

| Script | Covers | Credentials |
|---|---|---|
| `live_microsoft.py` | Microsoft Defender for Endpoint (token, `Ti.ReadWrite.All`/`Machine.Read.All`, indicator import, device sync) and Microsoft Sentinel / Azure Monitor Logs Ingestion (test record, live audit records, optional KQL check that the record is queryable) | see the docstring at the top of the script |

Run them against a **staging** installation: the script changes the Defender settings and creates (then
deletes) a temporary log export destination.

```bash
export AEGIS_URL=https://aegis-staging.corp.example AEGIS_USERNAME=breakglass AEGIS_PASSWORD=…
export AZURE_TENANT_ID=… DEFENDER_CLIENT_ID=… DEFENDER_CLIENT_SECRET=…
export SENTINEL_DCE=https://dce-aegisproxy-xxxx.westeurope-1.ingest.monitor.azure.com SENTINEL_DCR_ID=dcr-… SENTINEL_STREAM=Custom-AegisProxy_CL
export LA_WORKSPACE_ID=…            # optional: wait until the record is queryable in the workspace
python3 -I scripts/integration-tests/live_microsoft.py
```

The GitHub workflow `.github/workflows/live-integration.yml` runs the Sentinel part weekly or on demand
**without any stored secret**: it starts a control-plane on the runner, which authenticates with the runner's
GitHub OIDC token (`SENTINEL_AUTH=workload_identity`, `AZURE_FEDERATED_TOKEN_FILE`) through a federated
credential whose subject names the default branch (`repo:atomfritte/aegisproxy:ref:refs/heads/aegisproxy-2.1`),
so a workflow pushed to another branch cannot obtain Azure tokens. The Defender for Endpoint integration
authenticates with a client secret only; repository secrets are readable by any pushed workflow when
environments cannot be protected, so run the Defender part from an administrator workstation as shown above.
Splunk HEC, Datadog, MISP, TAXII, Keycloak, c-icap/ClamAV and the SIEM collectors are covered by the
end-to-end tests in [`docs/testing.md`](../../docs/testing.md).
