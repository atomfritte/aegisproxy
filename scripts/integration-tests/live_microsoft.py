#!/usr/bin/env python3
"""Live integration test against real Microsoft tenants: Defender for Endpoint and Microsoft Sentinel.

Runs through a running AegisProxy control-plane (the same code paths as the console) and needs only the
Python standard library. Every step prints PASS/FAIL; the exit code is the number of failed checks.

Control-plane (required):
  AEGIS_URL                 e.g. https://aegis.corp.example
  AEGIS_USERNAME / AEGIS_PASSWORD   a Super Admin with password sign-in (break-glass account)
  AEGIS_CA_FILE             optional CA bundle for the console certificate

Microsoft Defender for Endpoint (skipped when DEFENDER_CLIENT_ID is unset):
  AZURE_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET
  App registration with WindowsDefenderATP application permissions Ti.ReadWrite.All and Machine.Read.All
  (admin consent). DEFENDER_API_BASE / AZURE_AUTHORITY for sovereign clouds (optional).

Microsoft Sentinel / Azure Monitor Logs Ingestion (skipped when SENTINEL_DCE is unset):
  SENTINEL_DCE (logs ingestion endpoint), SENTINEL_DCR_ID (immutable id), SENTINEL_STREAM (Custom-AegisProxy_CL),
  SENTINEL_CLIENT_ID / SENTINEL_CLIENT_SECRET (Monitoring Metrics Publisher on the DCR; defaults to the Defender app)
  Optional end-to-end check that the record arrived: LA_WORKSPACE_ID plus LA_CLIENT_ID / LA_CLIENT_SECRET with
  Log Analytics Reader on the workspace (defaults to the Sentinel app). Ingestion can take up to 15 minutes.
  SENTINEL_CA_FILE: optional CA bundle when the ingestion endpoint is reached through a TLS-inspecting proxy.
  SENTINEL_AUTHORITY / AZURE_AUTHORITY: Entra ID authority for sovereign clouds (default login.microsoftonline.com).

Usage:  python3 -I scripts/integration-tests/live_microsoft.py
Deploy the Sentinel resources first with deploy/sentinel/aegisproxy-sentinel.bicep (outputs DCE, DCR id, stream).
The script changes the Defender integration settings of the target installation and creates (then deletes)
a temporary log export destination: use a test or staging installation.
"""
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"\n      -> {str(detail)[:600]}"), flush=True)


def env(name, default=""):
    return os.environ.get(name, default).strip()


class Aegis:
    def __init__(self, base, ca_file=""):
        self.base = base.rstrip("/")
        self.cookie = ""
        self.ctx = ssl.create_default_context(cafile=ca_file or None)

    def call(self, method, path, body=None, timeout=120):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"X-Requested-With": "aegis-ui", "Content-Type": "application/json", "Cookie": self.cookie})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
                if r.headers.get_all("Set-Cookie"):
                    self.cookie = "; ".join(c.split(";")[0] for c in r.headers.get_all("Set-Cookie"))
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode(errors="replace")


def azure_token(tenant, client_id, secret, scope, authority="https://login.microsoftonline.com"):
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret, "scope": scope}).encode()
    req = urllib.request.Request(f"{authority.rstrip('/')}/{tenant}/oauth2/v2.0/token", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())["access_token"]


def defender(aegis):
    tenant, client, secret = env("AZURE_TENANT_ID"), env("DEFENDER_CLIENT_ID"), env("DEFENDER_CLIENT_SECRET")
    cfg = {"enabled": True, "tenant_id": tenant, "client_id": client, "client_secret": secret,
           "import_indicators": True, "device_sync": True, "quarantine_on_risk": "off", "sync_minutes": 15}
    if env("DEFENDER_API_BASE"):
        cfg["api_base_url"] = env("DEFENDER_API_BASE")
    if env("AZURE_AUTHORITY"):
        cfg["authority_url"] = env("AZURE_AUTHORITY")
    st, out = aegis.call("PUT", "/api/integrations/defender", cfg)
    check("Defender: configuration saved (secret write-only)", st == 200 and not (out or {}).get("client_secret"), out)
    st, res = aegis.call("POST", "/api/integrations/defender/test", {})
    check("Defender: token and API permissions (test)", st == 200 and isinstance(res, dict) and res.get("ok"), res)
    if isinstance(res, dict):
        print(f"      indicators={res.get('indicators')} devices={res.get('devices')}")
    st, res = aegis.call("POST", "/api/integrations/defender/sync", {})
    check("Defender: device sync and indicator refresh", st == 200, res)
    st, res = aegis.call("GET", "/api/integrations/defender")
    c = (res or {}).get("config", {})
    check("Defender: last sync without error", c.get("last_sync_at") and not c.get("last_sync_error"), c)
    time.sleep(20)
    st, state = aegis.call("GET", "/api/state?exclude_flows=1")
    feeds = {f["id"]: f for f in state.get("security", {}).get("feeds", [])}
    f = feeds.get("microsoft-defender-indicators", {})
    check("Defender: indicator feed refreshed", f.get("last_success_at") and not f.get("last_error"), f)
    print(f"      Defender indicators imported: {f.get('entry_count')}")


def sentinel(aegis):
    tenant = env("AZURE_TENANT_ID")
    client = env("SENTINEL_CLIENT_ID") or env("DEFENDER_CLIENT_ID")
    secret = env("SENTINEL_CLIENT_SECRET") or env("DEFENDER_CLIENT_SECRET")
    marker = "aegis-live-" + uuid.uuid4().hex[:12]
    sink = {"name": "Live test " + marker, "type": "sentinel", "enabled": True, "streams": ["audit"], "endpoint": env("SENTINEL_DCE"),
            "dcr_immutable_id": env("SENTINEL_DCR_ID"), "stream_name": env("SENTINEL_STREAM", "Custom-AegisProxy_CL"),
            "azure_auth": "client_secret", "tenant_id": tenant, "client_id": client, "secret": secret, "flush_seconds": 1}
    if env("SENTINEL_AUTHORITY") or env("AZURE_AUTHORITY"):
        sink["authority_url"] = env("SENTINEL_AUTHORITY") or env("AZURE_AUTHORITY")
    if env("SENTINEL_CA_FILE"):  # TLS-inspecting egress proxies / private endpoints with a corporate CA
        sink["ca_cert_pem"] = open(env("SENTINEL_CA_FILE")).read()
    st, res = aegis.call("POST", "/api/integrations/exports/test", sink)
    check("Sentinel: test record accepted by the Logs Ingestion API", st == 200 and isinstance(res, dict) and res.get("ok"), res)
    st, saved = aegis.call("POST", "/api/integrations/exports", sink)
    check("Sentinel: destination saved", st == 200 and isinstance(saved, dict), saved)
    # An audit event that carries the marker (group creation), exported by the new destination.
    gid = "grp-" + marker[-12:]
    aegis.call("POST", "/api/groups", {"id": gid, "name": marker, "cidrs": ["192.0.2.0/24"]})
    status = {}
    for _ in range(12):
        time.sleep(5)
        st, ex = aegis.call("GET", "/api/integrations/exports")
        status = next((x for x in (ex or {}).get("status", []) if isinstance(saved, dict) and x.get("id") == saved.get("id")), {})
        if status.get("sent", 0) > 0 or status.get("last_error"):
            break
    check("Sentinel: live audit records delivered (sent > 0, no error)", status.get("sent", 0) > 0 and not status.get("last_error"), status)
    if env("LA_WORKSPACE_ID"):
        token = azure_token(tenant, env("LA_CLIENT_ID") or client, env("LA_CLIENT_SECRET") or secret, "https://api.loganalytics.io/.default")
        table = env("SENTINEL_STREAM", "Custom-AegisProxy_CL").removeprefix("Custom-")
        query = f'{table} | where TimeGenerated > ago(1h) | where tostring(Message) has "{marker}" or tostring(Data) has "{marker}" | take 1'
        found = False
        for _ in range(30):  # up to 15 minutes ingestion latency
            req = urllib.request.Request(f"https://api.loganalytics.io/v1/workspaces/{env('LA_WORKSPACE_ID')}/query",
                                         data=json.dumps({"query": query}).encode(), method="POST",
                                         headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                rows = json.loads(r.read()).get("tables", [{}])[0].get("rows", [])
            if rows:
                found = True
                break
            time.sleep(30)
        check("Sentinel: record queryable in the workspace (KQL)", found, query)
    if isinstance(saved, dict) and saved.get("id"):
        aegis.call("DELETE", f"/api/integrations/exports/{saved['id']}")
    aegis.call("DELETE", f"/api/groups/{gid}")


def main():
    if not env("AEGIS_URL"):
        print(__doc__)
        return 2
    aegis = Aegis(env("AEGIS_URL"), env("AEGIS_CA_FILE"))
    st, _ = aegis.call("POST", "/api/auth/login", {"username": env("AEGIS_USERNAME", "admin"), "password": env("AEGIS_PASSWORD")})
    check("control-plane sign-in", st == 200, st)
    if st != 200:
        return 1
    if env("DEFENDER_CLIENT_ID"):
        defender(aegis)
    else:
        print("SKIP  Defender (DEFENDER_CLIENT_ID not set)")
    if env("SENTINEL_DCE"):
        sentinel(aegis)
    else:
        print("SKIP  Sentinel (SENTINEL_DCE not set)")
    failed = RESULTS.count(False)
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} checks passed")
    return failed


if __name__ == "__main__":
    sys.exit(main())
