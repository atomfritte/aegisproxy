"""Sentinel / Logs Ingestion API conformance: AegisProxy's requests (through the real control-plane) are
compared with the requests of the official Azure SDKs (captured before in sdk.jsonl) and validated against
the official OpenAPI definition (Azure/azure-rest-api-specs, 2023-01-01).

Usage: python3 -I sentinel_e2e.py <control-plane binary> <capture.jsonl written by capture.py> <DataCollectionRules.json>
"""
import gzip, json, os, re, subprocess, sys, time, urllib.error, urllib.request

BIN, CAPTURE, SPEC = sys.argv[1:4]
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 18792
CP = f"http://127.0.0.1:{PORT}"
PW = "Sentinel-Root-Pass-2026x"
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DCR = "dcr-00000000000000000000000000000000"
STREAM = "Custom-AegisProxy_CL"
AUTH = "https://localhost:18443"
CA = open(os.path.join(HERE, "tls", "ca.pem")).read()
res = []


def check(name, cond, detail: object = ""):
    res.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" -> {str(detail)[:600]}"), flush=True)


cookie = ""


def call(m, p, b=None):
    global cookie
    data = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(CP + p, data=data, method=m, headers={"X-Requested-With": "aegis-ui", "Content-Type": "application/json", "Cookie": cookie})
    try:
        with urllib.request.urlopen(r, timeout=120) as x:
            if x.headers.get_all("Set-Cookie"):
                cookie = "; ".join(c.split(";")[0] for c in x.headers.get_all("Set-Cookie"))
            raw = x.read()
            return x.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def audience(scope):
    return scope[:-len("/.default")].rstrip("/") if scope.endswith("/.default") else scope


def captured(since):
    out = []
    with open(CAPTURE) as f:
        for i, line in enumerate(f):
            if i >= since:
                out.append(json.loads(line))
    return out


def count():
    with open(CAPTURE) as f:
        return sum(1 for _ in f)


sdk = [json.loads(l) for l in open(CAPTURE)]
spec = json.load(open(SPEC))
op = spec["paths"]["/dataCollectionRules/{ruleId}/streams/{stream}"]["post"]

fed = os.path.join(HERE, "data-sentinel", "federated-token")
data = os.path.join(HERE, "data-sentinel")
subprocess.run(["rm", "-rf", data])
os.makedirs(data)
open(fed, "w").write("eyJhbGciOiJSUzI1NiJ9.federated.sig")
env = dict(os.environ, CONTROL_PLANE_PORT=str(PORT), DATA_DIR=data, CERTS_DIR=data + "/certs", AEGIS_PUBLIC_URL=CP,
           AEGIS_JWT_SECRET="sentinel-jwt-secret-0123456789abcdef0123456789", AEGIS_DATAPLANE_KEY="sentinel-dataplane-key-0123456789abcdef0123",
           AEGIS_BOOTSTRAP_ADMIN_PASSWORD=PW, AEGIS_LOG_FORMAT="text", AEGIS_THREATINTEL_AUTOUPDATE="false",
           AZURE_FEDERATED_TOKEN_FILE=fed, AZURE_CLIENT_ID=CLIENT, AZURE_TENANT_ID=TENANT)
proc = subprocess.Popen([BIN], env=env, stdout=open(os.path.join(HERE, "logs", "cp-sentinel.log"), "w"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(CP + "/readyz", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    st, _ = call("POST", "/api/auth/login", {"username": "admin", "password": PW})
    check("login", st == 200, st)
    sink = {"name": "Sentinel", "type": "sentinel", "enabled": True, "streams": ["audit"], "endpoint": AUTH, "authority_url": AUTH,
            "tenant_id": TENANT, "client_id": CLIENT, "secret": "s3cret-value", "dcr_immutable_id": DCR, "stream_name": STREAM,
            "ca_cert_pem": CA, "azure_auth": "client_secret", "batch_size": 3000, "flush_seconds": 2}

    n0 = count()
    st, r = call("POST", "/api/integrations/exports/test", sink)
    check("client secret: test record accepted", st == 200 and r.get("ok") is True, r)
    reqs = captured(n0)
    tok = [x for x in reqs if x["path"].endswith("/oauth2/v2.0/token")]
    up = [x for x in reqs if x["path"].startswith("/dataCollectionRules/")]
    sdk_tok = next(x for x in sdk if x["path"].endswith("/oauth2/v2.0/token") and dict(x.get("form", [])).get("client_secret") and "monitor.azure.com" in dict(x["form"])["scope"])
    form, sform = dict(tok[0]["form"]) if tok else {}, dict(sdk_tok["form"])
    check("client secret: token request = SDK (same endpoint, grant, client, secret; scope with the Monitor audience)",
          tok and tok[0]["path"] == sdk_tok["path"] and form.get("grant_type") == sform["grant_type"] == "client_credentials"
          and form.get("client_id") == sform["client_id"] and form.get("client_secret") == sform["client_secret"]
          and audience(form.get("scope", "")) == audience(sform["scope"]) == "https://monitor.azure.com",
          (form, sform))
    sdk_up = next(x for x in sdk if x["path"].startswith("/dataCollectionRules/"))
    u = up[0] if up else {}
    check("upload: path, api-version, method = SDK and OpenAPI",
          u and u["path"] == sdk_up["path"] == f"/dataCollectionRules/{DCR}/streams/{STREAM}" and u["method"] == "POST"
          and dict(u["query"]).get("api-version") == dict(sdk_up["query"])["api-version"] == spec["info"]["version"], (u.get("path"), u.get("query")))
    h = u.get("headers", {})
    check("upload: Content-Type application/json (spec consumes), Content-Encoding gzip (spec: 'always gzip'), Bearer token",
          h.get("content-type") == "application/json" and h.get("content-encoding") == "gzip" and h.get("authorization", "").startswith("Bearer ")
          and spec["consumes"] == ["application/json"], h)
    check("upload: x-ms-client-request-id is a GUID (spec header)", re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", h.get("x-ms-client-request-id", "")), h)
    body = u.get("json")
    check("upload: body is an array of objects (spec body schema)", isinstance(body, list) and body and all(isinstance(x, dict) for x in body), type(body))
    check("upload: records carry TimeGenerated (ISO 8601) and the documented columns",
          body and re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", body[0].get("TimeGenerated", "")) and {"Stream", "Severity", "Message", "EventId"} <= set(body[0]), body[:1])
    allowed = {p["name"].lower() for p in op["parameters"] if "name" in p and p.get("in") == "header"} | {"x-ms-client-request-id"}
    extra = {k for k in h if k.startswith("x-ms-")} - allowed
    check("upload: no undocumented x-ms-* headers", not extra, extra)

    # Workload identity (federated token from AZURE_FEDERATED_TOKEN_FILE).
    n0 = count()
    st, r = call("POST", "/api/integrations/exports/test", dict(sink, azure_auth="workload_identity", secret="", client_id="", tenant_id=""))
    check("workload identity: test record accepted", st == 200 and r.get("ok") is True, r)
    tok = [x for x in captured(n0) if x["path"].endswith("/oauth2/v2.0/token")]
    sdk_wi = next(x for x in sdk if dict(x.get("form", [])).get("client_assertion_type"))
    form, sform = dict(tok[0]["form"]) if tok else {}, dict(sdk_wi["form"])
    check("workload identity: token request = SDK (client_assertion with the federated token, same assertion type and scope)",
          tok and tok[0]["path"] == sdk_wi["path"] and form == sform, (form, sform))

    # Live audit events with a batch larger than the 1 MB limit of one call.
    st, saved = call("POST", "/api/integrations/exports", sink)
    check("destination saved", st == 200 and saved.get("id"), saved)
    n0 = count()
    cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(200)]
    for i in range(700):
        call("POST", "/api/groups", {"id": f"grp-s-{i}", "name": f"Sentinel {i}", "cidrs": cidrs})
    deadline = time.time() + 60
    while time.time() < deadline:
        ups = [x for x in captured(n0) if x["path"].startswith("/dataCollectionRules/")]
        if sum(len(x.get("json") or []) for x in ups) >= 700:
            break
        time.sleep(1)
    ups = [x for x in captured(n0) if x["path"].startswith("/dataCollectionRules/")]
    total = sum(len(x.get("json") or []) for x in ups)
    check("live: all 700 audit events uploaded", total >= 700, total)
    biggest = max((x["decoded_len"] for x in ups), default=0)
    sdk_max = max(x["decoded_len"] for x in sdk if x["path"].startswith("/dataCollectionRules/"))
    check(f"live: every call within the 1 MB limit (largest {biggest} bytes uncompressed; SDK {sdk_max})", 0 < biggest <= 1 << 20, biggest)
    check("live: a batch above 1 MB was split into several calls", len(ups) >= 2, len(ups))
    tokens = [x for x in captured(n0) if x["path"].endswith("/oauth2/v2.0/token")]
    check("live: access token cached (no token request per upload)", len(tokens) <= 1, len(tokens))
finally:
    proc.terminate()
    try:
        proc.wait(10)
    except Exception:
        proc.kill()

print(f"\n{sum(res)}/{len(res)} passed")
sys.exit(0 if all(res) else 1)
