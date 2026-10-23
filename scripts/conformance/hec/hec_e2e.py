"""Splunk HEC conformance: AegisProxy control-plane -> OpenTelemetry Collector contrib splunk_hec receiver
(TLS, token via bearertokenauth scheme "Splunk") and Vector splunk_hec source with indexer acknowledgements.

Usage: python3 -I hec_e2e.py <control-plane binary>
"""
import json, os, subprocess, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
TLS = os.path.join(HERE, "..", "tls")
BIN = sys.argv[1]
PORT = 18791
CP = f"http://127.0.0.1:{PORT}"
DP_KEY = "hec-dataplane-key-0123456789abcdef0123456789"
ADMIN_PW = "Hec-Root-Pass-2026x"
OTEL_TOKEN = "otel-hec-token-0123456789"
VEC_TOKEN = "vector-ack-token-0123456789"
CA = open(os.path.join(TLS, "ca.pem")).read()
res = []


def check(name, cond, detail=""):
    res.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" -> {str(detail)[:500]}"), flush=True)


class Session:
    def __init__(self):
        self.cookie = ""

    def call(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"X-Requested-With": "aegis-ui", "Content-Type": "application/json", "Cookie": self.cookie}
        h.update(headers or {})
        req = urllib.request.Request(CP + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                if r.headers.get_all("Set-Cookie"):
                    self.cookie = "; ".join(c.split(";")[0] for c in r.headers.get_all("Set-Cookie"))
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw


def otel_records():
    """Flattens the OTLP JSON lines written by the collector's file exporter."""
    out = []
    try:
        with open(os.path.join(HERE, "out", "hec.jsonl"), "rb") as f:
            f.seek(OFFSETS["out/hec.jsonl"])
            lines = f.read().decode().splitlines()
    except FileNotFoundError:
        return out

    def val(v):
        if "stringValue" in v: return v["stringValue"]
        if "intValue" in v: return int(v["intValue"])
        if "doubleValue" in v: return v["doubleValue"]
        if "boolValue" in v: return v["boolValue"]
        if "kvlistValue" in v: return {kv["key"]: val(kv.get("value", {})) for kv in v["kvlistValue"].get("values", [])}
        if "arrayValue" in v: return [val(x) for x in v["arrayValue"].get("values", [])]
        return None

    for line in lines:
        line = line.strip("\x00").strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        for rl in doc.get("resourceLogs", []):
            rattrs = {a["key"]: val(a["value"]) for a in rl.get("resource", {}).get("attributes", [])}
            batch = sum(len(sl.get("logRecords", [])) for sl in rl.get("scopeLogs", []))
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    attrs = dict(rattrs)
                    attrs.update({a["key"]: val(a["value"]) for a in lr.get("attributes", [])})
                    out.append({"attrs": attrs, "body": val(lr.get("body", {})), "time": int(lr.get("timeUnixNano", "0")), "batch": batch})
    return out


def vector_records():
    try:
        with open(os.path.join(HERE, "vout", "hec_ack.jsonl"), "rb") as f:
            f.seek(OFFSETS["vout/hec_ack.jsonl"])
            return [json.loads(l) for l in f.read().decode().splitlines() if l.strip("\x00").strip()]
    except FileNotFoundError:
        return []


def wait_for(fn, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.5)
    return fn()


OFFSETS = {f: (os.path.getsize(os.path.join(HERE, f)) if os.path.exists(os.path.join(HERE, f)) else 0) for f in ("out/hec.jsonl", "vout/hec_ack.jsonl")}
data = os.path.join(HERE, "data-" + os.path.basename(BIN))
subprocess.run(["rm", "-rf", data])
env = dict(os.environ, CONTROL_PLANE_PORT=str(PORT), DATA_DIR=data, CERTS_DIR=data + "/certs", AEGIS_PUBLIC_URL=CP,
           AEGIS_JWT_SECRET="hec-jwt-secret-0123456789abcdef0123456789abcdef", AEGIS_DATAPLANE_KEY=DP_KEY,
           AEGIS_BOOTSTRAP_ADMIN_PASSWORD=ADMIN_PW, AEGIS_LOG_FORMAT="text", AEGIS_THREATINTEL_AUTOUPDATE="false")
log = open(os.path.join(HERE, "cp-" + os.path.basename(BIN) + ".log"), "w")
proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(CP + "/readyz", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    admin = Session()
    st, _ = admin.call("POST", "/api/auth/login", {"username": "admin", "password": ADMIN_PW})
    check("login as Super Admin", st == 200)

    otel = {"name": "Splunk via OTel", "type": "splunk_hec", "enabled": True, "streams": ["audit", "traffic", "security"],
            "endpoint": "https://127.0.0.1:18089", "ca_cert_pem": CA, "secret": OTEL_TOKEN, "index": "aegis_{stream}",
            "source_type": "aegisproxy", "flush_seconds": 1, "batch_size": 50}
    st, r = admin.call("POST", "/api/integrations/exports/test", dict(otel, ca_cert_pem=""))
    check("OTel HEC: untrusted certificate refused", st == 200 and r.get("ok") is False and "certificate" in str(r.get("error", "")).lower(), r)
    st, r = admin.call("POST", "/api/integrations/exports/test", dict(otel, secret="wrong-token"))
    check("OTel HEC: wrong token reported (HTTP 401)", st == 200 and r.get("ok") is False and "HTTP 401" in str(r.get("error", "")), r)
    st, r = admin.call("POST", "/api/integrations/exports/test", otel)
    check("OTel HEC: test record accepted", st == 200 and r.get("ok") is True, r)
    rec = wait_for(lambda: [x for x in otel_records() if "EXPORT_TEST" in json.dumps(x["body"])], 10)
    check("OTel HEC: test record arrived as structured event", bool(rec) and isinstance(rec[0]["body"], dict), rec[:1])

    st, saved = admin.call("POST", "/api/integrations/exports", otel)
    check("OTel HEC: destination saved", st == 200 and saved.get("id"), saved)
    vec = {"name": "Splunk with indexer acknowledgement (Vector)", "type": "splunk_hec", "enabled": True, "streams": ["audit"],
           "endpoint": "http://127.0.0.1:18090", "secret": VEC_TOKEN, "index": "aegis", "flush_seconds": 1}
    st, r = admin.call("POST", "/api/integrations/exports/test", vec)
    check("HEC with indexer acknowledgement enabled: test record accepted (channel header sent)", st == 200 and r.get("ok") is True, r)
    st, vsaved = admin.call("POST", "/api/integrations/exports", vec)
    check("HEC with indexer acknowledgement: destination saved", st == 200, vsaved)

    # Non-administrator view of a failing destination: no response body excerpt.
    bad = dict(otel, name="Wrong token", secret="wrong-token", enabled=False)
    st, bsaved = admin.call("POST", "/api/integrations/exports", bad)
    st, u = admin.call("POST", "/api/users", {"username": "infosec1", "display_name": "InfoSec", "email": "infosec1@example.com", "role": "INFOSEC_APPROVER", "password": "Kx9-Approver-Vault-2026"})
    check("InfoSec Approver account created", st == 200, u)
    secops = Session()
    st2, me = secops.call("POST", "/api/auth/login", {"username": "infosec1", "password": "Kx9-Approver-Vault-2026"})
    if isinstance(me, dict) and me.get("must_change_password"):
        secops.call("POST", "/api/auth/password", {"current_password": "Kx9-Approver-Vault-2026", "new_password": "Kx9-Approver-Vault-2027"})
    st, r = secops.call("POST", "/api/integrations/exports/test", {"id": bsaved.get("id"), "name": "x", "type": "splunk_hec", "streams": ["audit"], "endpoint": "https://evil.example"})
    err = str((r or {}).get("error", ""))
    check("InfoSec Approver: saved destination tested, error shortened (no response body)", st == 200 and r.get("ok") is False and err.endswith("/services/collector/event") and "HTTP 401" in err, (st, r))

    # Live events: audit (groups), browsing and security (data-plane flow batch).
    for i in range(3):
        admin.call("POST", "/api/groups", {"id": f"grp-hec-{i}", "name": f"HEC {i}", "cidrs": ["10.0.0.0/8"]})
    flows = [dict(server_ip="10.20.1.15", method="GET", scheme="https", host="intranet.example", path="/index.html",
                  full_url="https://intranet.example/index.html", verdict="ALLOWED", status_code=200, tls_intercepted=True),
             dict(server_ip="10.20.1.15", method="GET", scheme="https", host="malware-drop.example", path="/payload/stage2.bin",
                  full_url="https://malware-drop.example/payload/stage2.bin", verdict="THREAT_BLOCKED", threat_category="malware",
                  threat_source="URLhaus malware domains", threat_indicator="malware-drop.example", status_code=403, tls_intercepted=True)]
    req = urllib.request.Request(CP + "/api/dataplane/flows/batch", data=json.dumps({"flows": flows}).encode(), method="POST",
                                 headers={"X-Aegis-DataPlane-Key": DP_KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        check("data-plane flow batch accepted", 200 <= r.status < 300, r.status)
    t_sent = time.time()
    recs = wait_for(lambda: (lambda o: o if sum(1 for x in o if "GROUP_CREATED" in json.dumps(x["body"])) >= 3
                             and any("malware-drop.example" in json.dumps(x["body"]) and x["attrs"].get("com.splunk.index") == "aegis_security" for x in o) else None)(otel_records()), 30) or otel_records()
    aud = [x for x in recs if "GROUP_CREATED" in json.dumps(x["body"])]
    check("OTel HEC: audit events delivered", len(aud) >= 3, len(aud))
    a = aud[0] if aud else {"attrs": {}, "body": {}, "time": 0}
    check("OTel HEC: index from {stream} pattern (aegis_audit)", a["attrs"].get("com.splunk.index") == "aegis_audit", a["attrs"])
    check("OTel HEC: sourcetype aegisproxy:audit, source aegisproxy", a["attrs"].get("com.splunk.sourcetype") == "aegisproxy:audit" and a["attrs"].get("com.splunk.source") == "aegisproxy", a["attrs"])
    check("OTel HEC: host field set", bool(a["attrs"].get("host.name")), a["attrs"])
    check("OTel HEC: event time within 60 s of now (epoch seconds with ms)", abs(a["time"] / 1e9 - t_sent) < 60, a["time"])
    traffic = [x for x in recs if "intranet.example" in json.dumps(x["body"])]
    check("OTel HEC: browsing record delivered to aegis_traffic", any(x["attrs"].get("com.splunk.index") == "aegis_traffic" and x["attrs"].get("com.splunk.sourcetype") == "aegisproxy:traffic" for x in traffic), [x["attrs"] for x in traffic])
    sec = [x for x in recs if "malware-drop.example" in json.dumps(x["body"]) and x["attrs"].get("com.splunk.index") == "aegis_security"]
    check("OTel HEC: security event delivered to aegis_security", bool(sec), [x["attrs"] for x in recs if "malware-drop" in json.dumps(x["body"])])

    # Batching: 120 audit events -> several requests of at most 50 records.
    for i in range(120):
        admin.call("POST", "/api/groups", {"id": f"grp-batch-{i}", "name": f"Batch {i}", "cidrs": ["10.1.0.0/16"]})
    recs = wait_for(lambda: (lambda o: o if sum(1 for x in o if "grp-batch-" in json.dumps(x["body"]) and "GROUP_CREATED" in json.dumps(x["body"])) >= 120 else None)(otel_records()), 40) or otel_records()
    b = [x for x in recs if "grp-batch-" in json.dumps(x["body"]) and "GROUP_CREATED" in json.dumps(x["body"])]
    check("OTel HEC: 120 audit events delivered completely", len(b) == 120, len(b))
    check("OTel HEC: delivered in batches (several records per request, at most batch_size 50)", b and max(x["batch"] for x in b) > 1 and max(x["batch"] for x in b) <= 50, sorted({x["batch"] for x in b}))

    vrec = wait_for(lambda: [x for x in vector_records() if "GROUP_CREATED" in json.dumps(x)], 15)
    check("HEC with indexer acknowledgement: live audit events delivered", len(vrec) >= 3, len(vrec))

    # Receiver outage: records are spooled and delivered after recovery.
    subprocess.run(["docker", "stop", "-t", "2", "conf-otelcol"], capture_output=True)
    for i in range(5):
        admin.call("POST", "/api/groups", {"id": f"grp-outage-{i}", "name": f"Outage {i}", "cidrs": ["10.2.0.0/16"]})
    time.sleep(6)
    st, ex = admin.call("GET", "/api/integrations/exports")
    blob = json.dumps(ex)
    status = next((s for s in (ex.get("status") or ex.get("statuses") or []) if s.get("id") == saved.get("id")), None) if isinstance(ex, dict) else None
    if status is None:
        for s in (ex.get("sinks") or []) if isinstance(ex, dict) else []:
            if s.get("id") == saved.get("id"):
                status = s.get("status") or (s.get("statuses") or [None])[0]
    check("outage: destination reported as retrying with spooled records", status and status.get("state") in ("retrying", "error") and (status.get("spool_records", 0) > 0 or status.get("queued", 0) > 0), status or blob[:600])
    subprocess.run(["docker", "start", "conf-otelcol"], capture_output=True)
    recs = wait_for(lambda: (lambda o: o if sum(1 for x in o if "grp-outage-" in json.dumps(x["body"]) and "GROUP_CREATED" in json.dumps(x["body"])) >= 5 else None)(otel_records()), 120) or otel_records()
    o = [x for x in recs if "grp-outage-" in json.dumps(x["body"]) and "GROUP_CREATED" in json.dumps(x["body"])]
    check("outage: all 5 spooled audit events delivered after recovery", len(o) == 5, len(o))
    ids = [x["body"].get("event", {}).get("id") if isinstance(x["body"].get("event"), dict) else x["body"].get("event.id") for x in recs]
    st, ex = admin.call("GET", "/api/integrations/exports")
    print("final status:", json.dumps(ex)[:800])
finally:
    proc.terminate()
    try:
        proc.wait(10)
    except Exception:
        proc.kill()
print(f"\n{sum(res)}/{len(res)} passed")
sys.exit(0 if all(res) else 1)
