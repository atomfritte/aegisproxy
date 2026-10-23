"""End-to-end test of the Windows build (aegis-control-plane.exe) under Wine.

Part 1 runs the .exe as a console process (file mode, built-in audit rotation at 1 MB, restart durability).
Part 2 registers it with Wine's Service Control Manager (sc create / net start / net stop), which exercises
service_windows.go (svc.Run, Stop handling, state flush).

Usage: python3 -I exe_e2e.py <dir containing aegis-control-plane.exe>
"""
import json, os, ssl, subprocess, sys, time, urllib.error, urllib.request

APP = os.path.abspath(sys.argv[1])
IMAGE = "aegis-test-wine:local"
PW = "Wine-Root-Pass-2026x"
DPK = "wine-dataplane-key-0123456789abcdef0123456789"
SECRETS = {"AEGIS_JWT_SECRET": "wine-jwt-secret-0123456789abcdef0123456789abcd", "AEGIS_DATAPLANE_KEY": DPK,
           "AEGIS_ENCRYPTION_KEY": "wine-encryption-key-0123456789abcdef0123456789ab", "AEGIS_BOOTSTRAP_ADMIN_PASSWORD": PW}
res = []


def check(name, cond, detail: object = ""):
    res.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" -> {str(detail)[:400]}"), flush=True)


def sh(*args, check_rc=True, timeout=120):
    p = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if check_rc and p.returncode != 0:
        raise RuntimeError(f"{args}: {p.returncode} {p.stdout} {p.stderr}")
    return p


class Client:
    def __init__(self, base):
        self.base, self.cookie = base, ""

    def call(self, m, p, b=None, headers=None, raw=False):
        data = json.dumps(b).encode() if b is not None else None
        h = {"X-Requested-With": "aegis-ui", "Content-Type": "application/json", "Cookie": self.cookie}
        h.update(headers or {})
        r = urllib.request.Request(self.base + p, data=data, method=m, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=60) as x:
                if x.headers.get_all("Set-Cookie"):
                    self.cookie = "; ".join(c.split(";")[0] for c in x.headers.get_all("Set-Cookie"))
                body = x.read()
                if raw:
                    return x.status, body
                return x.status, json.loads(body) if body and x.headers.get_content_type() == "application/json" else body
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, body


def wait_ready(base, seconds=120):
    for _ in range(seconds * 2):
        try:
            with urllib.request.urlopen(base + "/readyz", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def dexec(name, *cmd, timeout=120):
    return sh("docker", "exec", name, *cmd, check_rc=False, timeout=timeout)


def data_files(name):
    p = dexec(name, "sh", "-c", "ls -1 /wineprefix/drive_c/aegis/data")
    return [l for l in p.stdout.split() if l.startswith("audit.jsonl")]


# ---------------------------------------------------------------- part 1: console process
P1 = "aegis-wine-e2e"
PORT1 = 18191
B1 = f"http://127.0.0.1:{PORT1}"
sh("docker", "rm", "-f", P1, check_rc=False)
env1 = dict(SECRETS, CONTROL_PLANE_PORT="8081", AEGIS_PUBLIC_URL=B1, DATA_DIR=r"C:\aegis\data", CERTS_DIR=r"C:\aegis\certs",
            AEGIS_LOG_FILE=r"C:\aegis\logs\control-plane.log", AEGIS_LOG_FORMAT="json", AEGIS_THREATINTEL_AUTOUPDATE="false",
            AEGIS_AUDIT_ROTATE_MB="1", AEGIS_SHUTDOWN_DELAY="0s")
args = ["docker", "run", "-d", "--name", P1, "-p", f"127.0.0.1:{PORT1}:8081", "-v", f"{APP}:/app:ro"]
for k, v in env1.items():
    args += ["-e", f"{k}={v}"]
args += [IMAGE, "sh", "-c", "mkdir -p /wineprefix/drive_c/aegis && cp /app/aegis-control-plane.exe /wineprefix/drive_c/aegis/ && exec wine 'C:\\aegis\\aegis-control-plane.exe'"]
sh(*args)
try:
    check("exe: starts under Wine and reports ready (log directory created on demand)", wait_ready(B1), sh("docker", "logs", "--tail", "20", P1, check_rc=False).stdout + sh("docker", "logs", "--tail", "20", P1, check_rc=False).stderr)
    c = Client(B1)
    st, me = c.call("POST", "/api/auth/login", {"username": "admin", "password": PW})
    check("exe: bootstrap admin login", st == 200, me)
    st, info = c.call("GET", "/healthz", raw=True)
    first = dexec(P1, "sh", "-c", "head -1 /wineprefix/drive_c/aegis/logs/control-plane.log").stdout
    check("exe: /healthz answers and the JSON log identifies the Windows build (2.1.0-wine)", st == 200 and '"version":"2.1.0-wine"' in first, (st, first))
    st, g = c.call("POST", "/api/groups", {"id": "grp-win", "name": "Windows servers", "cidrs": ["10.20.0.0/16"]})
    check("exe: create server group", st in (200, 201), g)
    st, ps = c.call("POST", "/api/policy-sets", {"kind": "standard", "spec": {"name": "Windows baseline", "enabled": True, "group_ids": ["grp-win"],
                    "rules": [{"name": "updates", "action": "ALLOW", "host_pattern": "*.windowsupdate.com", "path_pattern": "/**", "enabled": True}]}})
    check("exe: create policy set", st in (200, 201) and ps.get("id"), ps)
    st, pub = c.call("POST", f"/api/policy-sets/{ps['id']}/publish", {"comment": "wine e2e"})
    check("exe: publish policy set", st == 200, pub)
    st, bundle = c.call("GET", "/api/dataplane/bundle", headers={"X-Aegis-DataPlane-Key": DPK})
    check("exe: data-plane bundle served with the data-plane key", st == 200 and "windowsupdate" in json.dumps(bundle), str(bundle)[:300])
    st, _ = c.call("GET", "/api/dataplane/bundle", headers={"X-Aegis-DataPlane-Key": "wrong"})
    check("exe: data-plane bundle refused with a wrong key", st == 401, st)
    st, der = c.call("GET", "/api/public/ca/aegis-ca.der", raw=True)
    ossl = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-ext", "basicConstraints"], input=der, capture_output=True)
    check("exe: enterprise root CA generated on Windows paths (DER parses, CA:TRUE)", st == 200 and b"CA:TRUE" in ossl.stdout, ossl.stdout + ossl.stderr)
    st, ps1 = c.call("GET", "/api/public/ca/install-windows.ps1", raw=True)
    check("exe: Windows CA install script served", st == 200 and b"Import-Certificate" in ps1 or b"certutil" in ps1, ps1[:200])

    # Built-in audit rotation: grow the audit trail past 2 x 1 MB.
    cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(120)]
    n = 0
    deadline = time.time() + 600
    while time.time() < deadline:
        files = data_files(P1)
        if any(f.endswith(".gz") for f in files):
            break
        for _ in range(40):
            n += 1
            st, _ = c.call("POST", "/api/groups", {"id": "grp-win", "name": f"Windows servers {n}", "cidrs": cidrs[n % 7:] + cidrs[:n % 7]})
            if st != 200:
                raise RuntimeError(f"group update failed: {st} {_}")
        time.sleep(1.1)  # generations are named with second precision
    files = data_files(P1)
    check("exe: audit log rotated by the control-plane on Windows (no sharing violation)",
          any(len(f) == len("audit.jsonl-20260101000000") for f in files), files)
    check("exe: older generation gzip-compressed one rotation later", any(f.endswith(".gz") for f in files), files)
    st, v = c.call("GET", "/api/audit/verify")
    check("exe: complete audit chain across rotated generations verifies", st == 200 and v.get("valid") and v.get("events_checked", 0) > n, v)
    st, exp = c.call("GET", "/api/audit/export", raw=True)
    lines = [l for l in exp.splitlines() if l.strip()]
    ids = [json.loads(l)["id"] for l in lines]
    check("exe: audit export streams every generation once", st == 200 and len(ids) == len(set(ids)) == v.get("events_checked"), (len(ids), len(set(ids)), v))
    log = dexec(P1, "sh", "-c", "cat /wineprefix/drive_c/aegis/logs/control-plane.log").stdout
    check("exe: AEGIS_LOG_FILE written as JSON lines on the Windows path", log.count('"msg":"audit log rotated"') >= 2 and log.lstrip().startswith("{"), log[:300])

    # Restart: state and audit chain survive.
    st, before = c.call("GET", f"/api/policy-sets/{ps['id']}")
    sh("docker", "restart", "-t", "20", P1, timeout=120)
    check("exe: ready again after restart", wait_ready(B1), "")
    c2 = Client(B1)
    st, _ = c2.call("POST", "/api/auth/login", {"username": "admin", "password": PW})
    st2, after = c2.call("GET", f"/api/policy-sets/{ps['id']}")
    check("exe: published policy set persisted across restart", st == 200 and st2 == 200 and json.dumps(after.get("policy_set", after).get("rules")) == json.dumps(before.get("policy_set", before).get("rules")), after)
    st, v2 = c2.call("GET", "/api/audit/verify")
    check("exe: audit chain still valid after restart", v2.get("valid") and v2.get("events_checked", 0) >= v.get("events_checked", 0), v2)
    tmp = dexec(P1, "sh", "-c", "ls /wineprefix/drive_c/aegis/data | grep -c tmp || true").stdout.strip()
    check("exe: no temporary files left in the data directory", tmp == "0", tmp)
finally:
    print(dexec(P1, "sh", "-c", "tail -3 /wineprefix/drive_c/aegis/logs/control-plane.log").stdout[-600:])
    sh("docker", "rm", "-f", P1, check_rc=False)

# ---------------------------------------------------------------- part 2: Windows service (SCM)
P2 = "aegis-wine-svc"
PORT2 = 18192
B2 = f"http://127.0.0.1:{PORT2}"
sh("docker", "rm", "-f", P2, check_rc=False)
sh("docker", "run", "-d", "--name", P2, "-p", f"127.0.0.1:{PORT2}:8081", "-v", f"{APP}:/app:ro", IMAGE, "sh", "-c",
   "mkdir -p /wineprefix/drive_c/aegis && cp /app/aegis-control-plane.exe /wineprefix/drive_c/aegis/ && exec sleep infinity")
try:
    env2 = dict(SECRETS, CONTROL_PLANE_PORT="8081", AEGIS_PUBLIC_URL=B2, DATA_DIR=r"C:\aegis\data", CERTS_DIR=r"C:\aegis\certs",
                AEGIS_LOG_FILE=r"C:\aegis\logs\control-plane.log", AEGIS_LOG_FORMAT="json", AEGIS_THREATINTEL_AUTOUPDATE="false",
                AEGIS_SHUTDOWN_DELAY="0s")
    # Real Windows passes the service's REG_MULTI_SZ "Environment" value (written by the installer); Wine's
    # SCM ignores it, so the variables go into the machine environment and services.exe is restarted.
    for k, v in env2.items():
        dexec(P2, "wine", "reg", "add", r"HKLM\System\CurrentControlSet\Control\Session Manager\Environment", "/v", k, "/d", v, "/f")
    dexec(P2, "sh", "-c", "wineserver -k; wineserver -w; wineserver -p")
    # ImagePath as written by the installer: the explicit "service" entry point.
    p = dexec(P2, "wine", "sc", "create", "AegisControlPlane", "binPath=", r"C:\aegis\aegis-control-plane.exe service", "start=", "demand")
    check("svc: sc create (ImagePath with the service argument)", p.returncode == 0, p.stdout + p.stderr)
    p = dexec(P2, "wine", "net", "start", "AegisControlPlane", timeout=180)
    ready = wait_ready(B2, 90)
    check("svc: net start -> control-plane ready (svc.Run / Execute under the SCM)", ready, p.stdout + p.stderr)
    if ready:
        c = Client(B2)
        st, _ = c.call("POST", "/api/auth/login", {"username": "admin", "password": PW})
        check("svc: login through the service instance (configuration from the machine environment; Wine ignores the per-service Environment value)", st == 200, st)
        c.call("POST", "/api/groups", {"id": "grp-svc", "name": "svc", "cidrs": ["10.30.0.0/16"]})
    q = dexec(P2, "wine", "sc", "query", "AegisControlPlane")
    check("svc: sc query reports RUNNING", "RUNNING" in q.stdout, q.stdout + q.stderr)
    p = dexec(P2, "wine", "net", "stop", "AegisControlPlane", timeout=120)
    time.sleep(2)
    q = dexec(P2, "wine", "sc", "query", "AegisControlPlane")
    log = dexec(P2, "sh", "-c", "cat /wineprefix/drive_c/aegis/logs/control-plane.log").stdout
    check("svc: net stop -> STOPPED", "STOPPED" in q.stdout, q.stdout + p.stdout + p.stderr)
    check("svc: stop request handled gracefully (state flushed)", "control-plane stopped, state flushed to disk" in log, log[-500:])
    st_file = dexec(P2, "sh", "-c", "cat /wineprefix/drive_c/aegis/data/aegis_state.json").stdout
    check("svc: change made through the service is persisted", "grp-svc" in st_file, len(st_file))
    p = dexec(P2, "wine", "net", "start", "AegisControlPlane", timeout=180)
    check("svc: restart through the SCM", wait_ready(B2, 90), p.stdout + p.stderr)
    dexec(P2, "wine", "net", "stop", "AegisControlPlane", timeout=120)
    q = dexec(P2, "wine", "sc", "query", "AegisControlPlane")
    check("svc: clean stop reports exit code 0", "WIN32_EXIT_CODE    : 0" in q.stdout, q.stdout)
    # A configuration error must stop the service with an error instead of hanging in START_PENDING.
    dexec(P2, "wine", "reg", "add", r"HKLM\System\CurrentControlSet\Control\Session Manager\Environment", "/v", "AEGIS_AUDIT_ROTATE_MB", "/d", "-1", "/f")
    dexec(P2, "sh", "-c", "wineserver -k; wineserver -w; wineserver -p")
    p = dexec(P2, "wine", "net", "start", "AegisControlPlane", timeout=180)
    time.sleep(3)
    q = dexec(P2, "wine", "sc", "query", "AegisControlPlane")
    check("svc: configuration error -> service STOPPED with exit code 1 (reported, not hanging)", "STOPPED" in q.stdout and "WIN32_EXIT_CODE    : 1 " in q.stdout, q.stdout + p.stdout)
finally:
    sh("docker", "rm", "-f", P2, check_rc=False)

print(f"\n{sum(res)}/{len(res)} passed")
sys.exit(0 if all(res) else 1)
