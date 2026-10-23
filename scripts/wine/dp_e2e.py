"""Proxy end-to-end test of the Windows builds under Wine: aegis-control-plane.exe plus the data-plane on
python.org's Windows CPython (mitmproxy 12.3.0 win_amd64 wheels), started with the same mitmdump
arguments as deploy/windows/aegis-dataplane.xml. HTTPS traffic goes through the proxy from the container.

Usage: python3 -I dp_e2e.py <dir with aegis-control-plane.exe> <Windows Python dir> <repo>/data-plane
"""
import json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request

APP, PY, DP = (os.path.abspath(a) for a in sys.argv[1:4])
IMAGE = "aegis-test-wine:local"
NAME = "aegis-wine-dp"
PORT = 18193
CP = f"http://127.0.0.1:{PORT}"
PW = "Wine-Proxy-Pass-2026x"
DPK = "wine-dataplane-key-0123456789abcdef0123456789"
res = []


def check(name, cond, detail: object = ""):
    res.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" -> {str(detail)[:500]}"), flush=True)


def sh(*args, timeout=180):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def dexec(*cmd, env=None, detach=False, timeout=180):
    args = ["docker", "exec"] + (["-d"] if detach else [])
    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]
    return sh(*args, NAME, *cmd, timeout=timeout)


cookie = ""


def call(m, p, b=None):
    global cookie
    data = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(CP + p, data=data, method=m, headers={"X-Requested-With": "aegis-ui", "Content-Type": "application/json", "Cookie": cookie})
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            if x.headers.get_all("Set-Cookie"):
                cookie = "; ".join(c.split(";")[0] for c in x.headers.get_all("Set-Cookie"))
            raw = x.read()
            return x.status, json.loads(raw) if raw and x.headers.get_content_type() == "application/json" else raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def wait(cond, seconds):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def curl(url, *extra):
    p = dexec("curl", "-sS", "-o", "/tmp/body", "-w", "%{http_code} %{ssl_verify_result}", "--max-time", "60",
              "--proxy", "http://127.0.0.1:8080", "--cacert", "/tmp/aegis-ca.pem", *extra, url)
    body = dexec("cat", "/tmp/body").stdout
    return p.stdout.strip(), p.stderr.strip(), body


sh("docker", "rm", "-f", NAME)
sh("docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{PORT}:8081", "-v", f"{APP}:/app:ro", "-v", f"{PY}:/py:ro",
   "-v", f"{DP}:/dp:ro", IMAGE, "sh", "-c",
   "mkdir -p /wineprefix/drive_c/aegis && cp /app/aegis-control-plane.exe /wineprefix/drive_c/aegis/ && exec sleep infinity")
try:
    cp_env = {"CONTROL_PLANE_PORT": "8081", "AEGIS_PUBLIC_URL": CP, "DATA_DIR": r"C:\aegis\data", "CERTS_DIR": r"C:\aegis\certs",
              "AEGIS_LOG_FILE": r"C:\aegis\logs\control-plane.log", "AEGIS_THREATINTEL_AUTOUPDATE": "false",
              "AEGIS_JWT_SECRET": "wine-jwt-secret-0123456789abcdef0123456789abcd", "AEGIS_DATAPLANE_KEY": DPK,
              "AEGIS_ENCRYPTION_KEY": "wine-encryption-key-0123456789abcdef0123456789ab", "AEGIS_BOOTSTRAP_ADMIN_PASSWORD": PW}
    dexec("wine", r"C:\aegis\aegis-control-plane.exe", env=cp_env, detach=True)
    check("control-plane .exe ready", wait(lambda: urllib.request.urlopen(CP + "/readyz", timeout=2).status == 200, 120))
    st, _ = call("POST", "/api/auth/login", {"username": "admin", "password": PW})
    call("POST", "/api/groups", {"id": "grp-all", "name": "All", "cidrs": ["0.0.0.0/0"]})
    st, ps = call("POST", "/api/policy-sets", {"kind": "baseline", "spec": {"name": "Wine proxy", "enabled": True, "rules": [
        {"name": "example", "action": "ALLOW", "host_pattern": "example.com", "path_pattern": "/**", "methods": ["GET"], "enabled": True}]}})
    st, _ = call("POST", f"/api/policy-sets/{ps['id']}/publish", {"comment": "wine proxy e2e"})
    check("policy published (allow example.com, default deny)", st == 200, _)
    ca = urllib.request.urlopen(CP + "/api/public/ca/aegis-ca.pem").read()
    ca_file = os.path.join(tempfile.mkdtemp(prefix="aegis-wine-"), "aegis-ca.pem")
    open(ca_file, "wb").write(ca)
    sh("docker", "cp", ca_file, f"{NAME}:/tmp/aegis-ca.pem")

    # Data-plane: same arguments and environment as the WinSW service definition.
    dp_env = {"CONTROL_PLANE_URL": "http://127.0.0.1:8081", "AEGIS_DATAPLANE_KEY": DPK, "AEGIS_OPS_ADDR": "127.0.0.1:9091",
              "AEGIS_FAIL_MODE": "closed", "AEGIS_PROXY_MODE": "regular", "AEGIS_ACCESS_LOG": r"C:\aegis\logs\access.log",
              "AEGIS_ACCESS_LOG_FORMAT": "json", "AEGIS_WORKER_ID": "win-worker-1", "PYTHONNOUSERSITE": "1",
              "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1"}
    mitm_args = ["-s", r"Z:\dp\aegis_addon.py", "--set", r"confdir=C:\aegis\certs", "--listen-host", "127.0.0.1", "--listen-port", "8080",
                 "--set", "connection_strategy=lazy", "--set", "rawtcp=false", "--set", "onboarding=false", "--set", "block_global=false",
                 "--set", "ssl_insecure=false", "--set", "tls_version_server_min=TLS1_2", "--set", "body_size_limit=50m",
                 "--set", "termlog_verbosity=info"]
    launcher = "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"
    cmd = " ".join(["wine", r"'Z:\py\python.exe'", "-c", f"'{launcher}'"] + [f"'{a}'" for a in mitm_args]) + " < /dev/null 2>&1 | cat > /tmp/dp.log"
    # Attached (not docker exec -d): Wine hands Python invalid standard handles in detached sessions.
    dp_args = ["docker", "exec"]
    for k, v in dp_env.items():
        dp_args += ["-e", f"{k}={v}"]
    dp_proc = subprocess.Popen(dp_args + [NAME, "sh", "-c", cmd], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    up = wait(lambda: "200" in dexec("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1:9091/readyz").stdout, 180)
    check("data-plane on Windows CPython: ops /readyz (bundle synced)", up, dexec("tail", "-20", "/tmp/dp.log").stdout)

    st, state = call("GET", "/api/state?exclude_flows=1")
    dps = [d for d in (state.get("data_planes") or []) if d.get("id") == "win-worker-1"]
    check("worker heartbeat reaches the control-plane (healthy)", dps and dps[0].get("healthy"), state.get("data_planes"))
    check("YARA-X engine loaded on Windows (heartbeat)", dps and dps[0].get("yara_status") in ("idle", "ok"), dps[:1])

    code, err, body = curl("https://example.com/")
    check("allowed HTTPS via TLS interception with the enterprise CA (curl verifies the Aegis-issued certificate)", code.startswith("200 0") and "Example Domain" in body, (code, err))
    issuer = dexec("sh", "-c", "curl -sv --max-time 60 --proxy http://127.0.0.1:8080 --cacert /tmp/aegis-ca.pem -o /dev/null https://example.com/ 2>&1 | grep -i 'issuer:'").stdout
    check("certificate for example.com issued by the AegisProxy root CA", "AegisProxy" in issuer, issuer)
    code, err, body = curl("https://www.wikipedia.org/")
    check("default deny: HTTPS to a host without a rule is blocked with the block page", code.startswith("403") and "aegisproxy" in body.lower() and "access blocked" in body.lower(), (code, err, body[:200]))
    code, err, body = curl("http://example.com/", "-X", "POST", "-d", "x=1")
    check("method restriction: POST to example.com blocked", code.startswith("403"), (code, err))

    time.sleep(3)
    log = dexec("sh", "-c", "cat /wineprefix/drive_c/aegis/logs/access.log").stdout
    recs = [json.loads(l) for l in log.splitlines() if l.strip()]
    verdicts = {(r.get("host"), r.get("verdict")) for r in recs}
    check("access log written on the Windows path (JSON, allowed + blocked)", ("example.com", "ALLOWED") in verdicts and any(v == "BLOCKED" for _, v in verdicts), verdicts)
    def flows_seen():
        st, state = call("GET", "/api/state")
        return isinstance(state, dict) and any("wikipedia" in json.dumps(f) for f in state.get("flows") or [])
    check("flow records delivered to the control-plane", wait(flows_seen, 30), "")
finally:
    print(dexec("tail", "-15", "/tmp/dp.log").stdout[-1500:])
    sh("docker", "rm", "-f", NAME)

print(f"\n{sum(res)}/{len(res)} passed")
sys.exit(0 if all(res) else 1)
