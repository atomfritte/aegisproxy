# AegisProxy on Windows Server

This guide covers a production installation of AegisProxy on Windows Server without containers:
the control-plane as a native Windows service, the mitmproxy data-plane as a WinSW-wrapped service,
ClamAV for malware scanning, and the web console served either by the control-plane or by IIS.

All configuration variables are documented in [`docs/configuration.md`](../configuration.md). The Linux
counterpart of this guide is [`linux.md`](linux.md).

| Artefact | Purpose |
|---|---|
| `deploy/windows/Install-AegisControlPlane.ps1` | Install/upgrade/remove the control-plane service `AegisControlPlane` |
| `deploy/windows/Install-AegisDataPlane.ps1` | Install/upgrade/remove a data-plane worker `AegisDataPlane` (Python venv + WinSW) |
| `deploy/windows/aegis-dataplane.xml` | WinSW service template rendered by the data-plane script |
| `deploy/windows/Install-AegisConsole-IIS.ps1` | Host the web console on IIS 10 with HTTPS |
| `deploy/windows/iis/web.config` | IIS configuration: SPA routing, security headers, caching, optional ARR `/api` proxy |

---

## 1. Architecture

```
 Client servers (Windows / Linux)                           Administrators (browser)
 HTTP(S)_PROXY=http://<user>:<token>@proxy:8080                   │ HTTPS
 or source-IP identity (WinHTTP)                                  ▼
            │                                      ┌──────────────────────────────┐
            ▼                                      │ IIS (optional)               │
 ┌──────────────────────────────┐                  │ console + /api via ARR       │
 │ Data-plane worker(s)         │                  └──────────────┬───────────────┘
 │ service AegisDataPlane       │  policy bundle (2 s, ETag),     ▼
 │ mitmdump 12.3.0 + addon      │  threat intel, flows,  ┌──────────────────────────────┐
 │ :8080 proxy  :9091 ops       │──────────────────────▶ │ Control-plane                │
 │ fail-closed before 1st sync  │  HTTPS + data-plane key│ service AegisControlPlane    │
 └──────┬───────────────┬───────┘                        │ :8081 API (+ console)        │
        │               │ INSTREAM tcp/3310              │ state: file  |  PostgreSQL   │
        │               ▼                                └──────────────────────────────┘
        │        ClamAV clamd (loopback)
        ▼
  Internet / partner networks (upstream TLS always verified, TLS >= 1.2)
```

**Control-plane** (`aegis-control-plane.exe`, one static Go binary): REST API, policy engine, threat
intelligence feeds, audit trail, and optionally the web console (`AEGIS_UI_DIR`). It implements the Windows
Service Control Manager protocol itself under the fixed service name **`AegisControlPlane`**, so no wrapper is
needed: the installer registers `"…\aegis-control-plane.exe" service`, the explicit SCM entry point (without the
argument the binary runs in the foreground; installations from before 2.1 without it are still detected as a
service). Because the SCM discards stdout, it logs to `AEGIS_LOG_FILE`; errors that stop the service are also
written to the *Application* event log (source `AegisControlPlane`).

**Data-plane** (mitmproxy `mitmdump` + the `aegis_dp` addon): the explicit HTTP/HTTPS proxy that client
servers use. It identifies the calling server (per-server token or source IP), decrypts TLS with the enterprise
root CA, enforces the policy bundle, scans downloads with ClamAV, and streams telemetry to the control-plane.
mitmdump is not SCM-aware and therefore runs under [WinSW](https://github.com/winsw/winsw).

**Trust relationships**

| Secret | Created by | Used by | Notes |
|---|---|---|---|
| Data-plane key (`dataplane.key`) | control-plane installer | control-plane + every worker | authenticates workers, signs block tokens; mismatch = HTTP 401 at the control-plane, 503 at the proxy |
| JWT secret (`jwt.key`) | control-plane installer | control-plane replicas | console sessions; identical on all replicas |
| Enterprise root CA (`mitmproxy-ca.pem` = key + cert) | `aegis-control-plane gen-ca` | workers (key), clients (cert only) | the key never leaves admin-only ACLs; the control-plane process itself cannot read it |

**Failure semantics.** A worker answers `503` until it has loaded its first policy bundle
(`AEGIS_FAIL_MODE=closed`). Afterwards it keeps enforcing the last known policy if the control-plane becomes
unavailable, so control-plane upgrades and restarts do not interrupt proxy traffic.

### Topologies

| Topology | When | Layout |
|---|---|---|
| **All-in-one** | evaluation, small sites (< ~200 servers) | control-plane, worker, ClamAV and console on one VM |
| **Separated** | most production sites | 1 control-plane host (file storage) + one or more workers per network zone, each with a local clamd |
| **Cluster** | HA requirements, large fleets | ≥ 2 control-plane nodes + PostgreSQL + load balancer; ≥ 2 workers behind an L4 load balancer with source-IP affinity (section 9) |

### Port matrix

| Source | Destination | Port | Purpose |
|---|---|---|---|
| Client servers | worker | TCP 8080 (`-ListenPort`) | explicit proxy (plain HTTP to the proxy, CONNECT for HTTPS) |
| Workers | control-plane (or its load balancer) | TCP 8081 / 443 | policy sync, telemetry (`CONTROL_PLANE_URL`) |
| Administrators | control-plane / IIS | TCP 8081 / 443 | console + API |
| Client servers | control-plane | TCP 8081 / 443 | block-page access requests, CA download `/api/public/*` |
| Prometheus | control-plane `/metrics`, worker ops port | TCP 8081, 9091 | metrics (ops port is loopback-only by default) |
| Worker | clamd | TCP 3310 (loopback) | malware scanning |
| Control-plane nodes | PostgreSQL | TCP 5432 | cluster storage |
| Workers / control-plane | Internet | TCP 80/443 | upstream traffic, threat-intel feeds |

---

## 2. Prerequisites

| Item | Requirement |
|---|---|
| OS | Windows Server 2019, 2022 or 2025 (2016 works), x64, domain-joined recommended |
| Shell | Windows PowerShell 5.1 or PowerShell 7, elevated ("Run as administrator") |
| Control-plane binary | `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go -C control-plane build -trimpath -ldflags "-s -w -X main.Version=2.1.0" -o aegis-control-plane.exe .` |
| Web console | `npm --prefix frontend ci` and `npm --prefix frontend run build` → `frontend\dist` |
| Python (workers) | **python.org CPython 3.12+ (64-bit), installed "for all users" into `C:\Program Files\Python312`** (the default of `InstallAllUsers=1`). Silent: `python-3.12.x-amd64.exe /quiet InstallAllUsers=1 Include_launcher=1 InstallLauncherAllUsers=1 PrependPath=0`. Chocolatey: `choco install python312 --params "/InstallDir:'C:\Program Files\Python312'"` (its default `C:\Python312` lets users create files there) |
| WinSW (workers) | `WinSW-x64.exe` from a 2.x release on <https://github.com/winsw/winsw/releases> (MIT). It is never downloaded by the scripts; the data-plane script verifies it against `-WinSWSha256` (default: WinSW 2.12.0 x64, `05B82D46…3A0DA`) and aborts on a mismatch before changing anything |
| ClamAV (workers) | ClamAV for Windows MSI (x64) from <https://www.clamav.net/downloads> |
| TLS | server certificate from your PKI for the console/API host name (PEM for native TLS, certificate store for IIS) |
| Sizing (starting point) | control-plane 2 vCPU / 4 GB; worker 4 vCPU / 8 GB. Memory grows with concurrent large downloads (bodies up to `av_max_scan_bytes` are buffered for scanning); measure with `/metrics` |

> **Do not use mitmproxy's Windows installer / PyInstaller binaries.** The bundled executables do not
> necessarily contain every standard-library module the addon imports (`http.server`, `hmac`, `gzip`, ...).
> The data-plane script creates a virtual environment from the python.org interpreter and installs
> `mitmproxy==12.3.0` with pip. The Microsoft Store Python and per-user installations (`C:\Users\...`) are
> rejected because the service account cannot read them. The interpreter must also be writable by nobody but
> SYSTEM, Administrators, TrustedInstaller and the data-plane service (an allowlist: any other user or group,
> e.g. Users, Power Users, Remote Desktop Users, a domain group or a single account, counts). Checked are the
> owner and every allow ACE - also inherited and inherit-only ones - of the Python directory, `python.exe`, `Lib`,
> `DLLs`, `Lib\site-packages`, the `*.dll` and `*._pth` files next to `python.exe`, and `*.pth`,
> `sitecustomize.py` and `usercustomize.py` in `Lib` and `site-packages`; for the directory above the Python
> directory, its owner and whether others may delete or rename its entries or change its ACL. Code planted there
> (`python3XX.dll`, `Lib\sitecustomize.py`, a `.pth` file, a replaced Python directory) would run in the service.
> `-AllowWritablePython` overrides this check (not recommended).

Copy a deployment package to the target host, for example:

```
C:\Install\AegisProxy\
  aegis-control-plane.exe
  WinSW-x64.exe
  deploy\windows\...           (scripts, template, iis\web.config)
  data-plane\                  (aegis_addon.py, aegis_dp\)
  frontend\dist\               (built console)
```

If the scripts were downloaded, unblock them first: `Get-ChildItem C:\Install\AegisProxy -Recurse | Unblock-File`.
Run them with `powershell.exe -ExecutionPolicy RemoteSigned -File ...` or sign them with your code-signing
certificate if your policy is `AllSigned`.

---

## 3. Install the control-plane

```powershell
cd C:\Install\AegisProxy\deploy\windows
$pw = Read-Host 'Initial admin password (min. 12 chars)' -AsSecureString
.\Install-AegisControlPlane.ps1 `
    -BinaryPath ..\..\aegis-control-plane.exe `
    -PublicUrl https://aegis.corp.example:8081 `
    -UiDir ..\..\frontend\dist `
    -TlsCertFile C:\pki\aegis.corp.example.crt.pem -TlsKeyFile C:\pki\aegis.corp.example.key.pem `
    -BootstrapAdminPassword $pw `
    -FirewallRemoteAddress 10.0.0.0/8 `
    -GenerateMetricsToken
```

What the script does (idempotent - re-running it upgrades the binary and keeps secrets, CA and state):

1. Copies the binary to `C:\Program Files\AegisProxy\control-plane\` and the console to `...\ui\`. The program
   directory gets its own ACL (SYSTEM/Administrators full control, Users and the service read/execute), also for a
   custom `-InstallDir` outside `Program Files` - the log rotation script there must not be replaceable.
2. Creates `C:\ProgramData\AegisProxy\{data,certs,secrets,logs}`, removes the inherited ProgramData ACL
   (which lets every user create files) and grants SYSTEM/Administrators full control. Directories that already
   exist are taken over top-down, so that their creator cannot swap in a link meanwhile: first the root
   (Administrators become owner, protected ACL, explicit ACEs of other accounts removed - from then on nobody
   else can add, delete or rename entries in it), then each entry below, always after its parent (owner
   Administrators, explicit ACEs dropped so that it inherits the new ACL). `icacls` runs with `/L` (a link itself
   is changed, never its target) and without `/T` (which follows links); only an upgrade of an intact
   installation resets each subdirectory with one recursive `icacls /T /L` run. Junctions, symbolic links and
   files with further hard links (they share their ACL with a file elsewhere) are refused, before any change
   and again while each item is taken over. Files that appear in the directories between the inspection and the
   lock-down are reported and stop the installation. After the service grants the script reads every ACL back
   (owner Administrators/SYSTEM; only SYSTEM, Administrators, the service and - for program files - Users
   read) and stops before starting the service if anything else is found.
   **Pre-existing files.** Because every user may create `C:\ProgramData\AegisProxy` before the first
   installation, files found there (and in the program directory) are only kept on an upgrade of an intact
   installation - service registered, directories owned by Administrators with exactly these ACLs. Otherwise the
   script refuses to adopt them (a planted `jwt.key`, CA or state file would give their author a known key or an
   admin account) and lists them. Pass `-AdoptExistingSecrets` when they are yours: restore of a backup on a new
   host, reinstallation after `-Uninstall` (which keeps the data), an interrupted first run, or an installation
   from a Windows client edition, where the creating administrator (not the Administrators group) owns the
   directories.
3. Generates missing secrets (32 random bytes, hex) in `secrets\` and passes them **only as file paths**
   (`AEGIS_JWT_SECRET_FILE`, `AEGIS_DATAPLANE_KEY_FILE`, `AEGIS_DATABASE_URL_FILE`, ...). The per-service
   environment lives in the registry (`HKLM\SYSTEM\CurrentControlSet\Services\AegisControlPlane\Environment`),
   which local users can read - therefore no secret values are stored there, and the script refuses plain
   secret variables in `-ExtraEnvironment` (`AEGIS_JWT_SECRET`, `AEGIS_DATAPLANE_KEY`, `AEGIS_ENCRYPTION_KEY`,
   `AEGIS_ENCRYPTION_KEY_PREVIOUS`, `AEGIS_BOOTSTRAP_ADMIN_PASSWORD`, `AEGIS_METRICS_TOKEN`, `AEGIS_DATABASE_URL`)
   and removes them if an earlier installation left them there.
4. Runs `aegis-control-plane.exe gen-ca` if no CA exists and restricts `certs\mitmproxy-ca.pem` (the CA private
   key) to SYSTEM/Administrators. The control-plane only reads the public certificate.
5. Registers the service (`Automatic`), runs it as the virtual account **`NT SERVICE\AegisControlPlane`**,
   reduces its token to `SeChangeNotifyPrivilege`, and configures recovery
   (`restart/5000/restart/5000/restart/30000`, reset after 24 h, `failureflag 1` so that error exits also
   trigger a restart).
6. Grants the service account *modify* on `data` and `logs`, *read* on `certs` and `secrets` (inheritance
   removed on `secrets`).
7. Creates the firewall rule `AegisProxy-ControlPlane-In` (Domain profile by default; restrict
   `-FirewallRemoteAddress` to admin networks, workers and load balancers).
8. Registers the scheduled task `\AegisProxy\AegisProxy Control-Plane Log Rotation` (daily copy/truncate of
   `control-plane.log`, zipped, `-LogRetentionDays`). It runs as `NT SERVICE\AegisControlPlane`, not as SYSTEM:
   the service can modify the log directory, so a privileged task working there could be redirected by links the
   service planted. The script itself (`Invoke-AegisLogRotation.ps1` in the program directory) is read-only for
   that account.
9. Starts the service, waits for `/healthz`, and prints the CA fingerprint, the data-plane key path and the
   admin password location.

Important parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `-PublicUrl` | – (mandatory) | `AEGIS_PUBLIC_URL`: externally reachable URL (block pages, installers, links). Use `https://` |
| `-Port` / `-ListenAddress` | `8081` / – | `CONTROL_PLANE_PORT` / `AEGIS_LISTEN_ADDR` (e.g. `127.0.0.1:8081` behind a local IIS/ARR) |
| `-UiDir` | – | serve the console from the control-plane (same origin, simplest option) |
| `-Storage` / `-DatabaseUrl` | `file` / – | `postgres` for cluster mode (section 9) |
| `-TlsCertFile` / `-TlsKeyFile` | – | native HTTPS (PEM, unencrypted key) |
| `-TrustedProxies` / `-CorsOrigins` | – | `AEGIS_TRUSTED_PROXIES` / `AEGIS_CORS_ORIGINS` |
| `-ExtraEnvironment` | – | further non-secret variables, e.g. `@{ AEGIS_INTERNAL_DOMAINS = '.corp.example,.local' }` |
| `-ImportSecretsDir` / `-CaSourceDir` | – | join an existing cluster (identical secrets and CA); SMB sources must be encrypted (section 9) |
| `-AllowUnencryptedImport` | – | accept `-ImportSecretsDir` / `-CaSourceDir` over an unencrypted SMB connection |
| `-AdoptExistingSecrets` | – | keep secrets, CA, state and program files that existed before a first installation (see step 2) |
| `-Uninstall` | – | removes service, firewall rule, task and binaries (links inside are removed as links, never followed); **keeps** `C:\ProgramData\AegisProxy` |

Parameters that are not passed on a re-run keep their previous values (storage mode, port, trusted proxies,
CORS origins, extra variables). `-PublicUrl` must always be given.

**First login.** Open the console, sign in as `admin` with the bootstrap password (or the random password in
`C:\ProgramData\AegisProxy\data\secrets\initial-admin-password`), change it, create personal accounts with the
appropriate roles, then delete the password file (and, if used, `secrets\bootstrap-admin-password` followed by a
re-run of the installer).

---

## 4. TLS

| Option | Configuration |
|---|---|
| Native TLS on the control-plane | `-TlsCertFile`/`-TlsKeyFile` (stored as `secrets\tls-cert.pem` / `tls-key.pem`). TLS ≥ 1.2 |
| IIS in front (console + API via ARR) | `-ListenAddress 127.0.0.1:8081`, `-TrustedProxies 127.0.0.1/32`, enable the ARR rule in `web.config` |
| Load balancer termination | `-TrustedProxies <LB addresses>`; `-PublicUrl` = the LB URL |

Convert a PFX into PEM files (OpenSSL, e.g. from Git for Windows):

```powershell
openssl pkcs12 -in aegis.pfx -clcerts -nokeys -out aegis.crt.pem     # add intermediates to this file
openssl pkcs12 -in aegis.pfx -nocerts -nodes  -out aegis.key.pem
```

Certificate renewal: re-run the installer with the new files (the service is restarted, sessions survive).
Delete the transferred key files afterwards.

**Worker → control-plane trust.** Python on Windows trusts the Windows certificate store, so a control-plane
certificate issued by an internal CA that is distributed by GPO works without extra settings. Otherwise pass
`-ControlPlaneCaFile` (PEM bundle → `AEGIS_CONTROL_PLANE_CA_FILE`; when set, *only* this bundle is used).

---

## 5. ClamAV (antivirus)

1. Install the ClamAV MSI (default `C:\Program Files\ClamAV`).
2. Create the configuration from the samples and remove the `Example` line in both files:
   ```powershell
   cd 'C:\Program Files\ClamAV'
   copy .\conf_examples\clamd.conf.sample .\clamd.conf
   copy .\conf_examples\freshclam.conf.sample .\freshclam.conf
   notepad .\clamd.conf ; notepad .\freshclam.conf
   ```
   `clamd.conf`:
   ```
   TCPSocket 3310
   TCPAddr 127.0.0.1
   StreamMaxLength 100M
   MaxScanSize 400M
   MaxFileSize 100M
   LogFile C:\ProgramData\ClamAV\clamd.log
   LogTime yes
   ```
   `StreamMaxLength` must be ≥ the policy value `av_max_scan_bytes` (console → Threat Protection → Protection
   Policy, default 25 MiB); larger downloads are not scanned and are handled per `av_oversize_action`.
   `freshclam.conf`: keep `DatabaseMirror database.clamav.net`; for an internal mirror use `PrivateMirror`.
   If freshclam itself must use a proxy, set `HTTPProxyServer`/`HTTPProxyPort` and allow
   `database.clamav.net` in AegisProxy (or give the worker host direct access to the mirror).
3. Download the signatures once: `.\freshclam.exe`.
4. Run clamd and freshclam permanently - as services (ClamAV ≥ 0.104):
   ```powershell
   .\clamd.exe --install-service ; .\freshclam.exe --install-service
   Get-Service clamd, freshclam | Set-Service -StartupType Automatic -PassThru | Start-Service
   ```
   Service names differ between ClamAV builds; check with `Get-Service *clam*`. Alternatively, run freshclam
   as a scheduled task (clamd reloads updated signatures by itself, no restart needed):
   ```powershell
   $a = New-ScheduledTaskAction -Execute 'C:\Program Files\ClamAV\freshclam.exe'
   $t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 2)
   Register-ScheduledTask -TaskName 'ClamAV freshclam' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest
   ```
5. Check: `Test-NetConnection 127.0.0.1 -Port 3310`. The worker exposes `aegis_dp_clamd_available` on `/metrics`.

The worker is configured with `-ClamdAddress tcp://127.0.0.1:3310` (default). `unix://` sockets are not
available on Windows. An empty `-ClamdAddress ''` disables scanning on that worker.

---

## 6. Install a data-plane worker

```powershell
cd C:\Install\AegisProxy\deploy\windows
.\Install-AegisDataPlane.ps1 `
    -ControlPlaneUrl https://aegis.corp.example:8081 `
    -DataPlaneKeyFile C:\ProgramData\AegisProxy\secrets\dataplane.key `
    -CaFile C:\ProgramData\AegisProxy\certs\mitmproxy-ca.pem `
    -WinSWExe C:\Install\AegisProxy\WinSW-x64.exe `
    -AllowedRemoteAddress 10.20.0.0/16,10.30.0.0/16
```

On a separate host, copy `dataplane.key` and `mitmproxy-ca.pem` from the control-plane over an
administrative channel (SMB with encryption - `New-SmbMapping -RemotePath '\\cp1\c$' -RequirePrivacy $true` - or
your secret store), run the script, then delete the copies - the script stages its own copies with tight ACLs.
When `-DataPlaneKeyFile` / `-CaFile` point to an SMB path, the script checks `Get-SmbConnection` and refuses an
unencrypted connection unless `-AllowUnencryptedImport` is given. Every spelling of a network path counts:
`\\server\share`, `//server/share` and mixed separators, `\\?\UNC\...`, `\\.\UNC\...`, `\??\UNC\...`,
`FileSystem::\\...` and drive letters mapped to a share (also as `\\?\Z:\...`). Other device paths
(`\\?\GLOBALROOT\...`, `\\?\Volume{...}\...`) are refused - pass a drive-letter or UNC path. Shares of the host
itself (`localhost`, `127.x.x.x`, `::1`) are accepted with a note: the files do not cross the network. Without
`-CaFile`, the CA of a control-plane on the same host is used only if the `AegisControlPlane` service is installed
and `C:\ProgramData\AegisProxy\certs\mitmproxy-ca.pem` is restricted to SYSTEM/Administrators.

The script:

1. Verifies WinSW against `-WinSWSha256`, resolves Python (`py -3.12`, then 3.13/3.14, or `-PythonExe`) and refuses
   an interpreter that non-administrators can modify (section 2), creates
   `C:\Program Files\AegisProxy\data-plane\venv` (the program directory gets its own ACL: SYSTEM/Administrators
   full control, Users and the service read/execute) and installs `mitmproxy==12.3.0`, `yara-x==1.22.0` and the
   security overrides of `data-plane\requirements-security.txt`, then verifies that `http.server`, `hmac`,
   `gzip`, `ssl` and the addon import correctly. Existing program and data directories are taken over like on the
   control-plane (top-down, owner Administrators, foreign ACEs removed, links and hard-linked files refused, files
   planted during the run refused, ACLs verified after the installation); on a first installation, pre-existing files there - a staged CA, a control-plane CA bundle, a
   `confdir\config.yaml` (mitmdump options and scripts), a prepared venv or .NET extraction cache - are refused
   unless `-AdoptExistingSecrets` is given. Logs are kept either way.
2. Copies `aegis_addon.py` and `aegis_dp\` to `...\data-plane\app` (byte-compiled; the program directory is
   read-only for the service).
3. Stages the key (`C:\ProgramData\AegisProxy\data-plane\secrets\dataplane.key`, read-only for the service) and
   the CA (`...\confdir\mitmproxy-ca.pem`; mitmproxy needs a writable confdir for its dhparam file).
4. Renders `aegis-dataplane.xml` from the template, copies WinSW into the admin-only program directory and
   verifies the SHA-256 of that copy (the file the SCM runs; `-WinSWExe` may have changed after the early check),
   installs it as `aegis-dataplane.exe` and the service `AegisDataPlane`, and switches its logon account to
   **`NT SERVICE\AegisDataPlane`** before the first start. The mitmdump arguments are identical to `data-plane/entrypoint.sh`
   (`connection_strategy=lazy`, `rawtcp=false`, `onboarding=false`, `block_global=false`, `ssl_insecure=false`,
   `tls_version_server_min=TLS1_2`, `body_size_limit=1g`).
5. Opens the proxy port for `-AllowedRemoteAddress` only (Domain profile), and the ops port only if
   `-OpsAddr` is not loopback and `-MonitoringRemoteAddress` is given.
6. Starts the service and waits for `http://127.0.0.1:9091/readyz` (= first policy bundle loaded).

**Service account choice.** WinSW installs services as LocalSystem; its `<serviceaccount>` element handles
virtual accounts differently across WinSW versions. The script therefore leaves it out and runs
`sc.exe config AegisDataPlane obj= "NT SERVICE\AegisDataPlane"` before the first start - this works with WinSW
2.x and 3.x and gives the worker its own SID, so ACLs grant access to exactly this service. Use
`-ServiceAccount LocalService` only if virtual accounts are prohibited (LocalService is shared by many
services). The worker never needs LocalSystem.

Further parameters: `-ListenPort` (8080), `-ListenHost` (0.0.0.0), `-OpsAddr` (127.0.0.1:9091),
`-FailMode` (closed), `-WorkerId`, `-PublicUrl`/`-DashboardUrl` (block-page fallbacks), `-ExtraEnvironment`,
`-PipArgs`/`-RequirementsFile` (offline, hash-pinned installation from an internal wheel share - recommended
for production; see below), `-WinSWSha256` (hash of a different WinSW build), `-NoYara` (do not install
the YARA-X engine, which is otherwise installed as `yara-x==1.22.0` binary wheel), `-RecreateVenv`,
`-AllowWritablePython`, `-AllowUnencryptedImport`, `-AdoptExistingSecrets` (see above), `-Uninstall` (removes
service, rules, program files and the staged key/CA copies - links inside are removed as links, their targets are
never touched; keeps logs). `-ExtraEnvironment` refuses the variables the template or a dedicated parameter sets
(`CONTROL_PLANE_URL`, `AEGIS_DATAPLANE_KEY[_FILE]`, `AEGIS_OPS_ADDR`, `AEGIS_FAIL_MODE`, ...).

**Hash-pinned installation.** `-RequirementsFile` takes a complete lock file with hashes for every package,
including `yara-x` and the security baseline. Generate it on a build host with uv, whose `--override` raises
Brotli above mitmproxy's declared upper bound:

```powershell
'mitmproxy==12.3.0', 'yara-x==1.22.0' | Set-Content requirements.in
uv pip compile --python-version 3.12 --python-platform x86_64-pc-windows-msvc --generate-hashes `
    --override data-plane\requirements-security.txt requirements.in -o requirements-win.txt
```

The script installs it with `--require-hashes --no-deps`, aborts if a package is below the baseline of
`requirements-security.txt` (compared by the venv's Python with `packaging`, PEP 440: `1.2.1rc1` is below
`1.2.1`, an unparseable version fails the check), and aborts if `pip check` reports anything other than these
deliberate overrides (an incomplete lock file).

Manage the worker with `Get-Service AegisDataPlane | Restart-Service` or
`& 'C:\Program Files\AegisProxy\data-plane\aegis-dataplane.exe' status`. Logs (rolled by size, 20 MB × 10):
`C:\ProgramData\AegisProxy\data-plane\logs\aegis-dataplane.{out,err,wrapper}.log`.

### Verify

```powershell
Get-Service AegisControlPlane, AegisDataPlane
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9091/readyz          # 200 = policy loaded
curl.exe -x http://127.0.0.1:8080 https://www.example.com/ -I            # 403 block page until a rule allows it
curl.exe -x http://127.0.0.1:8080 http://aegis.ca/ca.crt -o aegis-ca.crt # CA served by the worker (magic host)
```

The console lists the worker under *Data-Plane Workers* with its `AEGIS_WORKER_ID` (default: host name),
heartbeat, policy revision and ClamAV status.

---

## 7. Web console hosting

| Option | How | Notes |
|---|---|---|
| **Control-plane** (recommended) | `-UiDir ..\..\frontend\dist` | same origin, no CORS, CSP set by the control-plane |
| **IIS, API on another origin** | `Install-AegisConsole-IIS.ps1 -ApiBaseUrl https://aegis-api.corp.example` | control-plane needs `-CorsOrigins https://<console host>`; the script adds the API origin to CSP `connect-src` |
| **IIS, same origin via ARR** | enable the `AegisApiReverseProxy` rule in `web.config` | requires ARR 3.0, `responseBufferLimit=0` for the SSE stream; control-plane `-ListenAddress 127.0.0.1:8081 -TrustedProxies 127.0.0.1/32` |

```powershell
.\Install-AegisConsole-IIS.ps1 -HostName aegis-console.corp.example `
    -CertificateThumbprint 3F2A...C9 -ApiBaseUrl https://aegis.corp.example:8081 -AddHttpBinding
```

The IIS script installs the role services, requires the **URL Rewrite** module
(<https://www.iis.net/downloads/microsoft/url-rewrite>; without it IIS returns HTTP 500.19), creates an
application pool with *No Managed Code*, mirrors `dist`, writes `config.js`
(`window.__AEGIS_CONFIG__ = { apiBaseUrl: "..." }`, `Cache-Control: no-store`), deploys `web.config`
(CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP, HSTS,
`/assets/*` cached one year as immutable, SPA fallback that excludes `/assets`, `/config.js`, `/api`), binds HTTPS
with SNI and restricts the site directory to the pool identity. An existing site directory is taken over before
the first file is copied (top-down like the service directories: owner Administrators, foreign ACEs removed,
junctions, symbolic links and hard-linked files refused); the ACL is verified
before the site is started.

Cookies: `AEGIS_COOKIE_SAMESITE=strict` works for `console.corp.example` + `api.corp.example` (same site).
Use `none` only for different registrable domains (requires HTTPS).

---

## 8. Proxy authentication with per-server tokens

Workers identify the calling server in this order: **token** (`Proxy-Authorization`), user name bound to the
server's IP/subnet, then **source IP/subnet** of the server object.

1. Console → *Fleet Inventory* → select the server → set the *proxy auth user* (e.g. `svc-erp-01`) → **Rotate token**. The token is shown
   once and stored only as a hash; rotation revokes the previous token immediately (audited).
2. Configure the client: `http://svc-erp-01:<token>@aegis-proxy.corp.example:8080` (URL-encode special
   characters).
3. Distribute tokens through your secret management (Intune, SCCM with encrypted variables, Ansible Vault,
   HashiCorp Vault), never through tickets or wikis. Rotate on a schedule and when a server is re-imaged.

Limitations and recommendations:

* **WinHTTP / WinINET cannot carry credentials in the proxy URL.** Windows Update, PowerShell, .NET and most
  Windows services are therefore identified by **source IP** - keep server objects' IPs/subnets accurate and make
  sure no NAT sits between servers and workers. Tokens are for tools that honour `HTTP(S)_PROXY` with
  credentials (curl, git, pip, Python, Go, Node.js).
* Machine-wide environment variables are readable by all local users; prefer per-service environment
  (registry `Environment` value of the service, tool config files with restricted ACLs).
* The proxy hop is plain HTTP (the CONNECT request carries the token in clear text). Place workers in a
  network segment that client servers reach without traversing untrusted networks.

---

## 9. Cluster mode (PostgreSQL)

```
            ┌──────────── L7/L4 load balancer :443 → :8081  (health: GET /readyz) ────────────┐
            ▼                                   ▼                                             │
   AegisControlPlane node 1           AegisControlPlane node 2  ...                           │
            └──────────────┬───────────────────┘                                              │
                           ▼                                                                  │
                 PostgreSQL (HA: Patroni / managed / Always-On-like setup)                    │
                                                                                              │
   L4 load balancer :8080  (balance source / source-IP affinity, health: TCP 9091 /readyz)   │
            ▼                         ▼                                                       │
   AegisDataPlane worker 1     AegisDataPlane worker 2  ── CONTROL_PLANE_URL = LB URL ────────┘
```

* **PostgreSQL** 14 or newer (the reference HA deployment uses 17). Create a database and a dedicated role
  (`CREATE ROLE aegis LOGIN PASSWORD '...'; CREATE DATABASE aegis OWNER aegis;`). The schema is created and
  migrated automatically (serialised by an advisory lock). Use TLS: `sslmode=verify-full`.
* **All control-plane nodes need identical** `jwt.key`, `dataplane.key` and CA. The state lives in PostgreSQL;
  `DATA_DIR` only holds caches. Install node 1 with `-Storage postgres -DatabaseUrl ...`, then nodes 2..n:
  ```powershell
  New-SmbMapping -RemotePath '\\node1\c$' -RequirePrivacy $true | Out-Null   # SMB 3 encryption for this session
  $dsn = Read-Host 'PostgreSQL DSN'     # postgres://aegis:...@pg.corp.example:5432/aegis?sslmode=verify-full
  .\Install-AegisControlPlane.ps1 -PublicUrl https://aegis.corp.example -Storage postgres -DatabaseUrl $dsn `
      -ImportSecretsDir \\node1\c$\ProgramData\AegisProxy\secrets `
      -CaSourceDir \\node1\c$\ProgramData\AegisProxy\certs `
      -TrustedProxies 10.10.0.10/32,10.10.0.11/32
  Remove-SmbMapping -RemotePath '\\node1\c$' -Force
  ```
  (`$dsn` ends up in `secrets\database-url`, readable only by the service and administrators.) The secrets and
  the CA private key cross the network: for UNC paths and mapped drives (in every spelling, see section 6) the
  script checks `Get-SmbConnection` and stops unless the connection is encrypted (`-RequirePrivacy $true` as above, or a share with
  `Set-SmbShare -EncryptData $true`). `-AllowUnencryptedImport` overrides the check; copying over another
  protected channel to a local directory works as well.
* **Control-plane load balancer:** round robin, no stickiness needed (sessions are signed JWTs, live updates are
  distributed through PostgreSQL `LISTEN/NOTIFY`), health check `GET /readyz` (includes database
  reachability), `X-Forwarded-For` + `AEGIS_TRUSTED_PROXIES`, idle timeout ≥ 1 h for the SSE stream
  `/api/flows/stream`. `-PublicUrl` is the load balancer URL on every node.
* **Worker load balancer:** plain TCP (L4) with **source-IP affinity** (`balance source`, F5 *source address
  persistence*, NetScaler *SOURCEIP*). Redirect-object grants (an allowed `302` to a signed CDN URL) are held by
  the worker that saw the redirect, so the follow-up request must reach the same worker. The load balancer must
  also **preserve the client IP** (no SNAT / auto-map) unless every server uses tokens, otherwise source-IP
  identification sees the load balancer. Health check: HTTP `GET /readyz` on the ops port (expose it with
  `-OpsAddr 0.0.0.0:9091 -MonitoringRemoteAddress <LB addresses>`). See `deploy/compose/ha/haproxy.cfg` for a
  reference configuration.
* Workers point `CONTROL_PLANE_URL` at the control-plane load balancer and all use the same `dataplane.key`
  and CA.

---

## 10. Rolling out the CA and proxy settings to client servers

Always verify the CA fingerprint printed by the installer (also visible in the console and at
`https://<PublicUrl>/api/public/ca/info`) through a second channel.

### Windows servers

**Group Policy (recommended for domain members)**

* CA: *Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies →
  Trusted Root Certification Authorities → Import* `aegis-enterprise-ca.der`.
* WinHTTP proxy (services, Windows Update, PowerShell): a startup script or GPP scheduled task running
  `netsh winhttp set proxy proxy-server="aegis-proxy.corp.example:8080" bypass-list="<local>;*.corp.example"`.
* Environment variables for CLI tools (*Preferences → Windows Settings → Environment*): `HTTP_PROXY`,
  `HTTPS_PROXY`, `NO_PROXY=localhost,127.0.0.1,.corp.example`.
* Runtimes with their own trust store: `NODE_EXTRA_CA_CERTS`, Java `keytool -importcert -cacerts`,
  Python `requests` (`REQUESTS_CA_BUNDLE` or `pip install pip-system-certs`), `git config --system http.sslBackend schannel`.

**One-shot installer** (non-domain servers, automation): the control-plane serves a fingerprint-pinned script
that adds only the pinned certificate to `LocalMachine\Root` (the download must be exactly that DER certificate;
a PKCS#7/PFX bundle or trailing data is refused), writes a PEM copy to `C:\Program Files\AegisProxy\ca-trust\`
(owner Administrators, ACL reset to SYSTEM/Administrators full and Users read, verified before writing - the
file is trusted machine-wide via `NODE_EXTRA_CA_CERTS`), configures Node.js/Git and - with `$env:AEGIS_PROXY` -
the WinHTTP and machine-wide proxy:

Never pipe the installer into `iex`: download it, compare its SHA-256 with the value the console shows under
**TLS & CA** (also `windows_script_sha256` of `GET /api/public/ca/info`), then run it (elevated):

```powershell
$env:AEGIS_PROXY = 'aegis-proxy.corp.example:8080'
$f = Join-Path $env:TEMP 'aegis-ca-install.ps1'
iwr -UseBasicParsing https://aegis.corp.example/api/public/ca/install-windows.ps1 -OutFile $f
if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '<windows_script_sha256 from the console>') { throw 'SHA-256 mismatch' }
powershell -NoProfile -ExecutionPolicy Bypass -File $f
```

### Linux servers

```bash
curl -fsSLo aegis-ca-install.sh https://aegis.corp.example/api/public/ca/install-linux.sh     # CA trust (pinned)
echo '<linux_script_sha256 from the console>  aegis-ca-install.sh' | sha256sum -c - && sudo bash aegis-ca-install.sh
sudo tee -a /etc/environment <<'EOF'
http_proxy=http://aegis-proxy.corp.example:8080
https_proxy=http://aegis-proxy.corp.example:8080
no_proxy=localhost,127.0.0.1,.corp.example
HTTP_PROXY=http://aegis-proxy.corp.example:8080
HTTPS_PROXY=http://aegis-proxy.corp.example:8080
NO_PROXY=localhost,127.0.0.1,.corp.example
EOF
```

Package managers and daemons need their own settings (apt `Acquire::http::Proxy`, dnf `proxy=`, Docker/containerd
systemd drop-ins). Details: [`linux.md`](linux.md#10-rolling-out-the-ca-and-proxy-settings-to-client-servers).

---

## 11. Upgrades

| Component | Procedure |
|---|---|
| Control-plane | Build the new `aegis-control-plane.exe`, re-run `Install-AegisControlPlane.ps1 -BinaryPath <new> -PublicUrl <same>`. The service stops, the binary is replaced, secrets/state/config are kept. Workers keep enforcing during the restart |
| Console | Rebuild `frontend\dist`; re-run with `-UiDir` (control-plane) or re-run `Install-AegisConsole-IIS.ps1` |
| Data-plane addon | Re-run `Install-AegisDataPlane.ps1` with the new `data-plane` folder |
| mitmproxy / Python | Update the pinned version (or `-RequirementsFile`), re-run with `-RecreateVenv`; a new Python minor version recreates the venv automatically |
| Cluster | One node at a time; wait for `/readyz` on the upgraded node before the next one. Upgrade the control-plane before the workers |

Check `aegis-control-plane.exe version`, `GET /api/public/meta` (field `version`) and `aegis_build_info` on `/metrics`.
Back up before every upgrade (section 12).

---

## 12. Backup and restore

| Data | Location | Notes |
|---|---|---|
| State (file mode) | `C:\ProgramData\AegisProxy\data\aegis_state.json` (+ `.bak`, the previous version) | written atomically; can be copied while the service runs |
| Audit trail | `data\audit.jsonl` (+ `audit.jsonl-YYYYMMDDhhmmss[.gz]`) | append-only JSON Lines, rotated by the control-plane at `AEGIS_AUDIT_ROTATE_MB` (default 256 MB; Windows cannot rename the open file externally), older generations gzip-compressed, never deleted; also ship to your SIEM |
| CA | `certs\` (incl. `mitmproxy-ca.pem` = **private key**) | losing it means re-distributing a new CA to every client |
| Secrets | `secrets\` | `jwt.key`, `dataplane.key`, `database-url`, TLS key, ... |
| PostgreSQL | database `aegis` | `pg_dump -Fc -d aegis -f aegis-$(Get-Date -f yyyyMMdd).dump` |
| Service configuration | registry `HKLM\SYSTEM\CurrentControlSet\Services\AegisControlPlane` | `reg export ... aegis-cp.reg` |

Backups contain the CA private key and all secrets: encrypt them and restrict access like the originals.

Restore (file mode): stop the service, restore `data\`, `certs\` and `secrets\`, re-run the installer (it
re-applies ACLs and the environment), verify `/healthz` and the CA fingerprint. On a new host (no service yet) or
after `-Uninstall`, the installer treats the restored files as pre-existing: pass `-AdoptExistingSecrets`.
Restore (cluster): `pg_restore -c -d aegis aegis-....dump`, restore `secrets\` and `certs\` on every node, start the
nodes.

---

## 13. Monitoring

| Endpoint | Component | Notes |
|---|---|---|
| `GET /healthz`, `GET /readyz` | control-plane | `/readyz` includes database reachability in cluster mode |
| `GET /metrics` | control-plane | Bearer token if `AEGIS_METRICS_TOKEN(_FILE)` is set (`-GenerateMetricsToken`) |
| `GET /healthz`, `/readyz`, `/metrics` | worker ops port (`AEGIS_OPS_ADDR`) | `/readyz` = a policy bundle is loaded |

Prometheus example:

```yaml
scrape_configs:
  - job_name: aegis-control-plane
    scheme: https
    authorization: { credentials_file: /etc/prometheus/aegis-metrics.token }
    static_configs: [{ targets: ['aegis.corp.example:8081'] }]
  - job_name: aegis-dataplane
    static_configs: [{ targets: ['dp-01.corp.example:9091', 'dp-02.corp.example:9091'] }]
```

Suggested alerts: target down; worker `/readyz` failing; `aegis_dp_policy_sync_age_seconds` > 300;
`increase(aegis_dataplane_auth_failures_total[5m]) > 0`; `aegis_dp_clamd_available == 0`;
`aegis_threatintel_feed_age_seconds` older than twice the feed interval; `aegis_security_events_open` rising;
disk space on `C:\ProgramData`. Windows-side: SCM events 7031/7034 (unexpected service termination) in the
*System* log, and errors of source **AegisControlPlane** in the *Application* log (event ID 1: the control-plane
terminated with an error — the message contains the reason, e.g. a configuration error before `AEGIS_LOG_FILE`
is open; ID 2: the service dispatcher failed). The installer registers the source.

### Log files and rotation

| Log | Rotation on Windows |
|---|---|
| `logs\control-plane.log` (`AEGIS_LOG_FILE`) | daily copy/truncate task registered by the installer (`-LogRetentionDays`), runs as `NT SERVICE\AegisControlPlane` |
| `data\audit.jsonl` | by the control-plane at `AEGIS_AUDIT_ROTATE_MB` (default 256 MB) into `audit.jsonl-YYYYMMDDhhmmss`, older generations gzip-compressed, never deleted (retention is your decision; export and verification include all generations) |
| worker access log (`AEGIS_ACCESS_LOG=<file>`) | by the worker at `AEGIS_ACCESS_LOG_ROTATE_MB` (Windows default 100 MB) into `access.log.1 … .N` (`AEGIS_ACCESS_LOG_KEEP`, default 10) |
| WinSW / mitmdump output | `roll-by-size` in the WinSW definition (20 MB × 10) |

Windows cannot rename a file that another process holds open, so external tools cannot rotate the audit and
access logs: the services do it themselves. Log shippers (Filebeat, Splunk UF, Azure Monitor Agent) follow the
renamed files as usual. Set the sizes with `-ExtraEnvironment @{ AEGIS_AUDIT_ROTATE_MB = '512' }`.

---

## 14. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| Clients report `certificate verify failed` / `unable to get local issuer certificate` | CA not trusted on the client, or a runtime with its own store | Install the CA (section 10); set `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, Java `cacerts` |
| Every request through the worker returns **503** | worker never loaded a policy (fail-closed) | Check `.../readyz`; worker logs; control-plane log for `rejected data-plane request with invalid key` (**HTTP 401** → `dataplane.key` differs; re-run the data-plane script with the correct `-DataPlaneKeyFile`) |
| Worker log shows connection/TLS errors to the control-plane | firewall, wrong `CONTROL_PLANE_URL`, untrusted control-plane certificate | `Test-NetConnection <host> -Port 8081`; `-ControlPlaneCaFile` |
| Security events `AV_ERROR` | clamd unreachable/not running, `StreamMaxLength` exceeded | `Test-NetConnection 127.0.0.1 -Port 3310`, `Get-Service *clam*`, align `StreamMaxLength` ≥ `av_max_scan_bytes`; `av_fail_mode` decides between allow+event and 503 |
| Allowed URL is blocked for one server | server not identified (NAT, missing IP/subnet, wrong token) | Check the flow in the console (server column); fix IP/subnet or token; avoid SNAT at load balancers |
| `AegisControlPlane` stops right after start, empty log | configuration error before logging starts (e.g. invalid `AEGIS_PUBLIC_URL`, unreadable `*_FILE`) | Application event log, source `AegisControlPlane`, event ID 1 (`Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='AegisControlPlane'} -MaxEvents 5`); or run in an elevated console with the service environment (below) |
| `AegisDataPlane` does not start | per-user Python, missing venv packages, CA without private key, port in use | `...\data-plane\logs\*.err.log` / `*.wrapper.log`; `netstat -ano | findstr :8080` |
| Console blank / CSP or CORS errors in the browser console | `config.js` points to another origin without matching CSP/CORS | Re-run the IIS script with `-ApiBaseUrl`; set `-CorsOrigins` on the control-plane |
| IIS returns 500.19 | URL Rewrite (or ARR for the `/api` rule) missing | Install the module(s) |
| A new CA appeared after a restore | `certs\mitmproxy-ca-cert.pem` was missing, the control-plane generated a new CA | Restore the original `certs\` and restart; re-stage the CA on the workers |
| Installer: `Refusing to adopt N file(s) that existed before this installation` | first installation (no service) or directories with an unexpected owner/ACL contain files | Check the listed files. Delete them if you do not know where they come from; re-run with `-AdoptExistingSecrets` for a restore, a reinstallation after `-Uninstall` or an interrupted first run |
| Installer: `ACL verification failed` | an ACE or owner could not be changed (e.g. an inheritance-blocking policy, a tool that re-adds ACEs) | Fix the listed paths (`icacls <path>`), re-run; the service is not started until the check passes |
| Installer: `Python at ... can be modified by non-administrators` | interpreter outside `Program Files` (e.g. `C:\Python312`), or an account other than SYSTEM/Administrators/TrustedInstaller/the service owns or may write to one of the listed paths (also the directory above the Python directory) | Reinstall python.org Python for all users into `C:\Program Files\Python312`, or remove the listed ACEs (`icacls <path> /remove <account>`). An `owner <SID>` entry on a Windows client edition is usually the administrator account that created the files: after checking it, `icacls <path> /setowner *S-1-5-32-544 /T /L` |
| Installer: `... over an SMB connection that is not encrypted` | `-ImportSecretsDir`/`-CaSourceDir`/`-DataPlaneKeyFile`/`-CaFile` on a plain SMB share (any spelling: `//host/share`, `\\?\UNC\...`, mapped drive) | `New-SmbMapping -RemotePath \\host\share -RequirePrivacy $true`, or copy the files over a protected channel |
| Installer: `... is a device path` | a source path like `\\?\GLOBALROOT\...` or `\\?\Volume{...}\...` | Pass a drive-letter or UNC path |
| Installer: `Junctions/symbolic links and hard-linked files are not allowed`, `Junction/symbolic link in the installation directories`, `... has further hard links` | a link or a hard-linked file in a directory that existed before (ACL changes and deletions would reach the file elsewhere) | Remove the listed entries (`Remove-Item` on the link itself; `fsutil hardlink list <file>` shows the other names of a hard-linked file) and re-run |
| Installer: `N file(s) appeared in the installation directories while this script ran` | someone who could still write to a pre-existing directory added files between the inspection and the lock-down | Find out where they come from, delete them and re-run; the directories are locked now, so a re-run is not raced |

Run the control-plane in the foreground with its service environment (stop the service first):

```powershell
Stop-Service AegisControlPlane
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\AegisControlPlane).Environment |
    ForEach-Object { $k, $v = $_ -split '=', 2; Set-Item -Path "Env:$k" -Value $v }
Remove-Item Env:AEGIS_LOG_FILE
& 'C:\Program Files\AegisProxy\control-plane\aegis-control-plane.exe'
```

---

## 15. Security hardening checklist

- [ ] `AEGIS_PUBLIC_URL` uses `https://`; TLS certificate from the internal PKI; HSTS active.
- [ ] Bootstrap password changed; `initial-admin-password` / `bootstrap-admin-password` files deleted;
      personal accounts with least-privilege roles; `AEGIS_DEMO_MODE=false`.
- [ ] `C:\ProgramData\AegisProxy` ACL: owner Administrators, no inherited `Users` access; `secrets\` and
      `mitmproxy-ca.pem` admin/service only (verified by the installers; `icacls` output reviewed).
- [ ] Never used `-AdoptExistingSecrets` for files of unknown origin; Python installed in `Program Files` (no
      `-AllowWritablePython`); secrets copied between hosts only over encrypted SMB or another protected channel.
- [ ] No secret values in the registry environment (only `*_FILE` paths).
- [ ] Services run as virtual accounts (`NT SERVICE\AegisControlPlane`, `NT SERVICE\AegisDataPlane`), never as
      LocalSystem.
- [ ] Firewall: proxy port only from server subnets; console/API only from admin networks, workers and load
      balancers; ops/metrics ports only from monitoring; Public profile closed.
- [ ] `AEGIS_TRUSTED_PROXIES` lists exactly the reverse proxies/load balancers.
- [ ] `/metrics` protected by `AEGIS_METRICS_TOKEN` or network ACLs.
- [ ] Data-plane installed from a hash-pinned, internally mirrored package set; WinSW binary verified.
- [ ] `AEGIS_FAIL_MODE=closed`; Protection Policy reviewed (threat intel `block`, AV `block`,
      `block_private_destinations`, `block_raw_tcp`, `allowed_ports`).
- [ ] ClamAV signatures update automatically; `StreamMaxLength` aligned with `av_max_scan_bytes`.
- [ ] CA fingerprint verified out-of-band on clients; CA key backed up encrypted, offline copy in a safe.
- [ ] Audit log shipped to the SIEM; backups encrypted and restore tested.
- [ ] Proxy tokens distributed via secret management and rotated; no SNAT between servers and workers.
- [ ] Windows Update / Defender exclusions reviewed (do not exclude the AegisProxy directories from AV scans
      without a reason).

## 16. Continuous verification

The CI job `windows` (`.github/workflows/ci.yml`) runs on every push on Windows Server 2022 and 2025:

1. the installer unit tests (Pester, 273 tests against an in-memory Windows model with owners, ACL
   inheritance, links, hard links, SMB connections and a local user racing the installer; nothing on the runner
   changes);
2. the control-plane Go test suite and the data-plane unit tests on Windows CPython 3.12;
3. installs Python for all users into `C:\Program Files\Python312` and WinSW 2.12.0 (pinned SHA-256), then both
   services, checks the event log source and the `service` ImagePath, and runs the log rotation task once as
   `NT SERVICE\AegisControlPlane` (result 0, archive created);
4. rolls out the enterprise CA the documented way (downloads `install-windows.ps1`, compares its SHA-256 with
   `windows_script_sha256` of `/api/public/ca/info`, runs it with `-File`), registers the runner as a server, publishes a policy
   set and checks an allowed HTTPS request (200), a denied one (403), the worker heartbeat and the recorded flow;
5. grows the audit trail past the (CI) rotation size of 1 MB, checks the rotated and compressed generations and
   verifies the complete hash chain across them;
6. starts the service with an invalid setting and expects event ID 1 with the reason in the Application log;
7. uninstalls both services and checks that the event log source is gone.

Use the same steps as a smoke test after an upgrade. Between pushes, `scripts/wine/` runs the Windows builds on
Linux under Wine (Go suites incl. cluster tests, the `.exe` as process and SCM service, the data-plane on Windows
CPython with HTTPS through the proxy) - see [`scripts/wine/README.md`](../../scripts/wine/README.md).
