# Windows builds under Wine

These scripts run the **Windows** builds of AegisProxy on a Linux workstation or CI runner with Wine 9
(Ubuntu 24.04 container): the control-plane test suite compiled for `windows/amd64`, the real
`aegis-control-plane.exe` as a console process and as a service under Wine's Service Control Manager, and the
data-plane on python.org's Windows CPython with the `win_amd64` wheels. They catch Windows-specific defects
(file sharing semantics, paths, service handling, Windows wheels) before the `windows` CI job runs on real
Windows Server 2022/2025, which stays the authoritative test.

| Script | What it does |
|---|---|
| `run-go-tests.sh <work-dir> [--cluster]` | builds the Wine image, compiles every control-plane test package for Windows and runs it in its package directory; `--cluster` adds the PostgreSQL cluster tests against `postgres:17-alpine` |
| `prepare-windows-python.sh <work-dir>` | downloads the Python 3.12.10 embeddable distribution (SHA-256 pinned) and installs the `win_amd64` wheels of the hash lock `data-plane/requirements-lock.txt` (mitmproxy 12.3.0, YARA-X 1.22.0, security overrides) with `uv` into `<work-dir>/python` |
| `exe_e2e.py <dir with aegis-control-plane.exe>` | console process: bootstrap, policies, data-plane bundle, CA, built-in audit rotation at 1 MB with compression, complete chain verification and export, restart durability; service: `sc create` with the `service` argument, `net start`/`net stop`, graceful stop with state flush, exit codes, configuration error → `STOPPED` with exit code 1 |
| `dp_e2e.py <exe dir> <work-dir>/python <repo>/data-plane` | control-plane `.exe` + data-plane on Windows CPython with the arguments of `deploy/windows/aegis-dataplane.xml`; HTTPS through the proxy with TLS interception by the enterprise CA, default deny with block page, method restriction, access log on a Windows path, heartbeat with YARA-X, flows at the control-plane |

```bash
scripts/wine/run-go-tests.sh /tmp/aegis-wine --cluster
GOOS=windows GOARCH=amd64 go -C control-plane build -ldflags "-X main.Version=3.0.0-wine" -o /tmp/aegis-wine/app/aegis-control-plane.exe .
python3 -I scripts/wine/exe_e2e.py /tmp/aegis-wine/app
scripts/wine/prepare-windows-python.sh /tmp/aegis-wine
python3 -I scripts/wine/dp_e2e.py /tmp/aegis-wine/app /tmp/aegis-wine/python "$PWD/data-plane"
python3 -I -m unittest discover -s data-plane/tests   # also under Wine: wine <work-dir>/python/python.exe -m unittest discover -s Z:\…\data-plane\tests
```

`dp_e2e.py` needs outbound HTTPS to `example.com` and `www.wikipedia.org`.

## Wine differences the scripts work around

These are limitations of Wine, not of the product; real Windows behaves as documented by Microsoft.

| Wine behaviour | Effect | Handling |
|---|---|---|
| `SIO_UDP_CONNRESET` not implemented (`WSAEOPNOTSUPP`) | Go cannot create UDP sockets | the UDP part of `TestSyslogTCPAndUDP` is skipped only for this error |
| the per-service `Environment` registry value is ignored | a service gets no configuration | `exe_e2e.py` puts the variables into the machine environment and restarts `wineserver` |
| `services.exe` does not run in session 0 | `svc.IsWindowsService()` returns false | the installer's ImagePath uses the explicit `service` argument, which is what the test registers |
| standard handles redirected to a regular file are invalid for Windows CPython | `init_sys_streams` fails | output is piped (`| cat > file`); WinSW writes the log files on Windows |
| the Application event log is a stub | event log entries cannot be inspected | covered on real Windows only |
