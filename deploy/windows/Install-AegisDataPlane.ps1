#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs, upgrades or removes an AegisProxy data-plane worker (mitmproxy 12.3.0 + AegisProxy addon)
    as a Windows service wrapped by WinSW.

.DESCRIPTION
    mitmdump is not aware of the Service Control Manager, so it runs under WinSW (https://github.com/winsw/winsw,
    MIT). The PyInstaller-bundled mitmproxy Windows binaries are NOT used: they do not necessarily ship all
    standard-library modules the addon imports (http.server, hmac, gzip, ...). Instead the script creates a
    virtual environment from a python.org CPython >= 3.12 installed "for all users" and installs
    mitmproxy==12.3.0 into it.

    Steps (idempotent; a re-run upgrades addon/venv/WinSW configuration and keeps the staged secrets):
      * resolves Python (py -3.12 / -3.13 / -3.14 or -PythonExe), creates <InstallDir>\venv, pip install
      * copies data-plane\aegis_addon.py + aegis_dp\ to <InstallDir>\app (byte-compiled)
      * stages the data-plane key and the CA (mitmproxy-ca.pem = key + cert) into <DataRoot> with ACLs that
        only SYSTEM, Administrators and the service account can read
      * renders aegis-dataplane.xml (template next to this script) for WinSW, installs the service
        "AegisDataPlane", switches it to the virtual account NT SERVICE\AegisDataPlane (or LocalService)
      * opens the proxy port in Windows Firewall for the allowed server subnets only
      * starts the service and waits for http://<OpsAddr>/readyz (= first policy bundle loaded)

    Layout:
      <InstallDir>\venv\                 Python virtual environment (mitmproxy 12.3.0)
      <InstallDir>\app\                  aegis_addon.py + aegis_dp\
      <InstallDir>\aegis-dataplane.exe   copy of WinSW-x64.exe (+ aegis-dataplane.xml)
      <DataRoot>\confdir\                private mitmproxy confdir (staged CA, dhparam) - service: modify
      <DataRoot>\secrets\dataplane.key   shared secret with the control-plane         - service: read
      <DataRoot>\logs\                   WinSW + mitmdump logs (rolled by size)        - service: modify

.PARAMETER PythonExe
    Explicit python.exe (python.org CPython >= 3.12, installed for all users). Default: detected with the
    Python launcher (py -3.12, then -3.13, -3.14).

.PARAMETER SourceDir
    The repository's data-plane folder (contains aegis_addon.py and aegis_dp\). Default: ..\..\data-plane.

.PARAMETER ControlPlaneUrl
    CONTROL_PLANE_URL - base URL of the control-plane (load balancer in cluster mode). https recommended.

.PARAMETER DataPlaneKeyFile
    File containing the data-plane key (control-plane: <DataRoot>\secrets\dataplane.key). Copied, never referenced.

.PARAMETER CaFile
    mitmproxy-ca.pem (CA private key + certificate) from the control-plane certs directory. Default when the
    control-plane runs on the same host: %ProgramData%\AegisProxy\certs\mitmproxy-ca.pem. On a re-run without
    -CaFile the already staged CA is kept.

.PARAMETER ClamdAddress
    AEGIS_CLAMD_ADDRESS, e.g. tcp://127.0.0.1:3310 (ClamAV for Windows). Empty string disables antivirus.
    unix:// sockets are not supported on Windows.

.PARAMETER WinSWExe
    Path to a verified WinSW-x64.exe (2.x). It is NOT downloaded automatically.

.PARAMETER WinSWSha256
    Expected SHA-256 of -WinSWExe. Default: WinSW-x64.exe of WinSW 2.12.0. The installation stops on a mismatch;
    pass the hash of your verified copy when you deploy another 2.x release.

.PARAMETER AllowedRemoteAddress
    Remote addresses allowed to use the proxy port (Windows Firewall), e.g. 10.20.0.0/16,10.30.0.0/16.

.PARAMETER ServiceAccount
    Virtual (default): NT SERVICE\AegisDataPlane - dedicated per-service SID, ACLs apply to this service only.
    LocalService: NT AUTHORITY\LocalService - shared with other services, use only if virtual accounts are
    prohibited by policy.

.PARAMETER RequirementsFile
    Complete, hash-pinned lock file (uv pip compile --generate-hashes; its --override is needed), installed with
    --require-hashes --no-deps instead of mitmproxy==12.3.0 and yara-x==1.22.0 (include yara-x to keep YARA
    scanning). It must pin every dependency and at least the versions of data-plane\requirements-security.txt,
    e.g. uv pip compile --generate-hashes --override requirements-security.txt requirements.in. The overrides are
    not installed on top of it (that would bypass hash checking); the script verifies the baseline versions and
    runs pip check, which may only report the conflicts caused by those overrides.

.PARAMETER Uninstall
    Removes the service, firewall rules, program files and the staged CA/key copies; keeps the logs.

.EXAMPLE
    .\Install-AegisDataPlane.ps1 -ControlPlaneUrl https://aegis.corp.example `
        -DataPlaneKeyFile C:\ProgramData\AegisProxy\secrets\dataplane.key `
        -CaFile C:\ProgramData\AegisProxy\certs\mitmproxy-ca.pem `
        -WinSWExe C:\Install\WinSW-x64.exe -AllowedRemoteAddress 10.20.0.0/16,10.30.0.0/16

.EXAMPLE
    # Offline / hash-pinned installation from an internal wheel share
    .\Install-AegisDataPlane.ps1 ... -RequirementsFile \\fs\aegis\requirements-win.txt `
        -PipArgs '--no-index','--find-links','\\fs\aegis\wheels'

.NOTES
    Reference for all variables: docs/configuration.md. Operations guide: docs/deployment/windows.md.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string]$PythonExe,

    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AegisProxy\data-plane'),

    [string]$DataRoot = (Join-Path $env:ProgramData 'AegisProxy\data-plane'),

    [Parameter(ParameterSetName = 'Install')]
    [string]$SourceDir = (Join-Path $PSScriptRoot '..\..\data-plane'),

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [ValidatePattern('^https?://[^\s/?#]+')]
    [string]$ControlPlaneUrl,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string]$DataPlaneKeyFile,

    [Parameter(ParameterSetName = 'Install')]
    [string]$CaFile,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int]$ListenPort = 8080,

    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9A-Za-z.:-]+$')]
    [string]$ListenHost = '0.0.0.0',

    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9A-Za-z.-]+:\d{1,5}$')]
    [string]$OpsAddr = '127.0.0.1:9091',

    [Parameter(ParameterSetName = 'Install')]
    [AllowEmptyString()]
    [string]$ClamdAddress = 'tcp://127.0.0.1:3310',

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string]$WinSWExe,

    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$WinSWSha256 = '05B82D46AD331CC16BDC00DE5C6332C1EF818DF8CEEFCD49C726553209B3A0DA',

    [Parameter(ParameterSetName = 'Install')]
    [string[]]$AllowedRemoteAddress = @('LocalSubnet'),

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('Domain', 'Private', 'Public', 'Any')]
    [string[]]$FirewallProfile = @('Domain'),

    # Prometheus scrapers allowed to reach the ops port when -OpsAddr is not loopback.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$MonitoringRemoteAddress,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('Virtual', 'LocalService')]
    [string]$ServiceAccount = 'Virtual',

    # AEGIS_CONTROL_PLANE_CA_FILE: CA bundle (PEM) of an internal PKI that issued the control-plane certificate.
    [Parameter(ParameterSetName = 'Install')]
    [string]$ControlPlaneCaFile,

    [Parameter(ParameterSetName = 'Install')]
    [string]$PublicUrl,

    [Parameter(ParameterSetName = 'Install')]
    [string]$DashboardUrl,

    [Parameter(ParameterSetName = 'Install')]
    [string]$WorkerId,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('closed', 'open')]
    [string]$FailMode = 'closed',

    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^\d+[kmgKMG]?$')]
    [string]$BodySizeLimit = '1g',

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('error', 'warn', 'info', 'alert', 'debug')]
    [string]$MitmLogLevel = 'info',

    # Additional pip arguments, e.g. '--no-index','--find-links','\\fs\wheels' or '--index-url','https://nexus/...'.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$PipArgs,

    # Complete hash-pinned lock file (installed with --require-hashes --no-deps instead of mitmproxy==12.3.0
    # and yara-x==1.22.0); include yara-x in it to keep YARA scanning.
    [Parameter(ParameterSetName = 'Install')]
    [string]$RequirementsFile,

    # Do not install the YARA-X engine (YARA rule sets then report "unavailable" on this worker).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$NoYara,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$RecreateVenv,

    # Additional non-secret variables for the worker, e.g. @{ AEGIS_LOG_LEVEL = 'DEBUG' }.
    [Parameter(ParameterSetName = 'Install')]
    [hashtable]$ExtraEnvironment,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipFirewall,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(10, 900)]
    [int]$ReadyTimeoutSeconds = 120,

    [Parameter(Mandatory = $true, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- constants ---------------------------------------------------------------------------------------
$ServiceName      = 'AegisDataPlane'
$MitmproxyVersion = '12.3.0'
$YaraXVersion     = '1.22.0'
$WinSWUrl         = 'https://github.com/winsw/winsw/releases (2.x, asset WinSW-x64.exe)'
$FirewallProxy    = 'AegisProxy-DataPlane-Proxy-In'
$FirewallOps      = 'AegisProxy-DataPlane-Ops-In'
$SidSystem        = '*S-1-5-18'
$SidAdmins        = '*S-1-5-32-544'
$SidLocalService  = '*S-1-5-19'
$SidUsers         = '*S-1-5-32-545'

$InstallDir  = [System.IO.Path]::GetFullPath($InstallDir)
$DataRoot    = [System.IO.Path]::GetFullPath($DataRoot)
$VenvDir     = Join-Path $InstallDir 'venv'
$VenvPython  = Join-Path $VenvDir 'Scripts\python.exe'
$Mitmdump    = Join-Path $VenvDir 'Scripts\mitmdump.exe'
$AppDir      = Join-Path $InstallDir 'app'
$WrapperExe  = Join-Path $InstallDir 'aegis-dataplane.exe'
$WrapperXml  = Join-Path $InstallDir 'aegis-dataplane.xml'
$ConfDir     = Join-Path $DataRoot 'confdir'
$SecretsDir  = Join-Path $DataRoot 'secrets'
$LogsDir     = Join-Path $DataRoot 'logs'
$RuntimeDir  = Join-Path $DataRoot 'runtime'
$StagedCa    = Join-Path $ConfDir 'mitmproxy-ca.pem'
$StagedKey   = Join-Path $SecretsDir 'dataplane.key'
$StagedCpCa  = Join-Path $SecretsDir 'control-plane-ca.pem'
$ServiceKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$Template    = Join-Path $PSScriptRoot 'aegis-dataplane.xml'

if ($ServiceAccount -eq 'LocalService') {
    $LogonAccount = 'NT AUTHORITY\LocalService'; $AclPrincipal = $SidLocalService
}
else {
    $LogonAccount = "NT SERVICE\$ServiceName"; $AclPrincipal = "NT SERVICE\$ServiceName"
}

# --- helpers -----------------------------------------------------------------------------------------
function Write-Step([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Note([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

function Invoke-Native {
    # Captures output, throws on unexpected exit codes (EAP 'Continue' avoids PS 5.1 stderr pitfalls).
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @(), [int[]]$SuccessCodes = @(0), [switch]$NoThrow)
    $ErrorActionPreference = 'Continue'
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    if (-not $NoThrow -and $SuccessCodes -notcontains $code) {
        throw ("'{0} {1}' failed with exit code {2}:`n{3}" -f $FilePath, ($ArgumentList -join ' '), $code, ($output -join "`n"))
    }
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function Invoke-NativeLive {
    # Streams output to the console (pip progress), throws on a non-zero exit code.
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    & $FilePath @ArgumentList | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $LASTEXITCODE." }
}

function Read-SecretFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return ([System.IO.File]::ReadAllText($Path)).Trim([char[]]@([char]0xFEFF, ' ', "`t", "`r", "`n"))
}

function Write-TextNoBom([string]$Path, [string]$Value) {
    [System.IO.File]::WriteAllText($Path, $Value, (New-Object System.Text.UTF8Encoding($false)))
}

function ConvertTo-XmlText([string]$Value) {
    if ($Value -match '[\x00-\x1f]') { throw "Value '$Value' contains control characters." }
    return [System.Security.SecurityElement]::Escape($Value)
}

function Get-PemCertificateInfo([string]$Path) {
    $text = [System.IO.File]::ReadAllText($Path)
    $m = [regex]::Match($text, '-----BEGIN CERTIFICATE-----(?<b64>[A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    if (-not $m.Success) { return $null }
    $raw = [Convert]::FromBase64String(($m.Groups['b64'].Value -replace '\s', ''))
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $raw)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($cert.RawData) } finally { $sha.Dispose() }
    return [pscustomobject]@{ Subject = $cert.Subject; NotAfter = $cert.NotAfter; Fingerprint = ([System.BitConverter]::ToString($hash)).Replace('-', ':') }
}

function Get-HttpStatus([string]$Url) {
    # Direct connection (no system proxy), 3 s timeout. Returns the HTTP status or 0 if unreachable.
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Proxy = $null
        $req.Timeout = 3000
        $resp = $req.GetResponse()
        try { return [int]$resp.StatusCode } finally { $resp.Close() }
    }
    catch {
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) { return [int]$ex.Response.StatusCode }
        return 0
    }
}

function Wait-ServiceState([string]$Name, [string]$State, [int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($State -eq 'Deleted' -and -not $svc) { return $true }
        if ($svc -and "$($svc.Status)" -eq $State) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Stop-DataPlaneService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Step "Stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force
        if (-not (Wait-ServiceState -Name $ServiceName -State 'Stopped' -TimeoutSeconds 60)) {
            throw "Service $ServiceName did not stop within 60 seconds."
        }
    }
}

function Remove-DataPlaneService {
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { return }
    Stop-DataPlaneService
    if (Test-Path -LiteralPath $WrapperExe) {
        $null = Invoke-Native -FilePath $WrapperExe -ArgumentList @('uninstall') -NoThrow
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        $null = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('delete', $ServiceName) -NoThrow
    }
    if (-not (Wait-ServiceState -Name $ServiceName -State 'Deleted' -TimeoutSeconds 30)) {
        throw "Service $ServiceName is marked for deletion but still present. Close services.msc / Event Viewer and re-run."
    }
}

function Show-Diagnostic {
    Get-ChildItem -LiteralPath $LogsDir -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 2 | ForEach-Object {
            Write-Note "Last lines of $($_.FullName):"
            Get-Content -LiteralPath $_.FullName -Tail 20 | ForEach-Object { Write-Host "    $_" }
        }
    Write-Note 'Typical causes: control-plane unreachable (CONTROL_PLANE_URL, firewall, TLS trust -> -ControlPlaneCaFile),'
    Write-Note 'wrong data-plane key (control-plane log: "rejected data-plane request with invalid key", HTTP 401),'
    Write-Note 'CA file without private key, or Python packages missing in the venv.'
}

# =====================================================================================================
# Uninstall
# =====================================================================================================
if ($Uninstall) {   # parameter set 'Uninstall'
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop and remove service')) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Remove-DataPlaneService; Write-Ok "Service $ServiceName removed." }
        else { Write-Note "Service $ServiceName is not installed." }
    }
    if ($PSCmdlet.ShouldProcess('AegisProxy data-plane firewall rules', 'Remove')) {
        foreach ($rule in @($FirewallProxy, $FirewallOps)) {
            Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
    }
    if ($PSCmdlet.ShouldProcess("$ConfDir, $SecretsDir", 'Delete staged CA private key and data-plane key copies')) {
        foreach ($dir in @($ConfDir, $SecretsDir, $RuntimeDir)) {
            if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
        }
    }
    if ((Test-Path -LiteralPath $InstallDir) -and $PSCmdlet.ShouldProcess($InstallDir, 'Remove program files (venv, addon, WinSW)')) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
    }
    Write-Ok 'AegisProxy data-plane uninstalled.'
    Write-Note "Logs were kept in $LogsDir. The staged CA key / data-plane key copies were deleted; the originals remain on the control-plane."
    Write-Note 'Remember to remove the proxy settings from client servers or point them to another worker.'
    return
}

# =====================================================================================================
# Install / upgrade - validation
# =====================================================================================================
$ControlPlaneUrl = $ControlPlaneUrl.TrimEnd('/')
if ($ControlPlaneUrl -notmatch '^https://') {
    Write-Note 'CONTROL_PLANE_URL is http:// - the data-plane key and policy bundle travel unencrypted. Use https:// across hosts.'
}

# WinSW (never downloaded automatically)
if (-not (Test-Path -LiteralPath $WinSWExe -PathType Leaf)) {
    Write-Note "WinSW is not downloaded automatically. Download WinSW-x64.exe from $WinSWUrl,"
    Write-Note 'verify it (hash / internal software repository) and pass it with -WinSWExe C:\path\WinSW-x64.exe.'
    Write-Note 'The script copies it to <InstallDir>\aegis-dataplane.exe and renders aegis-dataplane.xml next to it;'
    Write-Note 'WinSW 2.x finds its configuration by the executable name ("aegis-dataplane.exe install|start|stop|status").'
    throw "WinSW executable not found: $WinSWExe"
}
$WinSWExe = (Resolve-Path -LiteralPath $WinSWExe).ProviderPath
$winswInfo = (Get-Item -LiteralPath $WinSWExe).VersionInfo
$winswHash = (Get-FileHash -LiteralPath $WinSWExe -Algorithm SHA256).Hash
if ("$($winswInfo.ProductName) $($winswInfo.FileDescription) $($winswInfo.OriginalFilename) $($winswInfo.InternalName)" -notmatch 'WinSW|Windows Service Wrapper') {
    Write-Note "$WinSWExe does not identify itself as WinSW - make sure this is the correct file."
}
if ($winswHash -ne $WinSWSha256) {
    throw "SHA-256 of $WinSWExe is $winswHash, expected $($WinSWSha256.ToUpperInvariant()) (WinSW 2.12.0 x64 unless -WinSWSha256 is given). Use a verified WinSW copy or pass the hash of your verified release with -WinSWSha256."
}
Write-Step "WinSW: $WinSWExe (version $($winswInfo.FileVersion), SHA-256 $winswHash verified)."

if (-not (Test-Path -LiteralPath $Template -PathType Leaf)) { throw "WinSW template not found: $Template" }

# Addon sources
$SourceDir = [System.IO.Path]::GetFullPath($SourceDir)
foreach ($required in @('aegis_addon.py', 'aegis_dp\addon.py', 'aegis_dp\__init__.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $SourceDir $required))) { throw "$SourceDir is not the data-plane folder ($required missing). Use -SourceDir." }
}

# Data-plane key
$keyValue = Read-SecretFile $DataPlaneKeyFile
if (-not $keyValue) { throw "Data-plane key file '$DataPlaneKeyFile' not found or empty." }
if ($keyValue.Length -lt 32 -or $keyValue -match '\s') { throw "The data-plane key in '$DataPlaneKeyFile' must be a single token of at least 32 characters." }

# CA (key + certificate)
if (-not $CaFile -and -not (Test-Path -LiteralPath $StagedCa)) {
    $sameHostCa = Join-Path $env:ProgramData 'AegisProxy\certs\mitmproxy-ca.pem'
    if (Test-Path -LiteralPath $sameHostCa) { $CaFile = $sameHostCa; Write-Step "Using the control-plane CA on this host: $CaFile" }
    else { throw '-CaFile is required: path to mitmproxy-ca.pem (CA private key + certificate) from the control-plane certs directory.' }
}
if ($CaFile) {
    $CaFile = (Resolve-Path -LiteralPath $CaFile).ProviderPath
    $caText = [System.IO.File]::ReadAllText($CaFile)
    if ($caText -notmatch '-----BEGIN (RSA |EC )?PRIVATE KEY-----' -or $caText -notmatch '-----BEGIN CERTIFICATE-----') {
        throw "$CaFile must contain the CA private key AND certificate (mitmproxy-ca.pem, not mitmproxy-ca-cert.pem)."
    }
}
if ($ControlPlaneCaFile -and -not (Test-Path -LiteralPath $ControlPlaneCaFile -PathType Leaf)) { throw "-ControlPlaneCaFile '$ControlPlaneCaFile' not found." }

# ClamAV
if ($ClamdAddress -like 'unix://*') { throw 'unix:// clamd sockets are not supported on Windows. Use tcp://127.0.0.1:3310 (clamd.conf: TCPSocket 3310, TCPAddr 127.0.0.1).' }
if ($ClamdAddress -and $ClamdAddress -notmatch '^(tcp://)?[0-9A-Za-z.-]+:\d{1,5}$') { throw "Invalid -ClamdAddress '$ClamdAddress' (expected tcp://host:port)." }
if (-not $ClamdAddress) { Write-Note 'No -ClamdAddress: antivirus scanning is disabled on this worker (policy switch has no effect).' }

# Set by the template or by dedicated parameters - a second <env> element with the same name would be ambiguous.
$reservedEnv = @('AEGIS_DATAPLANE_KEY', 'AEGIS_DATAPLANE_KEY_FILE', 'CONTROL_PLANE_URL', 'AEGIS_OPS_ADDR', 'AEGIS_FAIL_MODE',
    'AEGIS_PROXY_MODE', 'AEGIS_CLAMD_ADDRESS', 'AEGIS_CONTROL_PLANE_CA_FILE', 'AEGIS_PUBLIC_URL', 'DASHBOARD_URL', 'AEGIS_WORKER_ID',
    'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'PYTHONUTF8')
if ($ExtraEnvironment) {
    foreach ($key in $ExtraEnvironment.Keys) {
        if ($key -notmatch '^[A-Z_][A-Z0-9_]*$') { throw "Invalid environment variable name '$key'." }
        if ($reservedEnv -contains $key) { throw "$key is managed by this script (template or dedicated parameter)." }
    }
}

# Python (python.org CPython >= 3.12, all-users installation)
$pythonBase = $null
if ($PythonExe) {
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "-PythonExe '$PythonExe' not found." }
    $pythonBase = (Resolve-Path -LiteralPath $PythonExe).ProviderPath
}
else {
    $launcher = Get-Command -Name 'py.exe' -ErrorAction SilentlyContinue
    if (-not $launcher) { throw 'Python launcher (py.exe) not found. Install python.org Python 3.12+ for all users or pass -PythonExe.' }
    foreach ($selector in @('-3.12', '-3.13', '-3.14')) {
        $probe = Invoke-Native -FilePath $launcher.Source -ArgumentList @($selector, '-c', 'import sys; print(sys.executable)') -NoThrow
        if ($probe.ExitCode -eq 0 -and $probe.Output.Count -gt 0) { $pythonBase = ($probe.Output[-1]).Trim(); break }
    }
    if (-not $pythonBase) { throw 'No Python 3.12+ found via "py -3.12/-3.13/-3.14". Install python.org Python 3.12 (for all users).' }
}
$pyVersion = ((Invoke-Native -FilePath $pythonBase -ArgumentList @('-c', 'import sys; print(sys.version_info[0], sys.version_info[1], sys.version_info[2], sep=chr(46))')).Output -join '').Trim()
if ([version]$pyVersion -lt [version]'3.12.0') { throw "Python $pyVersion at $pythonBase is too old; mitmproxy $MitmproxyVersion requires Python >= 3.12." }
if ($pythonBase -like '*\WindowsApps\*') { throw 'The Microsoft Store Python cannot be used by services. Install python.org Python for all users.' }
if ($pythonBase -like (Join-Path $env:SystemDrive 'Users\*')) {
    throw "Python at $pythonBase is a per-user installation; the service account cannot read it. Reinstall python.org Python with 'Install for all users' (InstallAllUsers=1)."
}
Write-Step "Python $pyVersion at $pythonBase"

# =====================================================================================================
# Install / upgrade - changes
# =====================================================================================================
if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop service for upgrade')) { Stop-DataPlaneService }

if ($PSCmdlet.ShouldProcess($DataRoot, 'Create directories and restrict ACL to SYSTEM/Administrators')) {
    foreach ($dir in @($InstallDir, $AppDir, $DataRoot, $ConfDir, $SecretsDir, $LogsDir, $RuntimeDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
    # Program files (venv, addon, WinSW): users read/execute only, also for a custom -InstallDir outside
    # %ProgramFiles% that would inherit "create files/folders" for users (DLL / module planting).
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($InstallDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${SidUsers}:(OI)(CI)RX", '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($DataRoot, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", '/Q')
    Write-Ok "Directories ready under $DataRoot"
}

# --- Python virtual environment ----------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($VenvDir, "Create venv and install mitmproxy==$MitmproxyVersion")) {
    $recreate = [bool]$RecreateVenv
    $venvCfg = Join-Path $VenvDir 'pyvenv.cfg'
    if (Test-Path -LiteralPath $venvCfg) {
        $venvHome = (Get-Content -LiteralPath $venvCfg | Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1) -replace '^\s*home\s*=\s*', ''
        if ("$venvHome".TrimEnd('\') -ne (Split-Path -Parent $pythonBase).TrimEnd('\')) {
            Write-Note "Existing venv was created with '$venvHome' - recreating it for $pythonBase."
            $recreate = $true
        }
    }
    if ($recreate -and (Test-Path -LiteralPath $VenvDir)) { Remove-Item -LiteralPath $VenvDir -Recurse -Force }
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Write-Step "Creating virtual environment $VenvDir"
        Invoke-NativeLive -FilePath $pythonBase -ArgumentList @('-m', 'venv', $VenvDir)
    }
    Write-Note 'Supply chain: for production prefer an offline, hash-pinned installation from a vetted wheel mirror'
    Write-Note '(-RequirementsFile <uv pip compile --generate-hashes --override requirements-security.txt output> -PipArgs --no-index,--find-links,<share>).'
    $pipArgList = @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--require-virtualenv')
    if ($RequirementsFile) {
        # A complete lock file pins every dependency; --no-deps lets it raise packages above mitmproxy's upper
        # bounds (security baseline). Completeness is checked with "pip check" below.
        $pipArgList += @('--require-hashes', '--no-deps', '-r', (Resolve-Path -LiteralPath $RequirementsFile).ProviderPath)
    }
    else {
        $pipArgList += "mitmproxy==$MitmproxyVersion"
        # YARA-X ships binary wheels for Windows x64; never fall back to a source build.
        if (-not $NoYara) { $pipArgList += @("yara-x==$YaraXVersion", '--only-binary', 'yara-x') }
    }
    if ($PipArgs) { $pipArgList += $PipArgs }
    Write-Step "pip $($pipArgList[2..($pipArgList.Count - 1)] -join ' ')"
    Invoke-NativeLive -FilePath $VenvPython -ArgumentList $pipArgList
    # Security overrides for mitmproxy dependencies (mitmproxy's upper bound excludes the fixed release).
    $securityReq = Join-Path $SourceDir 'requirements-security.txt'
    if ((Test-Path -LiteralPath $securityReq) -and -not $RequirementsFile) {
        $secArgs = @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--require-virtualenv', '--no-deps', '--only-binary=:all:', '-r', $securityReq)
        if ($PipArgs) { $secArgs += $PipArgs }
        Invoke-NativeLive -FilePath $VenvPython -ArgumentList $secArgs
    }
    elseif (Test-Path -LiteralPath $securityReq) {
        # Hash-pinned mode: an unhashed install on top would bypass --require-hashes, so only verify the pins.
        foreach ($line in (Get-Content -LiteralPath $securityReq)) {
            if ($line -notmatch '^\s*(?<name>[A-Za-z0-9._-]+)==(?<version>[0-9]+(\.[0-9]+)+)') { continue }
            $pkg = $Matches['name']; $minimum = [version]$Matches['version']; $have = $null
            $probe = Invoke-Native -FilePath $VenvPython -ArgumentList @('-c', 'import importlib.metadata as m, sys; print(m.version(sys.argv[1]))', $pkg) -SuccessCodes @(0, 1)
            if ($probe.ExitCode -eq 0 -and [version]::TryParse((($probe.Output -join '').Trim()), [ref]$have) -and $have -lt $minimum) {
                throw "$RequirementsFile installs $pkg $have; the security baseline requires >= $minimum (data-plane\requirements-security.txt). Pin it with its hash in the requirements file."
            }
        }
        # Every dependency must be in the lock file; the only tolerated conflicts are the baseline overrides.
        $overrides = @(foreach ($line in (Get-Content -LiteralPath $securityReq)) {
                if ($line -match '^\s*(?<name>[A-Za-z0-9._-]+)==') { $Matches['name'].ToLowerInvariant().Replace('_', '-') }
            })
        $pipCheck = Invoke-Native -FilePath $VenvPython -ArgumentList @('-m', 'pip', 'check') -SuccessCodes @(0, 1)
        $broken = @($pipCheck.Output | Where-Object {
                $_.Trim() -and $_ -notmatch '^No broken' -and
                -not ($_ -match 'but you have (?<pkg>\S+) ' -and $overrides -contains $Matches['pkg'].ToLowerInvariant().Replace('_', '-'))
            })
        if ($broken.Count) {
            throw ("The hash-pinned requirements file is incomplete or inconsistent ({0}), pip check reports:`n  {1}" -f $RequirementsFile, ($broken -join "`n  "))
        }
    }
    if (-not (Test-Path -LiteralPath $Mitmdump)) { throw "mitmdump.exe not found in the venv ($Mitmdump)." }
    # The addon needs these standard-library modules - fail now instead of at service start.
    $check = Invoke-Native -FilePath $VenvPython -ArgumentList @('-c', 'import http.server, hmac, gzip, ssl, asyncio, mitmproxy.version as v; print(v.VERSION)')
    $installed = ($check.Output -join '').Trim()
    if ($installed -ne $MitmproxyVersion) { Write-Note "Installed mitmproxy $installed (expected $MitmproxyVersion)." }
    Write-Ok "mitmproxy $installed installed in $VenvDir"
    $yaraCheck = Invoke-Native -FilePath $VenvPython -ArgumentList @('-c', 'import yara_x') -SuccessCodes @(0, 1)
    if ($yaraCheck.ExitCode -eq 0) { Write-Ok 'YARA-X available for YARA rule sets' }
    else { Write-Note 'YARA-X is not installed: YARA rule sets report "unavailable" on this worker.' }
}

# --- addon -------------------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($AppDir, 'Install AegisProxy addon')) {
    $null = Invoke-Native -FilePath 'robocopy.exe' -ArgumentList @((Join-Path $SourceDir 'aegis_dp'), (Join-Path $AppDir 'aegis_dp'),
        '/MIR', '/XD', '__pycache__', 'tests', '/XF', '*.pyc', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:2', '/W:2') -SuccessCodes @(0, 1, 2, 3, 4, 5, 6, 7)
    Copy-Item -LiteralPath (Join-Path $SourceDir 'aegis_addon.py') -Destination (Join-Path $AppDir 'aegis_addon.py') -Force
    $null = Invoke-Native -FilePath $VenvPython -ArgumentList @('-m', 'compileall', '-q', $AppDir)
    # Import test (does not instantiate the addon, so no configuration is needed).
    $null = Invoke-Native -FilePath $VenvPython -ArgumentList @('-c', 'import sys; sys.path.insert(0, sys.argv[1]); import aegis_dp.addon', $AppDir)
    Write-Ok "Addon installed in $AppDir (import check passed)"
}

# --- secrets / CA ------------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($DataRoot, 'Stage data-plane key and CA')) {
    Write-TextNoBom -Path $StagedKey -Value ($keyValue + "`n")
    if ($CaFile) {
        # Remove artefacts of a previous CA, then stage the new key + certificate.
        # Written from the validated content: -CaFile may be the staged file itself (re-run).
        Get-ChildItem -LiteralPath $ConfDir -Filter 'mitmproxy-ca*' -ErrorAction SilentlyContinue | Remove-Item -Force
        Write-TextNoBom -Path $StagedCa -Value $caText
    }
    if ($ControlPlaneCaFile) { Copy-Item -LiteralPath $ControlPlaneCaFile -Destination $StagedCpCa -Force }
    Write-Ok 'Data-plane key and CA staged.'
}

# --- WinSW service definition ------------------------------------------------------------------------
$extraEnv = [ordered]@{}
if ($ClamdAddress) { $extraEnv['AEGIS_CLAMD_ADDRESS'] = $ClamdAddress }
if ($ControlPlaneCaFile -or (Test-Path -LiteralPath $StagedCpCa)) { $extraEnv['AEGIS_CONTROL_PLANE_CA_FILE'] = $StagedCpCa }
if ($PublicUrl)    { $extraEnv['AEGIS_PUBLIC_URL'] = $PublicUrl.TrimEnd('/') }
if ($DashboardUrl) { $extraEnv['DASHBOARD_URL'] = $DashboardUrl.TrimEnd('/') }
if ($WorkerId)     { $extraEnv['AEGIS_WORKER_ID'] = $WorkerId }
if ($ExtraEnvironment) { foreach ($key in $ExtraEnvironment.Keys) { $extraEnv[$key] = [string]$ExtraEnvironment[$key] } }
$extraEnvXml = (@(foreach ($key in $extraEnv.Keys) {
    '<env name="{0}" value="{1}"/>' -f (ConvertTo-XmlText $key), (ConvertTo-XmlText $extraEnv[$key])
}) -join "`r`n  ")

$placeholders = [ordered]@{
    '@@MITMDUMP_EXE@@'       = ConvertTo-XmlText $Mitmdump
    '@@ADDON_SCRIPT@@'       = ConvertTo-XmlText (Join-Path $AppDir 'aegis_addon.py')
    '@@CONFDIR@@'            = ConvertTo-XmlText $ConfDir
    '@@LISTEN_HOST@@'        = ConvertTo-XmlText $ListenHost
    '@@LISTEN_PORT@@'        = ConvertTo-XmlText "$ListenPort"
    '@@BODY_SIZE_LIMIT@@'    = ConvertTo-XmlText $BodySizeLimit.ToLowerInvariant()
    '@@MITM_LOG_LEVEL@@'     = ConvertTo-XmlText $MitmLogLevel
    '@@WORKDIR@@'            = ConvertTo-XmlText $AppDir
    '@@LOG_DIR@@'            = ConvertTo-XmlText $LogsDir
    '@@CONTROL_PLANE_URL@@'  = ConvertTo-XmlText $ControlPlaneUrl
    '@@DATAPLANE_KEY_FILE@@' = ConvertTo-XmlText $StagedKey
    '@@OPS_ADDR@@'           = ConvertTo-XmlText $OpsAddr
    '@@FAIL_MODE@@'          = ConvertTo-XmlText $FailMode
    '@@EXTRA_ENV@@'          = $extraEnvXml
}
$rendered = [System.IO.File]::ReadAllText($Template)
# Replace the template's documentation header with a short generated-file notice.
$header = '<!-- Generated by Install-AegisDataPlane.ps1 on {0:yyyy-MM-dd HH:mm} from deploy\windows\aegis-dataplane.xml. Do not edit: re-run the script. -->' -f (Get-Date)
$rendered = (New-Object System.Text.RegularExpressions.Regex('(?s)<!--.*?-->')).Replace($rendered, $header, 1)
foreach ($key in $placeholders.Keys) { $rendered = $rendered.Replace($key, $placeholders[$key]) }
if ($rendered -match '@@[A-Z_]+@@') { throw "Unreplaced placeholder in the WinSW configuration: $($Matches[0])" }
try { [void][xml]$rendered } catch { throw "Rendered WinSW configuration is not well-formed XML: $($_.Exception.Message)" }

if ($PSCmdlet.ShouldProcess($WrapperXml, 'Write WinSW configuration and (re)install the service')) {
    Remove-DataPlaneService      # WinSW applies service-level settings at install time -> reinstall on every run
    Copy-Item -LiteralPath $WinSWExe -Destination $WrapperExe -Force
    Write-TextNoBom -Path $WrapperXml -Value $rendered
    $null = Invoke-Native -FilePath $WrapperExe -ArgumentList @('install')
    if (-not (Wait-ServiceState -Name $ServiceName -State 'Stopped' -TimeoutSeconds 30)) { throw "WinSW did not register the service $ServiceName." }
    # Switch the logon account before the first start (WinSW installs as LocalSystem).
    $null = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('config', $ServiceName, 'obj=', $LogonAccount)
    $null = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('sidtype', $ServiceName, 'unrestricted')
    $null = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('failure', $ServiceName, 'reset=', '3600', 'actions=', 'restart/5000/restart/5000/restart/30000')
    $null = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('failureflag', $ServiceName, '1')
    # WinSW-x64 is a self-contained .NET single-file app: give it a private, writable extraction directory.
    New-ItemProperty -Path $ServiceKey -Name 'Environment' -PropertyType MultiString -Force `
        -Value ([string[]]@("DOTNET_BUNDLE_EXTRACT_BASE_DIR=$RuntimeDir")) | Out-Null
    Write-Ok "Service $ServiceName installed (logon: $LogonAccount)."
}

# --- ACLs (service SID resolves only after installation) ---------------------------------------------
if ($PSCmdlet.ShouldProcess($DataRoot, "Grant $LogonAccount access")) {
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($InstallDir, '/grant:r', "${AclPrincipal}:(OI)(CI)RX", '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($ConfDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${AclPrincipal}:(OI)(CI)M", '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($SecretsDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${AclPrincipal}:(OI)(CI)R", '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($LogsDir, '/grant:r', "${AclPrincipal}:(OI)(CI)M", '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($RuntimeDir, '/grant:r', "${AclPrincipal}:(OI)(CI)M", '/Q')
    Write-Ok 'ACLs: program files = read, confdir/logs = modify, secrets = read (no inheritance); everything else SYSTEM/Administrators only.'
}

# --- firewall ----------------------------------------------------------------------------------------
$opsHost, $opsPort = $OpsAddr -split ':', 2
if (-not $SkipFirewall -and $PSCmdlet.ShouldProcess($FirewallProxy, "Allow inbound TCP $ListenPort")) {
    Get-NetFirewallRule -Name $FirewallProxy -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name $FirewallProxy -DisplayName "AegisProxy Data-Plane Proxy (TCP $ListenPort)" -Group 'AegisProxy' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $ListenPort `
        -Profile $FirewallProfile -RemoteAddress $AllowedRemoteAddress | Out-Null
    Write-Ok ("Firewall: proxy port {0} open for {1} (profile {2})." -f $ListenPort, ($AllowedRemoteAddress -join ','), ($FirewallProfile -join ','))
    Get-NetFirewallRule -Name $FirewallOps -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($opsHost -notin @('127.0.0.1', 'localhost')) {
        if ($MonitoringRemoteAddress) {
            New-NetFirewallRule -Name $FirewallOps -DisplayName "AegisProxy Data-Plane Ops/Metrics (TCP $opsPort)" -Group 'AegisProxy' `
                -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([int]$opsPort) `
                -Profile $FirewallProfile -RemoteAddress $MonitoringRemoteAddress | Out-Null
            Write-Ok "Firewall: ops port $opsPort open for $($MonitoringRemoteAddress -join ',')."
        }
        else { Write-Note "Ops endpoint listens on $OpsAddr but no -MonitoringRemoteAddress was given: no firewall rule created." }
    }
}

# --- start + readiness -------------------------------------------------------------------------------
$ready = $false
if ($PSCmdlet.ShouldProcess($ServiceName, 'Start service and wait for /readyz')) {
    Write-Step "Starting $ServiceName"
    try { Start-Service -Name $ServiceName } catch { Write-Note "Start-Service reported: $($_.Exception.Message)" }
    $probeHost = $opsHost
    if ($probeHost -eq '0.0.0.0') { $probeHost = '127.0.0.1' }
    $base = "http://${probeHost}:$opsPort"
    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
    $alive = $false
    do {
        Start-Sleep -Seconds 2
        if (-not $alive -and (Get-HttpStatus "$base/healthz") -eq 200) { $alive = $true; Write-Step 'Worker process is up (/healthz), waiting for the first policy sync (/readyz)...' }
        if ($alive -and (Get-HttpStatus "$base/readyz") -eq 200) { $ready = $true; break }
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } while ((Get-Date) -lt $deadline -and $svc -and $svc.Status -ne 'Stopped')
    if ($ready) { Write-Ok "Data-plane is ready ($base/readyz): policy bundle loaded, proxy enforcing on port $ListenPort." }
    elseif ($alive) {
        Write-Note "Worker runs but has not loaded a policy yet ($base/readyz != 200). Until then it answers 503 (AEGIS_FAIL_MODE=$FailMode)."
        Show-Diagnostic
    }
    else {
        Write-Note "Worker did not come up within $ReadyTimeoutSeconds s (service status: $((Get-Service -Name $ServiceName).Status))."
        Show-Diagnostic
    }
}

# --- summary -----------------------------------------------------------------------------------------
Write-Host ''
Write-Host '==================== AegisProxy data-plane ====================' -ForegroundColor Cyan
Write-Host "Service         : $ServiceName (WinSW, logon $LogonAccount)"
Write-Host "Proxy           : http://<this-host>:$ListenPort   (explicit HTTP/HTTPS proxy)"
Write-Host "Ops endpoint    : http://$OpsAddr  (/healthz /readyz /metrics)"
Write-Host "Control-plane   : $ControlPlaneUrl"
Write-Host ("Antivirus       : {0}" -f ($(if ($ClamdAddress) { $ClamdAddress } else { 'disabled' })))
Write-Host "Logs            : $LogsDir"
if (Test-Path -LiteralPath $StagedCa) {
    $caInfo = Get-PemCertificateInfo $StagedCa
    if ($caInfo) { Write-Host "Root CA SHA-256 : $($caInfo.Fingerprint) (must match the control-plane)" -ForegroundColor Green }
}
Write-Host 'Manage          : Get-Service AegisDataPlane | Restart-Service   or   & "<InstallDir>\aegis-dataplane.exe" status'
Write-Host "Clients         : http_proxy/https_proxy=http://<proxy_auth_user>:<token>@<this-host>:$ListenPort (or source-IP identity); CA via <PublicUrl>/api/public/ca/install-windows.ps1 | install-linux.sh"
if (-not $ready -and -not $WhatIfPreference) { exit 1 }
