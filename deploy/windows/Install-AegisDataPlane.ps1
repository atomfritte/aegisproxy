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
    virtual environment from a python.org CPython >= 3.12 installed "for all users" into a directory that only
    administrators can modify (%ProgramFiles%) and installs mitmproxy==12.3.0 into it.

    Steps (idempotent; a re-run upgrades addon/venv/WinSW configuration and keeps the staged secrets):
      * refuses installation sources that non-administrators can change (this script, the WinSW template, WinSW,
        data-plane\, the lock file, the CA files, and every folder above them), before it runs or copies any of them
      * resolves Python (-PythonExe or the all-users installation of 3.12 / 3.13 / 3.14 registered in HKLM) and
        refuses an interpreter that non-administrators can modify before it runs it for the first time
      * takes over existing directories (owner Administrators, foreign ACEs removed), including
        %ProgramData%\AegisProxy above the default data root; files that existed before are only kept on an
        upgrade of an intact installation or with -AdoptExistingSecrets
      * creates <InstallDir>\venv and installs the hash-locked data-plane\requirements-lock.txt (mitmproxy 12.3.0,
        YARA-X and every dependency, binary wheels only) with pip --require-hashes
      * copies data-plane\aegis_addon.py + aegis_dp\ to <InstallDir>\app (byte-compiled)
      * stages the data-plane key and the CA (mitmproxy-ca.pem = key + cert) into <DataRoot> with ACLs that
        only SYSTEM, Administrators and the service account can read (verified after the installation)
      * copies WinSW into the admin-only program directory and verifies the SHA-256 of that copy, renders
        aegis-dataplane.xml (template next to this script), installs the service "AegisDataPlane" and
        switches it to the virtual account NT SERVICE\AegisDataPlane (or LocalService)
      * opens the proxy port in Windows Firewall for the allowed server subnets only
      * starts the service and waits for http://<OpsAddr>/readyz (= first policy bundle loaded)

    Layout:
      <InstallDir>\venv\                 Python virtual environment (mitmproxy 12.3.0)
      <InstallDir>\app\                  aegis_addon.py + aegis_dp\
      <InstallDir>\aegis-dataplane.exe   copy of WinSW-x64.exe (+ aegis-dataplane.xml)
      <DataRoot>\confdir\                private mitmproxy confdir (staged CA, dhparam) - service: modify
      <DataRoot>\secrets\dataplane.key   shared secret with the control-plane         - service: read
      <DataRoot>\logs\                   WinSW + mitmdump logs (rolled by size)        - service: modify
      <DataRoot>\flow-spool\             traffic records not yet acknowledged by the control-plane
                                         (AEGIS_FLOW_SPOOL_DIR)                       - service: modify

.PARAMETER PythonExe
    Explicit python.exe (python.org CPython >= 3.12, installed for all users). Default: the all-users installation
    of Python 3.12, then 3.13, 3.14 as registered in HKLM\SOFTWARE\Python\PythonCore\<version>\InstallPath (PEP 514,
    what "py -3.12" finds); found without running the launcher or the interpreter. The interpreter is first run
    after its directory, DLLs, Lib and site-packages passed the check of -AllowWritablePython, and always in
    isolated mode (-I; the version probe also without the site module, -S).

.PARAMETER AllowWritablePython
    Accept a base interpreter whose directory, Lib, DLLs or site-packages non-administrators (Users,
    Authenticated Users, Everyone, INTERACTIVE, ...) can modify or create files in, e.g. C:\Python312 below a
    volume root that lets users create files. Code planted there runs in the service, and in this script (as
    Administrator) as soon as it runs the interpreter. Not recommended.

.PARAMETER AllowWritableSource
    Accept installation sources that non-administrators can change: this script, the WinSW template next to it,
    -WinSWExe, -SourceDir (everything below it), -RequirementsFile, -CaFile, -ControlPlaneCaFile and every folder above
    them up to the volume root. Allowed are only SYSTEM, Administrators and TrustedInstaller as owners and as
    principals that may write, create, delete, rename, change the permissions or take ownership (above the sources:
    rename, delete entries, change the permissions, take ownership). The script runs and copies these files with
    administrator rights, and the addon and the lock file decide which code runs in the service. Not recommended:
    keep the release in a folder that only administrators control (docs/deployment/windows.md, section 2).

.PARAMETER DataRoot
    Data directory (default %ProgramData%\AegisProxy\data-plane). Its parent %ProgramData%\AegisProxy is taken over
    as well (owner Administrators, SYSTEM/Administrators only; a control-plane on this host keeps the ACLs of its own
    subdirectories): whoever owns the parent could rename the data directory and put a junction in its place. Any
    other parent must already be controlled by administrators - the installation stops if a non-administrator owns
    it or may delete entries in it, change its permissions or take ownership of it.

.PARAMETER SourceDir
    The repository's data-plane folder (contains aegis_addon.py and aegis_dp\). Default: ..\..\data-plane.

.PARAMETER ControlPlaneUrl
    CONTROL_PLANE_URL - base URL of the control-plane (load balancer in cluster mode). https recommended.

.PARAMETER DataPlaneKeyFile
    File containing the data-plane key (control-plane: <DataRoot>\secrets\dataplane.key). Copied, never referenced.
    An SMB path (UNC or mapped drive) must use an encrypted connection, see -AllowUnencryptedImport.

.PARAMETER CaFile
    mitmproxy-ca.pem (CA private key + certificate) from the control-plane certs directory. Default when the
    control-plane service is installed on the same host: %ProgramData%\AegisProxy\certs\mitmproxy-ca.pem (only
    if that file is restricted to SYSTEM/Administrators). On a re-run without -CaFile the already staged CA is
    kept. Same SMB encryption requirement as -DataPlaneKeyFile.

.PARAMETER AllowUnencryptedImport
    Accept -DataPlaneKeyFile / -CaFile on an SMB connection that is not encrypted (the key and the CA private key
    then cross the network in clear text).

.PARAMETER AdoptExistingSecrets
    Keep a staged CA, control-plane CA bundle, confdir files and program files (venv, addon) that existed before
    this run although no intact installation vouches for them (no AegisDataPlane service, or directories whose
    owner/ACL differ from what this script sets). Not for files of unknown origin: a local user may have planted
    them (a confdir\config.yaml, for example, configures mitmdump).

.PARAMETER PolicyMaxAge
    AEGIS_POLICY_MAX_AGE (default 10m): once the last successful policy sync is older, the worker fails closed
    (503 policy_stale, open connections closed, /readyz fails) until it reaches the control-plane again, so a cut-off
    worker cannot keep enforcing a policy without later quarantines or revocations. Durations such as 900s, 15m,
    1h (at least 30 seconds and 5 x AEGIS_SYNC_INTERVAL_SECONDS); '' or 0 = no limit (posture warning).

.PARAMETER ClamdAddress
    AEGIS_CLAMD_ADDRESS, e.g. tcp://127.0.0.1:3310 (ClamAV for Windows). Empty string disables antivirus.
    unix:// sockets are not supported on Windows.

.PARAMETER WinSWExe
    Path to a verified WinSW-x64.exe (2.x). It is NOT downloaded automatically.

.PARAMETER WinSWSha256
    Expected SHA-256 of -WinSWExe. Default: WinSW-x64.exe of WinSW 2.12.0. Checked before any change and again
    on the copy in the program directory that is installed as the service; the installation stops on a
    mismatch. Pass the hash of your verified copy when you deploy another 2.x release.

.PARAMETER AllowedRemoteAddress
    Remote addresses allowed to use the proxy port (Windows Firewall), e.g. 10.20.0.0/16,10.30.0.0/16.

.PARAMETER ServiceAccount
    Virtual (default): NT SERVICE\AegisDataPlane - dedicated per-service SID, ACLs apply to this service only.
    LocalService: NT AUTHORITY\LocalService - shared with other services, use only if virtual accounts are
    prohibited by policy.

.PARAMETER RequirementsFile
    Your own complete, hash-pinned lock file instead of the shipped data-plane\requirements-lock.txt (default),
    installed with --require-hashes --no-deps (include yara-x to keep YARA scanning; -NoYara does not edit it). It
    must pin every dependency and at least the versions of data-plane\requirements-security.txt, e.g.
    uv pip compile --generate-hashes --override requirements-security.txt requirements.in. The overrides are not
    installed on top of it (that would bypass hash checking); the script verifies the baseline versions and runs
    pip check, which may only report the conflicts caused by those overrides. The shipped lock is checked the same
    way and installed from binary wheels only (--only-binary=:all:, no source builds as Administrator).

.PARAMETER AllowUnpinnedPackages
    Install mitmproxy==12.3.0, yara-x==1.22.0 and data-plane\requirements-security.txt from the package index
    without hash pinning (pip resolves the dependencies) instead of the shipped lock file. A compromised index,
    mirror or proxy then decides which code runs in the service. Not recommended.

.PARAMETER Uninstall
    Removes the service, firewall rules, program files and the staged CA/key copies; keeps the logs.

.EXAMPLE
    .\Install-AegisDataPlane.ps1 -ControlPlaneUrl https://aegis.corp.example `
        -DataPlaneKeyFile C:\ProgramData\AegisProxy\secrets\dataplane.key `
        -CaFile C:\ProgramData\AegisProxy\certs\mitmproxy-ca.pem `
        -WinSWExe C:\Install\WinSW-x64.exe -AllowedRemoteAddress 10.20.0.0/16,10.30.0.0/16

.EXAMPLE
    # Own hash-pinned lock file (kept with the release: its hashes decide what runs), wheels from an internal share
    .\Install-AegisDataPlane.ps1 ... -RequirementsFile C:\Install\AegisProxy\requirements-win.txt `
        -PipArgs '--no-index','--find-links','\\fs\aegis\wheels'

.NOTES
    Reference for all variables: docs/configuration.md. Operations guide: docs/deployment/windows.md.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string]$PythonExe,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowWritablePython,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowWritableSource,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowUnencryptedImport,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AdoptExistingSecrets,

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
    [ValidatePattern('^(\d+|(\d+[smhdSMHD])+)?$')]
    [string]$PolicyMaxAge = '10m',

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('error', 'warn', 'info', 'alert', 'debug')]
    [string]$MitmLogLevel = 'info',

    # Additional pip arguments, e.g. '--no-index','--find-links','\\fs\wheels' or '--index-url','https://nexus/...'.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$PipArgs,

    # Complete hash-pinned lock file instead of the shipped data-plane\requirements-lock.txt (installed with
    # --require-hashes --no-deps); include yara-x in it to keep YARA scanning.
    [Parameter(ParameterSetName = 'Install')]
    [string]$RequirementsFile,

    # Install from the package index without hash pinning instead of the shipped lock file (not recommended).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowUnpinnedPackages,

    # Do not install the YARA-X engine (YARA rule sets then report "unavailable" on this worker). The shipped lock
    # file is installed without its yara-x entry.
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
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'   # NT SERVICE\TrustedInstaller

$InstallDir  = [System.IO.Path]::GetFullPath($InstallDir)
$DataRoot    = [System.IO.Path]::GetFullPath($DataRoot)
$DataParent  = Split-Path -Parent $DataRoot
# %ProgramData%\AegisProxy (parent of the default data root, data root of a control-plane on this host) is taken over.
$OwnDataParent = $DataParent.TrimEnd('\', '/') -eq ([System.IO.Path]::GetFullPath((Join-Path $env:ProgramData 'AegisProxy'))).TrimEnd('\', '/')
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
$SpoolDir    = Join-Path $DataRoot 'flow-spool'
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

function Get-ServiceSid([string]$Name) {
    # SID of NT SERVICE\<Name>, computed (it must be known before the service exists): S-1-5-80 and the SHA-1 of
    # the upper-case name in UTF-16LE as five little-endian DWORDs.
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Name.ToUpperInvariant())) } finally { $sha.Dispose() }
    return 'S-1-5-80-' + ((0..4 | ForEach-Object { [System.BitConverter]::ToUInt32($hash, 4 * $_) }) -join '-')
}

function ConvertTo-FileRight([int]$Rights) {
    # FileSystemRights of an ACE as unsigned mask of specific rights (generic rights mapped like NTFS does).
    $mask = [int64]$Rights -band 4294967295
    if ($mask -band 268435456)  { $mask = $mask -bor 2032127 }   # GENERIC_ALL     -> FullControl
    if ($mask -band 1073741824) { $mask = $mask -bor 1179926 }   # GENERIC_WRITE   -> FILE_GENERIC_WRITE
    if ($mask -band 2147483648) { $mask = $mask -bor 1179785 }   # GENERIC_READ    -> FILE_GENERIC_READ
    if ($mask -band 536870912)  { $mask = $mask -bor 1179808 }   # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
    return ($mask -band 2032127)
}

function Get-WritableSource {
    # Installation sources that someone other than SYSTEM, Administrators and TrustedInstaller can change (allowlist),
    # as Path/Who pairs. The installers run and copy them with administrator rights. Checked are each existing source,
    # everything below a source directory (links are not followed) and every directory above it up to the volume root:
    # a junction or symbolic link (its target is not checked), an owner outside that set (owners can always rewrite the
    # ACL) and the allow ACEs of other principals, explicit or inherited. On the sources and below them any of 852038 =
    # WriteData/CreateFiles, AppendData/CreateDirectories, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions,
    # TakeOwnership (generic rights mapped) counts, also in ACEs that only pass on to children. Above them only what
    # lets others replace their entries counts, on the directory itself: 852032 (Delete = rename, without creating
    # files and folders, which the volume root allows everyone), 786496 on the volume root (it cannot be renamed).
    # CREATOR OWNER / CREATOR GROUP / OWNER RIGHTS ACEs only reach owners, which are checked themselves.
    param([string[]]$Path = @())
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $ownerOnly = @('S-1-3-0', 'S-1-3-1', 'S-1-3-4')
    $names = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-7' = 'ANONYMOUS LOGON'; 'S-1-5-11' = 'Authenticated Users'
        'S-1-5-32-545' = 'Users'; 'S-1-5-32-546' = 'Guests'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE' }
    $checks = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($p in @($Path | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $current = (Resolve-Path -LiteralPath $p).ProviderPath
        if ($current.Length -gt 3) { $current = $current.TrimEnd('\', '/') }
        $above = $false
        while ($current -and -not $seen.ContainsKey("$above|$current")) {
            $seen["$above|$current"] = $true
            $checks.Add(@{ Path = $current; Above = $above })
            $current = [System.IO.Path]::GetDirectoryName($current)
            $above = $true
        }
    }
    $found = [ordered]@{}
    foreach ($check in $checks) {
        $pending = New-Object System.Collections.Stack
        $pending.Push($check.Path)
        while ($pending.Count) {
            $p = [string]$pending.Pop()
            $who = @()
            $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            if (-not $item) { $who += 'not readable' }
            elseif ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $who += 'junction/symbolic link, its target is not checked' }
            else {
                try { $acl = Get-Acl -LiteralPath $p; $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) }
                catch { $acl = $null; $who += 'ACL not readable' }
                if ($acl) {
                    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
                    $ownerSid = if ($owner) { "$($owner.Value)" } else { 'none' }
                    if ($trusted -notcontains $ownerSid) { $who += "owner $(if ($names.ContainsKey($ownerSid)) { $names[$ownerSid] } else { $ownerSid })" }
                    $mask = if (-not $check.Above) { 852038 } elseif ([System.IO.Path]::GetDirectoryName($p)) { 852032 } else { 786496 }
                    foreach ($rule in $rules) {
                        $sid = "$($rule.IdentityReference.Value)"
                        if ("$($rule.AccessControlType)" -ne 'Allow' -or $trusted -contains $sid -or $ownerOnly -contains $sid) { continue }
                        if ($check.Above -and "$($rule.PropagationFlags)" -match 'InheritOnly') { continue }
                        if (-not ((ConvertTo-FileRight ([int]$rule.FileSystemRights)) -band $mask)) { continue }
                        $who += $(if ($names.ContainsKey($sid)) { $names[$sid] } else { $sid })
                    }
                }
                if (-not $check.Above -and $item.PSIsContainer) {
                    try { foreach ($child in @(Get-ChildItem -LiteralPath $p -Force)) { $pending.Push($child.FullName) } }
                    catch { $who += 'content not readable' }
                }
            }
            if ($who.Count) { $found[$p] = @(@($found[$p]) + $who | Where-Object { $_ } | Sort-Object -Unique) }
        }
    }
    foreach ($p in $found.Keys) { [pscustomobject]@{ Path = $p; Who = ($found[$p] -join ', ') } }
}

function Assert-TrustedSource {
    # Stops before anything of the sources is read, run or copied when Get-WritableSource reports them (with -Allow:
    # warns), and shows how to keep the release in a folder that only administrators control.
    param([string[]]$Path = @(), [switch]$Allow)
    $writable = @(Get-WritableSource -Path $Path | Sort-Object -Property Path)
    if (-not $writable.Count) { return }
    $list = @($writable | Select-Object -First 15 | ForEach-Object { '  {0} ({1})' -f $_.Path, $_.Who })
    if ($writable.Count -gt 15) { $list += "  ... and $($writable.Count - 15) more" }
    $folder = Join-Path $env:SystemDrive 'Install'
    $message = ("Non-administrators can change installation sources that this script runs or copies with administrator rights:`n{0}`n" +
        "Copy the release into a folder that only administrators control (docs/deployment/windows.md, section 2), e.g.:`n" +
        "  New-Item -ItemType Directory -Force `"{1}`"`n" +
        "  icacls `"{1}`" /inheritance:r /grant:r `"*S-1-5-32-544:(OI)(CI)F`" `"*S-1-5-18:(OI)(CI)F`"`n" +
        "  (copy the release into it)`n" +
        "  icacls `"{1}`" /setowner *S-1-5-32-544 /T /L /C /Q`n" +
        'Copy it again rather than fixing the ACLs in place: files that others could change may have been altered') -f ($list -join "`n"), $folder
    if (-not $Allow) { throw "$message. Or pass -AllowWritableSource to accept the risk." }
    Write-Note "$message. Continuing because of -AllowWritableSource."
}

function Get-AclProblem {
    # Deviations of Path from the expected ACL: a directory must be owned by Administrators or SYSTEM, and every
    # allow ACE (explicit or inherited) must belong to a principal of -Allowed (SID -> F|M|RX|R) and stay within
    # that principal's rights.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][hashtable]$Allowed)
    try { $acl = Get-Acl -LiteralPath $Path }
    catch { return @("${Path}: ACL not readable ($($_.Exception.Message))") }
    $problems = @()
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerSid = if ($owner) { "$($owner.Value)" } else { 'none' }
    if ((Test-Path -LiteralPath $Path -PathType Container) -and @('S-1-5-18', 'S-1-5-32-544') -notcontains $ownerSid) {
        $problems += "${Path}: owner $ownerSid is not Administrators/SYSTEM"
    }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
        $sid = "$($rule.IdentityReference.Value)"
        if (-not $Allowed.ContainsKey($sid)) { $problems += "${Path}: access for $sid is not expected"; continue }
        if ((ConvertTo-FileRight ([int]$rule.FileSystemRights)) -band -bnot $AclRights[$Allowed[$sid]]) {
            $problems += "${Path}: $sid has more than $($Allowed[$sid]) access"
        }
    }
    return $problems
}

function Get-NonAdminWritable {
    # Paths that someone other than SYSTEM, Administrators, TrustedInstaller and the service itself can modify
    # (allowlist): an owner outside that set (owners can always rewrite the ACL), or an allow ACE of another
    # principal - explicit or inherited, also one that only passes on to children - with any of 852038 =
    # WriteData/CreateFiles, AppendData/CreateDirectories, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions,
    # TakeOwnership (generic rights mapped). CREATOR OWNER / CREATOR GROUP / OWNER RIGHTS ACEs only reach owners,
    # which are checked themselves. For -Container (directories that hold the checked tree, e.g. the parent of the
    # Python directory) only what allows deleting, renaming or replacing their entries counts: owner and
    # DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership (786496) on the directory itself.
    param([string[]]$Path = @(), [string[]]$Container = @())
    $trusted = @('S-1-5-18', 'S-1-5-32-544', $SidTrustedInstaller, (Get-ServiceSid $ServiceName))
    $ownerOnly = @('S-1-3-0', 'S-1-3-1', 'S-1-3-4')
    $names = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-7' = 'ANONYMOUS LOGON'; 'S-1-5-11' = 'Authenticated Users'
        'S-1-5-32-545' = 'Users'; 'S-1-5-32-546' = 'Guests'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE' }
    $found = @()
    $checks = @(@($Path | ForEach-Object { @{ Path = $_; Mask = 852038; Self = $false } }) +
        @($Container | Where-Object { $_ } | ForEach-Object { @{ Path = $_; Mask = 786496; Self = $true } }))
    foreach ($check in $checks) {
        $p = $check.Path
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try { $acl = Get-Acl -LiteralPath $p; $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) }
        catch { $found += "$p (ACL not readable)"; continue }
        $who = @()
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        $ownerSid = if ($owner) { "$($owner.Value)" } else { 'none' }
        if ($trusted -notcontains $ownerSid) { $who += "owner $(if ($names.ContainsKey($ownerSid)) { $names[$ownerSid] } else { $ownerSid })" }
        foreach ($rule in $rules) {
            $sid = "$($rule.IdentityReference.Value)"
            if ("$($rule.AccessControlType)" -ne 'Allow' -or $trusted -contains $sid -or $ownerOnly -contains $sid) { continue }
            if ($check.Self -and "$($rule.PropagationFlags)" -match 'InheritOnly') { continue }
            if (-not ((ConvertTo-FileRight ([int]$rule.FileSystemRights)) -band $check.Mask)) { continue }
            $who += $(if ($names.ContainsKey($sid)) { $names[$sid] } else { $sid })
        }
        $who = @($who | Sort-Object -Unique)
        if ($who.Count) { $found += '{0} ({1})' -f $p, ($who -join ', ') }
    }
    return $found
}

function Assert-PlainItem($Item) {
    # Refuses a junction or symbolic link (ACL changes and deletions would act on its target) and a file with further
    # hard links (its ACL is shared with a file elsewhere).
    if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Junction/symbolic link in the installation directories: $($Item.FullName). Remove it and re-run."
    }
    if (-not $Item.PSIsContainer -and "$($Item.LinkType)" -eq 'HardLink') {
        throw "$($Item.FullName) has further hard links (they share its ACL with a file elsewhere). Remove it and re-run."
    }
}

function Protect-Directory {
    # Takes over a directory that may have existed before the installation, top-down, so that whoever created it
    # cannot swap in a link while it is processed. Root first: owner Administrators and a protected ACL with -Grant
    # (explicit ACEs of principals that are not -Allowed are removed) - from then on nobody else can create, delete
    # or rename entries in it. Then -Children and everything below them, each item only after its parent: owner
    # Administrators, explicit ACEs dropped (it inherits from Root only). icacls always gets /L (a link itself is
    # changed, never its target) and never /T (which follows links). A link or hard-linked file stops the
    # installation; items are checked again once taken over (until then their creator could still turn an empty
    # directory into a junction). -AllChildren takes the entries of Root as listed after it was locked.
    # -Trusted (upgrade of an intact installation: only administrators could write there) resets each child with
    # one recursive icacls run instead.
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string[]]$Grant,
        [Parameter(Mandatory = $true)][hashtable]$Allowed, [string[]]$Children = @(), [switch]$AllChildren, [switch]$Trusted)
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/setowner', $SidAdmins, '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList (@($Root, '/inheritance:r', '/grant:r') + $Grant + @('/L', '/Q'))
    $foreign = @((Get-Acl -LiteralPath $Root).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
            ForEach-Object { "$($_.IdentityReference.Value)" } | Where-Object { -not $Allowed.ContainsKey($_) } | Sort-Object -Unique)
    foreach ($sid in $foreign) { $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/remove', "*$sid", '/L', '/Q') }
    Assert-PlainItem (Get-Item -LiteralPath $Root -Force)
    if ($AllChildren) { $Children = @(Get-ChildItem -LiteralPath $Root -Force | ForEach-Object { $_.FullName }) }
    if ($Trusted) {
        foreach ($child in $Children) {
            if (-not (Test-Path -LiteralPath $child)) { continue }
            $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($child, '/setowner', $SidAdmins, '/T', '/L', '/C', '/Q')
            $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($child, '/reset', '/T', '/L', '/C', '/Q')
        }
        return
    }
    $pending = New-Object System.Collections.Stack
    foreach ($child in $Children) { $pending.Push($child) }
    while ($pending.Count) {
        $path = [string]$pending.Pop()
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        Assert-PlainItem $item
        $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/setowner', $SidAdmins, '/L', '/Q')
        $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/reset', '/L', '/Q')
        Assert-PlainItem (Get-Item -LiteralPath $path -Force)
        if ($item.PSIsContainer) { foreach ($child in @(Get-ChildItem -LiteralPath $path -Force)) { $pending.Push($child.FullName) } }
    }
}

function Find-ReparsePoint([string[]]$Path) {
    # Junctions and symbolic links at or below Path, found without following them (icacls /T, robocopy and
    # Remove-Item -Recurse of Windows PowerShell 5.1 act on their targets), and files with further hard links (they
    # share their ACL with a file elsewhere). Unreadable directories throw.
    $found = @()
    $pending = New-Object System.Collections.Stack
    foreach ($p in $Path) { if (Test-Path -LiteralPath $p) { $pending.Push((Get-Item -LiteralPath $p -Force)) } }
    while ($pending.Count) {
        $item = $pending.Pop()
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $found += $item.FullName }
        elseif ($item.PSIsContainer) { foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force)) { $pending.Push($child) } }
        elseif ("$($item.LinkType)" -eq 'HardLink') { $found += "$($item.FullName) (hard link)" }
    }
    return $found
}

function Remove-DirectoryTree([string]$Path) {
    # Deletes Path without following links: junctions and symbolic links below it are removed as links and their
    # targets stay untouched (Remove-Item -Recurse of Windows PowerShell 5.1 deletes the targets' content).
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if ($item.PSIsContainer -and -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force)) {
            if ($child.PSIsContainer) { Remove-DirectoryTree $child.FullName; continue }
            if ($child.IsReadOnly) { $child.IsReadOnly = $false }
            [System.IO.File]::Delete($child.FullName)
        }
    }
    if ($item.PSIsContainer) { [System.IO.Directory]::Delete($item.FullName, $false) } else { [System.IO.File]::Delete($item.FullName) }
}

function Assert-EncryptedSmbSource {
    # Secrets read from an SMB share cross the network in clear text unless the connection is encrypted (share or
    # server with SMB encryption, or a mapping created with New-SmbMapping -RequirePrivacy $true). Every spelling of
    # a network path counts: \\server\share, //server/share and mixed separators, \\?\UNC\ and \\.\UNC\, FileSystem::
    # provider paths, drive letters mapped to a share (also as \\?\Z:\). Other device paths (\\?\GLOBALROOT\...,
    # \\?\Volume{...}) are refused. Loopback servers (localhost, 127.0.0.0/8, ::1) are shares of this host: the files
    # do not cross the network.
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Path, [switch]$AllowUnencrypted)
    $remote = ($Path -replace '^(Microsoft\.PowerShell\.Core\\)?FileSystem::', '').Replace('/', '\')
    # Device namespace prefixes: \\?\, \\.\ and the NT form \??\.
    if ($remote -match '^(\\\\[?.]|\\\?\?)\\UNC\\(?<rest>.*)$') { $remote = '\\' + $Matches['rest'] }
    elseif ($remote -match '^(\\\\[?.]|\\\?\?)\\(?<rest>[A-Za-z]:(\\.*)?)$') { $remote = $Matches['rest'] }
    elseif ($remote -match '^(\\\\[?.]|\\\?\?)\\') { throw "$Name '$Path' is a device path. Pass a drive-letter or UNC path (\\server\share\...)." }
    if ($remote -match '^(?<drive>[A-Za-z]:)') {
        $mapping = @(Get-SmbMapping -LocalPath $Matches['drive'] -ErrorAction SilentlyContinue)
        if (-not $mapping.Count) { return }
        $remote = "$($mapping[0].RemotePath)".TrimEnd('\') + '\' + $remote.Substring(2).TrimStart('\')
    }
    if (-not $remote.StartsWith('\\')) { return }
    # \\server\share\x, \\\server\share\x and \\server\\share\x name the same share.
    $parts = @($remote.Split([char]'\') | Where-Object { $_ })
    $server = if ($parts.Count) { $parts[0] } else { '' }
    $share = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    if ($server -match '^(localhost|127(\.\d{1,3}){3}|::1|\[::1\]|0--1\.ipv6-literal\.net)$') {
        Write-Note "${Name}: \\$server\$share is a share of this host (loopback); the files do not cross the network."
        return
    }
    $null = Test-Path -LiteralPath ('\\' + ($parts -join '\'))   # opens the SMB session if there is none yet
    $connections = @(Get-SmbConnection -ServerName $server -ErrorAction SilentlyContinue | Where-Object { $_.ShareName -eq $share })
    if ($connections.Count -and -not @($connections | Where-Object { -not $_.Encrypted }).Count) {
        Write-Ok "${Name}: the SMB connection to \\$server\$share is encrypted."
        return
    }
    $message = "$Name reads secrets from \\$server\$share over an SMB connection that is not encrypted. Map the share with " +
        "New-SmbMapping -RemotePath '\\$server\$share' -RequirePrivacy `$true (or enable encryption on the share: Set-SmbShare -EncryptData `$true), " +
        'or copy the files over another protected channel.'
    if (-not $AllowUnencrypted) { throw "$message -AllowUnencryptedImport accepts the risk." }
    Write-Note "$message Continuing because of -AllowUnencryptedImport."
}

function Get-ExistingFile([string[]]$Path) {
    # Files below Path (reparse points are refused before, so the recursion stays inside Path).
    foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p) { Get-ChildItem -LiteralPath $p -Recurse -Force -File | ForEach-Object { $_.FullName } }
    }
}

function Get-InstallationAclProblem {
    # Deviations of the program and data directories (and the staged key/CA, wrapper, venv interpreter) from the
    # ACLs this script sets for the given service principal(s).
    param([Parameter(Mandatory = $true)][string[]]$Principal, [switch]$IncludeLogs)
    $program = $AclAdmins + @{ 'S-1-5-32-545' = 'RX' }
    $modify = $AclAdmins.Clone(); $read = $AclAdmins.Clone()
    foreach ($sid in $Principal) { $program[$sid] = 'RX'; $modify[$sid] = 'M'; $read[$sid] = 'R' }
    $checks = [ordered]@{}
    foreach ($path in @($InstallDir, $WrapperExe, $VenvPython)) { $checks[$path] = $program }
    $checks[$DataRoot] = $AclAdmins
    foreach ($path in @($ConfDir, $StagedCa, $RuntimeDir, $SpoolDir)) { $checks[$path] = $modify }
    $checks[$SecretsDir] = $read
    if (Test-Path -LiteralPath $SecretsDir) {
        foreach ($file in @(Get-ChildItem -LiteralPath $SecretsDir -Force -File)) { $checks[$file.FullName] = $read }
    }
    if ($IncludeLogs) { $checks[$LogsDir] = $modify }
    $problems = @()
    foreach ($path in $checks.Keys) { if (Test-Path -LiteralPath $path) { $problems += @(Get-AclProblem -Path $path -Allowed $checks[$path]) } }
    return $problems
}

# Expected ACLs (SID -> maximum rights) and the FileSystemRights masks of the icacls grants F, M, RX and R.
$AclSid     = if ($ServiceAccount -eq 'LocalService') { $SidLocalService.TrimStart('*') } else { Get-ServiceSid $ServiceName }
$AclRights  = @{ F = 2032127; M = 1245631; RX = 1179817; R = 1179785 }
$AclAdmins  = @{ 'S-1-5-18' = 'F'; 'S-1-5-32-544' = 'F' }
$AclProgram = $AclAdmins + @{ 'S-1-5-32-545' = 'RX'; $AclSid = 'RX' }

# Security baseline check, run by the venv's Python: PEP 440 comparison with packaging (pip's vendored copy if
# packaging itself is not installed), e.g. 1.2.1rc1 < 1.2.1 < 1.2.1.post1; an invalid version fails the check.
$BaselineCheck = @(
    'import re, sys, importlib.metadata as m'
    'try:'
    '    from packaging.version import Version'
    'except ImportError:'
    '    from pip._vendor.packaging.version import Version'
    'low = []'
    'for line in open(sys.argv[1], encoding=''utf-8''):'
    '    hit = re.match(r''\s*([A-Za-z0-9._-]+)==([^\s;#]+)'', line)'
    '    if not hit:'
    '        continue'
    '    try:'
    '        have = m.version(hit.group(1))'
    '    except m.PackageNotFoundError:'
    '        continue'
    '    if Version(have) < Version(hit.group(2)):'
    '        low.append(hit.group(1) + '' '' + have + '' < '' + hit.group(2))'
    'print(''; ''.join(low))'
    'sys.exit(1 if low else 0)'
) -join "`n"

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
    # Links below these directories are removed as links; their targets are never touched.
    if ($PSCmdlet.ShouldProcess("$ConfDir, $SecretsDir, $SpoolDir", 'Delete staged CA private key and data-plane key copies and undelivered traffic records')) {
        foreach ($dir in @($ConfDir, $SecretsDir, $RuntimeDir, $SpoolDir)) { Remove-DirectoryTree $dir }
    }
    if ((Test-Path -LiteralPath $InstallDir) -and $PSCmdlet.ShouldProcess($InstallDir, 'Remove program files (venv, addon, WinSW)')) {
        Remove-DirectoryTree $InstallDir
    }
    Write-Ok 'AegisProxy data-plane uninstalled.'
    Write-Note "Logs were kept in $LogsDir. The staged CA key / data-plane key copies (the originals remain on the control-plane) and traffic records not yet delivered to the control-plane (flow-spool) were deleted."
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

# Everything this script runs or copies as Administrator, or that decides which code runs in the service (addon, lock
# file, WinSW, CAs), must be out of reach of other accounts, including the folders above it (whoever may rename one can
# replace the files). The CA of a control-plane on this host (used without -CaFile) must be restricted to
# SYSTEM/Administrators, see below; a -CaFile that names the staged copy itself (a re-run that keeps the CA) belongs to
# this installation, whose ACLs are verified like the other staged files.
$caSource = $CaFile
if ($CaFile -and (Test-Path -LiteralPath $CaFile -PathType Leaf) -and
    [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $CaFile).ProviderPath) -eq [System.IO.Path]::GetFullPath($StagedCa)) { $caSource = $null }
Assert-TrustedSource -Path @($PSCommandPath, $Template, $WinSWExe, $SourceDir, $RequirementsFile, $caSource, $ControlPlaneCaFile) -Allow:$AllowWritableSource

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
# Early check (nothing is changed on a mismatch); the copy that becomes the service binary is verified again.
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
Assert-EncryptedSmbSource -Name '-DataPlaneKeyFile' -Path $DataPlaneKeyFile -AllowUnencrypted:$AllowUnencryptedImport
$keyValue = Read-SecretFile $DataPlaneKeyFile
if (-not $keyValue) { throw "Data-plane key file '$DataPlaneKeyFile' not found or empty." }
if ($keyValue.Length -lt 32 -or $keyValue -match '\s') { throw "The data-plane key in '$DataPlaneKeyFile' must be a single token of at least 32 characters." }

# CA (key + certificate)
if (-not $CaFile -and -not (Test-Path -LiteralPath $StagedCa)) {
    # Only the CA of an installed control-plane, whose installer restricts it to SYSTEM/Administrators.
    $sameHostCa = Join-Path $env:ProgramData 'AegisProxy\certs\mitmproxy-ca.pem'
    if ((Test-Path -LiteralPath $sameHostCa) -and (Get-Service -Name 'AegisControlPlane' -ErrorAction SilentlyContinue)) {
        $sameHostProblems = @(Get-AclProblem -Path $sameHostCa -Allowed $AclAdmins)
        if ($sameHostProblems.Count) {
            throw "The control-plane CA on this host is not restricted to SYSTEM/Administrators ($($sameHostProblems -join '; ')). Re-run Install-AegisControlPlane.ps1 or pass -CaFile."
        }
        $CaFile = $sameHostCa; Write-Step "Using the control-plane CA on this host: $CaFile"
    }
    else { throw '-CaFile is required: path to mitmproxy-ca.pem (CA private key + certificate) from the control-plane certs directory.' }
}
if ($CaFile) {
    Assert-EncryptedSmbSource -Name '-CaFile' -Path $CaFile -AllowUnencrypted:$AllowUnencryptedImport
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
    'AEGIS_POLICY_MAX_AGE', 'AEGIS_FLOW_SPOOL_DIR', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'PYTHONUTF8')
if ($ExtraEnvironment) {
    foreach ($key in $ExtraEnvironment.Keys) {
        if ($key -notmatch '^[A-Z_][A-Z0-9_]*$') { throw "Invalid environment variable name '$key'." }
        if ($reservedEnv -contains $key) { throw "$key is managed by this script (template or dedicated parameter)." }
    }
}

# Policy max age: the worker's minimum of 30 seconds (it also checks 5 x AEGIS_SYNC_INTERVAL_SECONDS itself).
$policyMaxAgeSeconds = 0
foreach ($m in [regex]::Matches($PolicyMaxAge.ToLowerInvariant(), '(\d+)([smhd]?)')) {
    $policyMaxAgeSeconds += [long]$m.Groups[1].Value * @{ '' = 1; 's' = 1; 'm' = 60; 'h' = 3600; 'd' = 86400 }[$m.Groups[2].Value]
}
if ($policyMaxAgeSeconds -gt 0 -and $policyMaxAgeSeconds -lt 30) { throw "-PolicyMaxAge '$PolicyMaxAge' is too short (at least 30 seconds, or 0 for no limit)." }
if (-not $policyMaxAgeSeconds) { Write-Note 'No -PolicyMaxAge: a worker cut off from the control-plane keeps enforcing its last policy indefinitely (no later quarantines or revocations).' }

# Python (python.org CPython >= 3.12, all-users installation). Nothing runs the interpreter before its files passed
# the check below: on startup it loads the DLLs next to python.exe, imports sitecustomize/usercustomize and executes
# the import lines of every site-packages\*.pth, so code planted there would run here as Administrator. The path comes
# from -PythonExe or from the registration of the all-users installation (PEP 514, HKLM: only administrators can
# change it; py -3.12 reads the same keys), not from running the launcher.
$pythonBase = $null
if ($PythonExe) {
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "-PythonExe '$PythonExe' not found." }
    $pythonBase = (Resolve-Path -LiteralPath $PythonExe).ProviderPath
}
else {
    foreach ($tag in @('3.12', '3.13', '3.14')) {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Python\PythonCore\$tag\InstallPath" -ErrorAction SilentlyContinue
        if (-not $reg) { continue }
        $exe = if ($reg.PSObject.Properties['ExecutablePath']) { "$($reg.ExecutablePath)" }
        elseif ($reg.PSObject.Properties['(default)']) { Join-Path "$($reg.'(default)')" 'python.exe' }
        else { '' }
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $pythonBase = (Resolve-Path -LiteralPath $exe).ProviderPath; break }
    }
    if (-not $pythonBase) {
        throw 'No all-users Python 3.12+ registered (HKLM\SOFTWARE\Python\PythonCore\3.12, 3.13 or 3.14). Install python.org Python 3.12 for all users (InstallAllUsers=1) or pass -PythonExe.'
    }
}
if ($pythonBase -like '*\WindowsApps\*') { throw 'The Microsoft Store Python cannot be used by services. Install python.org Python for all users.' }
if ($pythonBase -like (Join-Path $env:SystemDrive 'Users\*')) {
    throw "Python at $pythonBase is a per-user installation; the service account cannot read it. Reinstall python.org Python with 'Install for all users' (InstallAllUsers=1)."
}
# The venv runs the base interpreter, its DLLs and its standard library: whoever can plant files there
# (python3XX.dll, Lib\sitecustomize.py, site-packages\*.pth, python3XX._pth) runs code in the service, and whoever
# can delete or rename entries of the directory above can replace the whole installation.
$pyHome = Split-Path -Parent $pythonBase
$pyLib = Join-Path $pyHome 'Lib'
$pySite = Join-Path $pyLib 'site-packages'
$pyTree = @($pyHome, $pythonBase, $pyLib, (Join-Path $pyHome 'DLLs'), $pySite) +
    @(Get-ChildItem -LiteralPath $pyHome -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*.dll' -or $_.Name -like '*._pth' } | ForEach-Object { $_.FullName }) +
    @(foreach ($dir in @($pyLib, $pySite)) {
            Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*.pth' -or @('sitecustomize.py', 'usercustomize.py') -contains $_.Name } | ForEach-Object { $_.FullName }
        })
$pyWritable = @(Get-NonAdminWritable -Path $pyTree -Container @(Split-Path -Parent $pyHome))
if ($pyWritable.Count) {
    $pyMessage = "Python at $pythonBase can be modified by non-administrators: $($pyWritable -join '; '). Install python.org Python for all users into %ProgramFiles% (C:\Program Files\Python312, InstallAllUsers=1), whose ACL only lets administrators write"
    if (-not $AllowWritablePython) { throw "$pyMessage, or pass -AllowWritablePython to accept the risk." }
    Write-Note "$pyMessage. Continuing because of -AllowWritablePython."
}
# Every run of Python here uses isolated mode (-I: no PYTHON* variables, no user site-packages, neither the current
# directory nor the script directory on sys.path). The version probe also skips the site module (-S, no .pth files).
$pyVersion = ((Invoke-Native -FilePath $pythonBase -ArgumentList @('-I', '-S', '-c', 'import sys; print(sys.version_info[0], sys.version_info[1], sys.version_info[2], sep=chr(46))')).Output -join '').Trim()
if ([version]$pyVersion -lt [version]'3.12.0') { throw "Python $pyVersion at $pythonBase is too old; mitmproxy $MitmproxyVersion requires Python >= 3.12." }
Write-Step "Python $pyVersion at $pythonBase"

# Packages: by default the shipped lock file pins mitmproxy, YARA-X and every dependency by hash, binary wheels only (no
# source builds as Administrator). -RequirementsFile replaces it with your own lock; -AllowUnpinnedPackages resolves
# them from the package index without hashes.
$lockFile = $null
$lockArgs = @()
if ($RequirementsFile -and $AllowUnpinnedPackages) { throw '-RequirementsFile and -AllowUnpinnedPackages exclude each other.' }
if ($RequirementsFile) {
    if (-not (Test-Path -LiteralPath $RequirementsFile -PathType Leaf)) { throw "-RequirementsFile '$RequirementsFile' not found." }
    $lockFile = (Resolve-Path -LiteralPath $RequirementsFile).ProviderPath
}
elseif (-not $AllowUnpinnedPackages) {
    $lockFile = Join-Path $SourceDir 'requirements-lock.txt'
    if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
        throw "$lockFile is missing: the data-plane packages are installed hash-pinned from it. Pass your own lock with -RequirementsFile, or -AllowUnpinnedPackages to install them without hash pinning."
    }
    $lockArgs = @('--only-binary=:all:')
}
else {
    Write-Note 'Supply chain: -AllowUnpinnedPackages installs mitmproxy and its dependencies from the package index without hash pinning;'
    Write-Note 'a compromised index, mirror or proxy decides which code runs in the service. Prefer the shipped data-plane\requirements-lock.txt'
    Write-Note '(default) or -RequirementsFile <uv pip compile --generate-hashes --override requirements-security.txt output>.'
}

# Pre-existing directories: ProgramData (and the volume root for a custom path) lets every user create
# directories, so they may exist before the first installation, with a staged CA or control-plane CA bundle, a
# confdir\config.yaml (mitmdump options and scripts) or a prepared venv. Such content is only kept on an
# upgrade of an intact installation (service registered, directories owned by Administrators with the ACLs set
# below) or with -AdoptExistingSecrets. Links are refused: ACL changes and deletions would act on their targets
# (hard-linked files: on the file elsewhere). Protect-Directory checks again while it takes the directories over.
# The same holds for %ProgramData%\AegisProxy above the data root: whoever owns it (or may delete its entries) can
# rename the data root and put a junction in its place, so it is taken over too; any other parent of -DataRoot must
# already be controlled by administrators.
try {
    $links = @(Find-ReparsePoint @($InstallDir, $DataRoot))
    if ($OwnDataParent -and (Test-Path -LiteralPath $DataParent) -and ((Get-Item -LiteralPath $DataParent -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        $links += $DataParent
    }
    $parentIssues = @(Get-NonAdminWritable -Container @($DataParent))
    $trustIssues = @()
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { $trustIssues += "service $ServiceName is not installed (first installation)" }
    else { $trustIssues += @(Get-InstallationAclProblem -Principal @((Get-ServiceSid $ServiceName), $SidLocalService.TrimStart('*'))) }
    if ($parentIssues.Count) { $trustIssues += "parent directory not controlled by administrators: $($parentIssues -join '; ')" }
    $preExisting = @()
    if ($trustIssues.Count -and -not $links.Count) { $preExisting = @(Get-ExistingFile @($InstallDir, $ConfDir, $SecretsDir, $RuntimeDir, $SpoolDir)) }
}
catch { throw "Cannot inspect the existing installation directories ($($_.Exception.Message)). A directory that Administrators cannot read was not created by this script: remove it and re-run." }
if ($links.Count) { throw "Junctions/symbolic links and hard-linked files are not allowed in the installation directories: $($links -join ', '). Remove them and re-run." }
if ($parentIssues.Count -and -not $OwnDataParent) {
    throw "The parent directory of -DataRoot can be modified by non-administrators: $($parentIssues -join '; '). They could replace $DataRoot (rename it and put a junction in its place). Choose a -DataRoot whose parent only administrators control."
}
if ($preExisting.Count -and -not $AdoptExistingSecrets) {
    throw ("Refusing to adopt {0} file(s) that existed before this installation ({1}):`n  {2}`nA local user may have planted them. Delete them, or - if they are yours (interrupted first run, files you verified) - re-run with -AdoptExistingSecrets; the script then takes ownership and resets their ACLs." -f
        $preExisting.Count, ($trustIssues -join '; '), (($preExisting | Select-Object -First 10) -join "`n  "))
}
if ($preExisting.Count) { Write-Note "-AdoptExistingSecrets: keeping $($preExisting.Count) pre-existing file(s) ($($trustIssues -join '; '))." }

# =====================================================================================================
# Install / upgrade - changes
# =====================================================================================================
if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop service for upgrade')) { Stop-DataPlaneService }

if ($PSCmdlet.ShouldProcess($DataRoot, 'Create directories, take ownership and restrict ACL to SYSTEM/Administrators')) {
    # %ProgramData%\AegisProxy first, so that nobody can rename the data root while it is taken over. Only the
    # directory itself: a control-plane on this host keeps the ACLs of its subdirectories (it sets the same ACL here).
    if ($OwnDataParent) {
        if (-not (Test-Path -LiteralPath $DataParent)) { New-Item -ItemType Directory -Path $DataParent -Force | Out-Null }
        Protect-Directory -Root $DataParent -Grant @("${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F") -Allowed $AclAdmins
    }
    foreach ($dir in @($InstallDir, $AppDir, $DataRoot, $ConfDir, $SecretsDir, $LogsDir, $RuntimeDir, $SpoolDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
    # Administrators take ownership, foreign explicit ACEs are removed and everything below inherits from the
    # protected roots. Program files (venv, addon, WinSW): users read/execute only, also for a custom -InstallDir
    # outside %ProgramFiles% that would inherit "create files/folders" for users (DLL / module planting).
    $intact = -not $trustIssues.Count
    Protect-Directory -Root $InstallDir -Grant @("${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${SidUsers}:(OI)(CI)RX") -Allowed $AclProgram -AllChildren -Trusted:$intact
    Protect-Directory -Root $DataRoot -Grant @("${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F") -Allowed $AclAdmins -AllChildren -Trusted:$intact
    # Nobody else can add files from here on; files that appeared since the inspection above were planted meanwhile.
    if (-not $intact) {
        $planted = @(Get-ExistingFile @($InstallDir, $ConfDir, $SecretsDir, $RuntimeDir, $SpoolDir) | Where-Object { $preExisting -notcontains $_ })
        if ($planted.Count) {
            throw ("{0} file(s) appeared in the installation directories while this script ran:`n  {1}`nA local user may have planted them. Delete them and re-run." -f
                $planted.Count, (($planted | Select-Object -First 10) -join "`n  "))
        }
    }
    Write-Ok "Directories ready under $DataRoot (owner Administrators, foreign ACEs removed)"
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
    if ($recreate) { Remove-DirectoryTree $VenvDir }
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Write-Step "Creating virtual environment $VenvDir"
        Invoke-NativeLive -FilePath $pythonBase -ArgumentList @('-I', '-m', 'venv', $VenvDir)
    }
    $pipArgList = @('install', '--disable-pip-version-check', '--no-input', '--require-virtualenv')
    $pipReq = $lockFile
    if ($lockFile -and $NoYara -and -not $RequirementsFile) {
        # The shipped lock without the yara-x requirement and its hash lines, written to the admin-only program directory.
        $pipReq = Join-Path $InstallDir 'requirements-lock-noyara.txt'
        $skip = $false
        $kept = foreach ($line in [System.IO.File]::ReadAllLines($lockFile)) {
            if ($line -notmatch '^\s') { $skip = $line -match '^yara[-_]x\b' }
            if (-not $skip) { $line }
        }
        Write-TextNoBom -Path $pipReq -Value ((@($kept) -join "`n") + "`n")
    }
    if ($lockFile) {
        # A complete lock file pins every dependency; --no-deps lets it raise packages above mitmproxy's upper
        # bounds (security baseline). Completeness is checked with "pip check" below.
        $pipArgList += @('--require-hashes', '--no-deps') + $lockArgs + @('-r', $pipReq)
    }
    else {
        $pipArgList += "mitmproxy==$MitmproxyVersion"
        # YARA-X ships binary wheels for Windows x64; never fall back to a source build.
        if (-not $NoYara) { $pipArgList += @("yara-x==$YaraXVersion", '--only-binary', 'yara-x') }
    }
    if ($PipArgs) { $pipArgList += $PipArgs }
    Write-Step "pip $($pipArgList -join ' ')"
    try { Invoke-NativeLive -FilePath $VenvPython -ArgumentList (@('-I', '-m', 'pip') + $pipArgList) }
    finally { if ($pipReq -ne $lockFile) { Remove-Item -LiteralPath $pipReq -Force -ErrorAction SilentlyContinue } }
    # Security overrides for mitmproxy dependencies (mitmproxy's upper bound excludes the fixed release).
    $securityReq = Join-Path $SourceDir 'requirements-security.txt'
    if ((Test-Path -LiteralPath $securityReq) -and -not $lockFile) {
        $secArgs = @('-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--require-virtualenv', '--no-deps', '--only-binary=:all:', '-r', $securityReq)
        if ($PipArgs) { $secArgs += $PipArgs }
        Invoke-NativeLive -FilePath $VenvPython -ArgumentList $secArgs
    }
    elseif (Test-Path -LiteralPath $securityReq) {
        # Hash-pinned mode: an unhashed install on top would bypass --require-hashes, so only verify the pins. The
        # venv's Python compares the versions (PEP 440: pre-releases sort before the release, invalid versions fail).
        $baseline = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-c', $BaselineCheck, $securityReq) -SuccessCodes @(0, 1)
        if ($baseline.ExitCode -ne 0) {
            throw ("{0} does not meet the security baseline of data-plane\requirements-security.txt: {1}. Pin the fixed versions with their hashes in the requirements file." -f
                $lockFile, (@($baseline.Output | Where-Object { "$_".Trim() }) -join ' '))
        }
        # Every dependency must be in the lock file; the only tolerated conflicts are the baseline overrides
        # (names compared PEP 503-normalized).
        $overrides = @(foreach ($line in (Get-Content -LiteralPath $securityReq)) {
                if ($line -match '^\s*(?<name>[A-Za-z0-9._-]+)==') { ($Matches['name'] -replace '[-_.]+', '-').ToLowerInvariant() }
            })
        $pipCheck = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-m', 'pip', 'check') -SuccessCodes @(0, 1)
        $broken = @($pipCheck.Output | Where-Object {
                $_.Trim() -and $_ -notmatch '^No broken' -and
                -not ($_ -match 'but you have (?<pkg>\S+) ' -and $overrides -contains ($Matches['pkg'] -replace '[-_.]+', '-').ToLowerInvariant())
            })
        if ($broken.Count) {
            throw ("The hash-pinned requirements file is incomplete or inconsistent ({0}), pip check reports:`n  {1}" -f $lockFile, ($broken -join "`n  "))
        }
    }
    if (-not (Test-Path -LiteralPath $Mitmdump)) { throw "mitmdump.exe not found in the venv ($Mitmdump)." }
    # The addon needs these standard-library modules - fail now instead of at service start.
    $check = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-c', 'import http.server, hmac, gzip, ssl, asyncio, mitmproxy.version as v; print(v.VERSION)')
    $installed = ($check.Output -join '').Trim()
    if ($installed -ne $MitmproxyVersion) { Write-Note "Installed mitmproxy $installed (expected $MitmproxyVersion)." }
    Write-Ok "mitmproxy $installed installed in $VenvDir"
    $yaraCheck = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-c', 'import yara_x') -SuccessCodes @(0, 1)
    if ($yaraCheck.ExitCode -eq 0) { Write-Ok 'YARA-X available for YARA rule sets' }
    else { Write-Note 'YARA-X is not installed: YARA rule sets report "unavailable" on this worker.' }
}

# --- addon -------------------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($AppDir, 'Install AegisProxy addon')) {
    $null = Invoke-Native -FilePath 'robocopy.exe' -ArgumentList @((Join-Path $SourceDir 'aegis_dp'), (Join-Path $AppDir 'aegis_dp'),
        '/MIR', '/XJ', '/XD', '__pycache__', 'tests', '/XF', '*.pyc', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:2', '/W:2') -SuccessCodes @(0, 1, 2, 3, 4, 5, 6, 7)
    Copy-Item -LiteralPath (Join-Path $SourceDir 'aegis_addon.py') -Destination (Join-Path $AppDir 'aegis_addon.py') -Force
    $null = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-m', 'compileall', '-q', $AppDir)
    # Import test (does not instantiate the addon, so no configuration is needed).
    $null = Invoke-Native -FilePath $VenvPython -ArgumentList @('-I', '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import aegis_dp.addon', $AppDir)
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
if ($policyMaxAgeSeconds) { $extraEnv['AEGIS_POLICY_MAX_AGE'] = $PolicyMaxAge.ToLowerInvariant() }
$extraEnv['AEGIS_FLOW_SPOOL_DIR'] = $SpoolDir
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
    # -WinSWExe may have changed since the early check (it usually lives in a directory other users can write):
    # verify the copy inside the admin-only program directory, which is what the SCM will run.
    $stagedWrapper = "$WrapperExe.new"
    Copy-Item -LiteralPath $WinSWExe -Destination $stagedWrapper -Force
    $copiedHash = (Get-FileHash -LiteralPath $stagedWrapper -Algorithm SHA256).Hash
    if ($copiedHash -ne $WinSWSha256) {
        Remove-Item -LiteralPath $stagedWrapper -Force
        throw "SHA-256 of the copied wrapper is $copiedHash, expected $($WinSWSha256.ToUpperInvariant()): $WinSWExe changed after it was verified. Keep the verified WinSW copy in a directory only administrators can write."
    }
    Remove-DataPlaneService      # WinSW applies service-level settings at install time -> reinstall on every run
    if (Test-Path -LiteralPath $WrapperExe) { Remove-Item -LiteralPath $WrapperExe -Force }
    Move-Item -LiteralPath $stagedWrapper -Destination $WrapperExe
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
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($InstallDir, '/grant:r', "${AclPrincipal}:(OI)(CI)RX", '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($ConfDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${AclPrincipal}:(OI)(CI)M", '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($SecretsDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${AclPrincipal}:(OI)(CI)R", '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($LogsDir, '/grant:r', "${AclPrincipal}:(OI)(CI)M", '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($RuntimeDir, '/grant:r', "${AclPrincipal}:(OI)(CI)M", '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($SpoolDir, '/grant:r', "${AclPrincipal}:(OI)(CI)M", '/L', '/Q')
    # Read the result back: only SYSTEM, Administrators, the service (and users: read program files) may have access.
    $aclProblems = @(Get-InstallationAclProblem -Principal @($AclSid) -IncludeLogs)
    if ($OwnDataParent) { $aclProblems += @(Get-AclProblem -Path $DataParent -Allowed $AclAdmins) }
    if ($aclProblems.Count) {
        throw ("ACL verification failed - the service was not started:`n  {0}" -f ($aclProblems -join "`n  "))
    }
    Write-Ok 'ACLs verified: program files = read, confdir/logs/flow-spool = modify, secrets = read (no inheritance); everything else SYSTEM/Administrators only.'
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
