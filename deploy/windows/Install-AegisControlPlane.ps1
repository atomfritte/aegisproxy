#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs, upgrades or removes the AegisProxy control-plane as a native Windows service.

.DESCRIPTION
    The control-plane binary (aegis-control-plane.exe) implements the Service Control Manager protocol
    itself (service name "AegisControlPlane"), so no service wrapper is needed. The service is registered as
    "<InstallDir>\aegis-control-plane.exe" service - the argument selects the SCM dispatcher explicitly; started
    without it, the binary runs in the foreground (troubleshooting).

    What the script does (idempotent - a re-run upgrades the binary and keeps all secrets/state):
      * copies the binary (and optionally the built web console) to -InstallDir
      * creates <DataRoot>\data, \certs, \secrets, \logs with restrictive ACLs; existing directories are taken
        over (owner Administrators, foreign ACEs removed) and the result is verified. Files that existed
        before are only kept on an upgrade of an intact installation or with -AdoptExistingSecrets
      * generates missing secrets (32 random bytes, hex) into <DataRoot>\secrets and passes them to the
        service exclusively as AEGIS_*_FILE paths (the service environment in the registry is readable
        by local users, secret values never go there)
      * provisions the enterprise root CA with "aegis-control-plane gen-ca" if none exists; the CA private
        key (mitmproxy-ca.pem) is readable by SYSTEM/Administrators only - the control-plane only needs
        the public certificate, the data-plane receives its own copy of the key
      * registers the service (Automatic, image path "<exe>" service; older registrations without the argument
        are updated), runs it as the virtual account NT SERVICE\AegisControlPlane,
        restricts its privileges, configures recovery (restart on failure) and the service environment
      * registers the Application event log source "AegisControlPlane" (fatal start/termination errors -
        under the SCM there is no console)
      * opens the listener port in Windows Firewall, registers a daily log rotation task that runs as the
        service's virtual account
      * starts the service and waits for /healthz

    Data layout:
      <InstallDir>\aegis-control-plane.exe     binary            (Program Files ACL, read-only for users)
      <InstallDir>\ui\                          web console       (optional, -UiDir)
      <DataRoot>\data\                          aegis_state.json(.bak), audit.jsonl, threat-intel cache
      <DataRoot>\certs\                         enterprise root CA (public certs; key restricted)
      <DataRoot>\secrets\                       jwt.key, dataplane.key, encryption.key, database-url, tls-*.pem, ...
      <DataRoot>\logs\control-plane.log         AEGIS_LOG_FILE (stdout is discarded by the SCM)

.PARAMETER BinaryPath
    Path to aegis-control-plane.exe (GOOS=windows GOARCH=amd64 build). Default: next to this script.
    On a re-run without a new binary the installed one is kept.

.PARAMETER PublicUrl
    AEGIS_PUBLIC_URL - externally reachable base URL (https:// in production).

.PARAMETER ProxyAddress
    AEGIS_PROXY_ADDRESS - host:port that servers use as their HTTP(S) proxy (shown in onboarding
    snippets). Default: host of PublicUrl with port 8080.

.PARAMETER UiDir
    Optional path to the built console (frontend\dist). Copied to <InstallDir>\ui and served by the
    control-plane (AEGIS_UI_DIR). Omit when the console is hosted separately (IIS, see iis\).

.PARAMETER Storage
    file (single node, default) or postgres (active-active cluster, requires -DatabaseUrl once).

.PARAMETER DatabaseUrl
    PostgreSQL DSN, written to <DataRoot>\secrets\database-url (AEGIS_DATABASE_URL_FILE). Prefer
    entering it interactively (Read-Host) instead of putting it into the shell history.

.PARAMETER TlsCertFile
    PEM certificate (chain) for native HTTPS. Copied to <DataRoot>\secrets\tls-cert.pem.

.PARAMETER TlsKeyFile
    Unencrypted PEM private key (PKCS#1/PKCS#8/EC). Copied to <DataRoot>\secrets\tls-key.pem.

.PARAMETER BootstrapAdminPassword
    Optional password for the bootstrap super admin "admin" (min. 12 characters). Without it the
    control-plane writes a random password to <DataRoot>\data\secrets\initial-admin-password.

.PARAMETER ImportSecretsDir
    Cluster nodes 2..n: directory containing jwt.key, dataplane.key and encryption.key of the first node. All
    control-plane replicas must use identical secrets. An SMB path (UNC or mapped drive) must use an encrypted
    connection (New-SmbMapping -RequirePrivacy $true or a share with EncryptData), see -AllowUnencryptedImport.

.PARAMETER CaSourceDir
    Cluster nodes 2..n: certs directory of the first node (the CA must be identical cluster-wide). Contains the
    CA private key: the same SMB encryption requirement applies.

.PARAMETER AllowUnencryptedImport
    Accept -ImportSecretsDir / -CaSourceDir on an SMB connection that is not encrypted (secrets and the CA key
    then cross the network in clear text).

.PARAMETER AdoptExistingSecrets
    Keep secrets, CA, state and program files that existed before this run although no intact installation
    vouches for them (first installation: no service registered, or directories whose owner/ACL differ from
    what this script sets). Use it after restoring a backup on a new host, when reinstalling after -Uninstall,
    or after an interrupted first run - not for files of unknown origin, a local user may have planted them.

.PARAMETER Force
    Allow replacing an existing, different CA or secrets with -CaSourceDir / -ImportSecretsDir.

.PARAMETER Uninstall
    Removes the service, the event log source, the firewall rule, the log rotation task and the binaries.
    All data, secrets and the CA under -DataRoot are kept.

.EXAMPLE
    .\Install-AegisControlPlane.ps1 -BinaryPath .\aegis-control-plane.exe `
        -PublicUrl https://aegis.corp.example:8081 -UiDir ..\..\frontend\dist `
        -TlsCertFile C:\pki\aegis.crt.pem -TlsKeyFile C:\pki\aegis.key.pem

.EXAMPLE
    # Cluster node 2 (PostgreSQL storage, secrets + CA from node 1 over an encrypted SMB connection)
    New-SmbMapping -RemotePath '\\node1\c$' -RequirePrivacy $true | Out-Null
    $dsn = Read-Host 'PostgreSQL DSN'
    .\Install-AegisControlPlane.ps1 -PublicUrl https://aegis.corp.example -Storage postgres -DatabaseUrl $dsn `
        -ImportSecretsDir \\node1\c$\ProgramData\AegisProxy\secrets -CaSourceDir \\node1\c$\ProgramData\AegisProxy\certs `
        -TrustedProxies 10.10.0.10/32,10.10.0.11/32
    Remove-SmbMapping -RemotePath '\\node1\c$' -Force

.EXAMPLE
    .\Install-AegisControlPlane.ps1 -Uninstall

.NOTES
    Requires Windows Server 2016+ / Windows PowerShell 5.1 or PowerShell 7. Run elevated.
    Reference for all variables: docs/configuration.md. Operations guide: docs/deployment/windows.md.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'aegis-control-plane.exe'),

    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AegisProxy\control-plane'),

    [string]$DataRoot = (Join-Path $env:ProgramData 'AegisProxy'),

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [ValidatePattern('^https?://[^\s/?#]+')]
    [string]$PublicUrl,

    [Parameter(ParameterSetName = 'Install')]
    [string]$UiDir,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('file', 'postgres')]
    [string]$Storage = 'file',

    [Parameter(ParameterSetName = 'Install')]
    [string]$DatabaseUrl,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int]$Port = 8081,

    # Optional AEGIS_LISTEN_ADDR, e.g. 127.0.0.1:8081 when only a local reverse proxy (IIS/ARR) may connect.
    [Parameter(ParameterSetName = 'Install')]
    [string]$ListenAddress,

    [Parameter(ParameterSetName = 'Install')]
    [string]$TlsCertFile,

    [Parameter(ParameterSetName = 'Install')]
    [string]$TlsKeyFile,

    [Parameter(ParameterSetName = 'Install')]
    [System.Security.SecureString]$BootstrapAdminPassword,

    [Parameter(ParameterSetName = 'Install')]
    [string]$DashboardUrl,

    [Parameter(ParameterSetName = 'Install')]
    [string]$ProxyAddress,

    # AEGIS_TRUSTED_PROXIES: CIDRs of reverse proxies / load balancers.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$TrustedProxies,

    # AEGIS_CORS_ORIGINS: origins of a separately hosted console.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$CorsOrigins,

    [Parameter(ParameterSetName = 'Install')]
    [string]$ImportSecretsDir,

    [Parameter(ParameterSetName = 'Install')]
    [string]$CaSourceDir,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowUnencryptedImport,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AdoptExistingSecrets,

    # Creates secrets\metrics.token and protects /metrics with it (AEGIS_METRICS_TOKEN_FILE).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$GenerateMetricsToken,

    # Additional non-secret variables, e.g. @{ AEGIS_INTERNAL_DOMAINS = '.corp.example,.local' }.
    [Parameter(ParameterSetName = 'Install')]
    [hashtable]$ExtraEnvironment,

    [Parameter(ParameterSetName = 'Install')]
    [string[]]$FirewallRemoteAddress = @('Any'),

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('Domain', 'Private', 'Public', 'Any')]
    [string[]]$FirewallProfile = @('Domain'),

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipFirewall,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 3650)]
    [int]$LogRetentionDays = 30,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipLogRotationTask,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(10, 600)]
    [int]$HealthTimeoutSeconds = 90,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$Force,

    [Parameter(Mandatory = $true, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- constants ---------------------------------------------------------------------------------------
$ServiceName     = 'AegisControlPlane'          # fixed: compiled into the binary (service_windows.go)
$ServiceAccount  = "NT SERVICE\$ServiceName"   # virtual account, no password management
$DisplayName     = 'AegisProxy Control-Plane'
$Description     = 'AegisProxy policy, threat-intelligence and audit control-plane (API + web console).'
$ExeName         = 'aegis-control-plane.exe'
$FirewallRule    = 'AegisProxy-ControlPlane-In'
$TaskName        = 'AegisProxy Control-Plane Log Rotation'
$TaskPath        = '\AegisProxy\'
$SidSystem       = '*S-1-5-18'                 # NT AUTHORITY\SYSTEM (locale independent)
$SidAdmins       = '*S-1-5-32-544'             # BUILTIN\Administrators
$SidUsers        = '*S-1-5-32-545'             # BUILTIN\Users
$PlainSecretVars = @('AEGIS_JWT_SECRET', 'AEGIS_DATAPLANE_KEY', 'AEGIS_BOOTSTRAP_ADMIN_PASSWORD',
                     'AEGIS_METRICS_TOKEN', 'AEGIS_DATABASE_URL', 'AEGIS_ENCRYPTION_KEY', 'AEGIS_ENCRYPTION_KEY_PREVIOUS')

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$DataRoot   = [System.IO.Path]::GetFullPath($DataRoot)
$ExePath    = Join-Path $InstallDir $ExeName
$UiTarget   = Join-Path $InstallDir 'ui'
$DataDir    = Join-Path $DataRoot 'data'
$CertsDir   = Join-Path $DataRoot 'certs'
$SecretsDir = Join-Path $DataRoot 'secrets'
$LogsDir    = Join-Path $DataRoot 'logs'
$LogFile    = Join-Path $LogsDir 'control-plane.log'
$caKey      = Join-Path $CertsDir 'mitmproxy-ca.pem'
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
# Same registration as Go's eventlog.InstallAsEventCreate (service_windows.go logs under this source).
$EventLogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"

# --- helpers -----------------------------------------------------------------------------------------
function Write-Step([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Note([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

function Invoke-Native {
    # Runs a native command, returns its output as strings and throws on a non-zero exit code.
    # (Windows PowerShell 5.1 turns redirected stderr into terminating errors under 'Stop'.)
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @(), [int[]]$SuccessCodes = @(0))
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    if ($SuccessCodes -notcontains $code) {
        throw ("'{0} {1}' failed with exit code {2}:`n{3}" -f $FilePath, ($ArgumentList -join ' '), $code, ($output -join "`n"))
    }
    return $output
}

function Get-RandomHex([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return (($buffer | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Write-SecretFile([string]$Path, [string]$Value) {
    # UTF-8 without BOM: a BOM would become part of the secret (Go strings.TrimSpace keeps U+FEFF).
    [System.IO.File]::WriteAllText($Path, $Value + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Read-SecretFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return ([System.IO.File]::ReadAllText($Path)).Trim([char[]]@([char]0xFEFF, ' ', "`t", "`r", "`n"))
}

function ConvertFrom-SecureStringPlain([System.Security.SecureString]$Secure) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-CaInfo([string]$Dir) {
    $der = Join-Path $Dir 'aegis-enterprise-ca.der'
    $pem = Join-Path $Dir 'mitmproxy-ca-cert.pem'
    $path = $null
    if (Test-Path -LiteralPath $der) { $path = $der } elseif (Test-Path -LiteralPath $pem) { $path = $pem }
    if (-not $path) { return $null }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $path
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($cert.RawData) } finally { $sha.Dispose() }
    return [pscustomobject]@{
        Subject     = $cert.Subject
        NotAfter    = $cert.NotAfter
        Fingerprint = ([System.BitConverter]::ToString($hash)).Replace('-', ':')
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

function Stop-AegisService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Step "Stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force
        if (-not (Wait-ServiceState -Name $ServiceName -State 'Stopped' -TimeoutSeconds 60)) {
            throw "Service $ServiceName did not stop within 60 seconds."
        }
    }
}

function Copy-WithRetry([string]$Source, [string]$Destination) {
    for ($i = 1; $i -le 10; $i++) {
        try { Copy-Item -LiteralPath $Source -Destination $Destination -Force; return }
        catch { if ($i -eq 10) { throw }; Start-Sleep -Seconds 1 }   # binary may still be locked briefly
    }
}

function Assert-NoControlChar([string]$Name, [string]$Value) {
    if ($Value -match '[\x00-\x1f]') { throw "$Name contains control characters." }
}

function Show-LogTail {
    if (Test-Path -LiteralPath $LogFile) {
        Write-Note "Last lines of ${LogFile}:"
        Get-Content -LiteralPath $LogFile -Tail 25 | ForEach-Object { Write-Host "    $_" }
    }
    else {
        Write-Note "No log file yet. Configuration errors that occur before logging starts are not visible under the SCM;"
        Write-Note "run & '$ExePath' (without the 'service' argument, in the foreground) in an elevated console with the service environment to see them (docs/deployment/windows.md, Troubleshooting)."
    }
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 20 -ErrorAction Stop |
            Where-Object { $_.Message -match 'AegisProxy|AegisControlPlane' } |
            Select-Object -First 5 | ForEach-Object { Write-Host ("    [SCM {0:HH:mm:ss}] {1}" -f $_.TimeCreated, $_.Message) }
    }
    catch { Write-Verbose "No matching SCM events: $_" }
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
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/setowner', $SidAdmins, '/L', '/Q') | Out-Null
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList (@($Root, '/inheritance:r', '/grant:r') + $Grant + @('/L', '/Q')) | Out-Null
    $foreign = @((Get-Acl -LiteralPath $Root).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
            ForEach-Object { "$($_.IdentityReference.Value)" } | Where-Object { -not $Allowed.ContainsKey($_) } | Sort-Object -Unique)
    foreach ($sid in $foreign) { Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/remove', "*$sid", '/L', '/Q') | Out-Null }
    Assert-PlainItem (Get-Item -LiteralPath $Root -Force)
    if ($AllChildren) { $Children = @(Get-ChildItem -LiteralPath $Root -Force | ForEach-Object { $_.FullName }) }
    if ($Trusted) {
        foreach ($child in $Children) {
            if (-not (Test-Path -LiteralPath $child)) { continue }
            Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($child, '/setowner', $SidAdmins, '/T', '/L', '/C', '/Q') | Out-Null
            Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($child, '/reset', '/T', '/L', '/C', '/Q') | Out-Null
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
        Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/setowner', $SidAdmins, '/L', '/Q') | Out-Null
        Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/reset', '/L', '/Q') | Out-Null
        Assert-PlainItem (Get-Item -LiteralPath $path -Force)
        if ($item.PSIsContainer) { foreach ($child in @(Get-ChildItem -LiteralPath $path -Force)) { $pending.Push($child.FullName) } }
    }
}

function Test-ReparsePoint([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return [bool]($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
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

function Get-InstallationAclProblem([switch]$IncludeLogs) {
    # Deviations of the program and data directories (and the secrets, CA key, binary) from the ACLs this script sets.
    $checks = [ordered]@{}
    $checks[$InstallDir] = $AclProgram
    $checks[$ExePath]    = $AclProgram
    $checks[$DataRoot]   = $AclAdmins
    $checks[$DataDir]    = $AclAdmins + @{ $ServiceSid = 'M' }
    $checks[$CertsDir]   = $AclAdmins + @{ $ServiceSid = 'RX' }
    $checks[$caKey]      = $AclAdmins
    $checks[$SecretsDir] = $AclAdmins + @{ $ServiceSid = 'R' }
    if (Test-Path -LiteralPath $SecretsDir) {
        foreach ($file in @(Get-ChildItem -LiteralPath $SecretsDir -Force -File)) { $checks[$file.FullName] = $checks[$SecretsDir] }
    }
    if ($IncludeLogs) { $checks[$LogsDir] = $AclAdmins + @{ $ServiceSid = 'M' } }
    $problems = @()
    foreach ($path in $checks.Keys) { if (Test-Path -LiteralPath $path) { $problems += @(Get-AclProblem -Path $path -Allowed $checks[$path]) } }
    return $problems
}

# Expected ACLs (SID -> maximum rights) and the FileSystemRights masks of the icacls grants F, M, RX and R.
$ServiceSid = Get-ServiceSid $ServiceName
$AclRights  = @{ F = 2032127; M = 1245631; RX = 1179817; R = 1179785 }
$AclAdmins  = @{ 'S-1-5-18' = 'F'; 'S-1-5-32-544' = 'F' }
$AclProgram = $AclAdmins + @{ 'S-1-5-32-545' = 'RX'; $ServiceSid = 'RX' }

# =====================================================================================================
# Uninstall
# =====================================================================================================
if ($PSCmdlet.ParameterSetName -eq 'Uninstall') {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop and delete service')) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-AegisService
            Invoke-Native -FilePath 'sc.exe' -ArgumentList @('delete', $ServiceName) | Out-Null
            if (-not (Wait-ServiceState -Name $ServiceName -State 'Deleted' -TimeoutSeconds 30)) {
                Write-Note "Service is marked for deletion; it disappears once all handles (services.msc, Event Viewer) are closed."
            }
            Write-Ok "Service $ServiceName removed."
        }
        else { Write-Note "Service $ServiceName is not installed." }
    }
    if ($PSCmdlet.ShouldProcess($FirewallRule, 'Remove firewall rule')) {
        Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    if ((Test-Path -LiteralPath $EventLogKey) -and $PSCmdlet.ShouldProcess($EventLogKey, 'Remove event log source')) {
        Remove-Item -LiteralPath $EventLogKey -Recurse -Force
    }
    if ($PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
        Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false
    }
    if ((Test-Path -LiteralPath $ExePath) -and $PSCmdlet.ShouldProcess($InstallDir, 'Remove program files')) {
        Remove-DirectoryTree $InstallDir
    }
    Write-Ok 'AegisProxy control-plane uninstalled.'
    Write-Note "Data, secrets and the enterprise root CA were KEPT in $DataRoot (state, audit.jsonl, certs, secrets)."
    Write-Note 'A later installation on this host keeps them only with -AdoptExistingSecrets (without a service they are treated as pre-existing files).'
    Write-Note "Back them up before purging; to remove everything: Remove-Item -LiteralPath '$DataRoot' -Recurse -Force"
    Write-Note "If a data-plane is installed on this host, it still uses its own copy of the CA and key."
    return
}

# =====================================================================================================
# Install / upgrade
# =====================================================================================================
# Settings of a previous installation are kept when the corresponding parameter is not passed again,
# so that a plain re-run (binary upgrade) never silently changes e.g. the storage mode.
$ManagedKeys = @('CONTROL_PLANE_PORT', 'AEGIS_LISTEN_ADDR', 'AEGIS_PUBLIC_URL', 'AEGIS_DASHBOARD_URL', 'AEGIS_PROXY_ADDRESS', 'DATA_DIR',
    'CERTS_DIR', 'AEGIS_STORAGE', 'AEGIS_DATABASE_URL_FILE', 'AEGIS_JWT_SECRET_FILE', 'AEGIS_DATAPLANE_KEY_FILE', 'AEGIS_ENCRYPTION_KEY_FILE',
    'AEGIS_BOOTSTRAP_ADMIN_PASSWORD_FILE', 'AEGIS_METRICS_TOKEN_FILE', 'AEGIS_TLS_CERT_FILE', 'AEGIS_TLS_KEY_FILE',
    'AEGIS_UI_DIR', 'AEGIS_TRUSTED_PROXIES', 'AEGIS_CORS_ORIGINS', 'AEGIS_LOG_FILE', 'AEGIS_LOG_FORMAT', 'AEGIS_DEMO_MODE')
$previousEnv = [ordered]@{}
$prevProp = Get-ItemProperty -Path $ServiceKey -Name 'Environment' -ErrorAction SilentlyContinue
if ($prevProp) {
    foreach ($line in @($prevProp.Environment)) {
        $pair = "$line" -split '=', 2
        if ($pair.Count -eq 2) { $previousEnv[$pair[0]] = $pair[1] }
    }
}
$bound = $PSBoundParameters
if (-not $bound.ContainsKey('Storage') -and $previousEnv.Contains('AEGIS_STORAGE')) { $Storage = $previousEnv['AEGIS_STORAGE'] }
if (-not $bound.ContainsKey('Port') -and $previousEnv.Contains('CONTROL_PLANE_PORT')) { $Port = [int]$previousEnv['CONTROL_PLANE_PORT'] }
if (-not $bound.ContainsKey('ListenAddress') -and $previousEnv.Contains('AEGIS_LISTEN_ADDR')) { $ListenAddress = $previousEnv['AEGIS_LISTEN_ADDR'] }
if (-not $bound.ContainsKey('DashboardUrl') -and $previousEnv.Contains('AEGIS_DASHBOARD_URL')) { $DashboardUrl = $previousEnv['AEGIS_DASHBOARD_URL'] }
if (-not $bound.ContainsKey('ProxyAddress') -and $previousEnv.Contains('AEGIS_PROXY_ADDRESS')) { $ProxyAddress = $previousEnv['AEGIS_PROXY_ADDRESS'] }
if (-not $bound.ContainsKey('TrustedProxies') -and $previousEnv.Contains('AEGIS_TRUSTED_PROXIES')) { $TrustedProxies = @($previousEnv['AEGIS_TRUSTED_PROXIES']) }
if (-not $bound.ContainsKey('CorsOrigins') -and $previousEnv.Contains('AEGIS_CORS_ORIGINS')) { $CorsOrigins = @($previousEnv['AEGIS_CORS_ORIGINS']) }

$PublicUrl = $PublicUrl.TrimEnd('/')
Assert-NoControlChar 'PublicUrl' $PublicUrl
if ($PublicUrl -notmatch '^https://') {
    Write-Note 'AEGIS_PUBLIC_URL is http:// - session cookies are not Secure. Use https:// in production.'
}
if ([bool]$TlsCertFile -ne [bool]$TlsKeyFile) { throw '-TlsCertFile and -TlsKeyFile must be given together.' }
if ($ImportSecretsDir) { Assert-EncryptedSmbSource -Name '-ImportSecretsDir' -Path $ImportSecretsDir -AllowUnencrypted:$AllowUnencryptedImport }
if ($CaSourceDir) { Assert-EncryptedSmbSource -Name '-CaSourceDir' -Path $CaSourceDir -AllowUnencrypted:$AllowUnencryptedImport }
if ($Storage -eq 'postgres' -and -not $DatabaseUrl -and -not (Test-Path -LiteralPath (Join-Path $SecretsDir 'database-url'))) {
    throw '-Storage postgres requires -DatabaseUrl on the first installation.'
}
if ($ExtraEnvironment) {
    foreach ($key in $ExtraEnvironment.Keys) {
        if ($key -notmatch '^[A-Z_][A-Z0-9_]*$') { throw "Invalid environment variable name '$key'." }
        if ($PlainSecretVars -contains $key) {
            throw "$key must not be passed as plain value (the service environment is readable by local users). Use the generated *_FILE secrets."
        }
        Assert-NoControlChar $key ([string]$ExtraEnvironment[$key])
    }
}

# --- binary ------------------------------------------------------------------------------------------
$newBinary = $null
if ($BinaryPath -and (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    $newBinary = (Resolve-Path -LiteralPath $BinaryPath).ProviderPath
    $fs = [System.IO.File]::OpenRead($newBinary)
    try { $magic = New-Object byte[] 2; [void]$fs.Read($magic, 0, 2) } finally { $fs.Dispose() }
    if ($magic[0] -ne 0x4D -or $magic[1] -ne 0x5A) {
        throw "$newBinary is not a Windows executable. Build it with: GOOS=windows GOARCH=amd64 go build -o aegis-control-plane.exe ."
    }
    # Bounded call: outdated builds without the "version" subcommand would start a server instead of exiting.
    $versionOut = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $newBinary -ArgumentList 'version' -NoNewWindow -PassThru -RedirectStandardOutput $versionOut
        if (-not $proc.WaitForExit(15000)) {
            $proc.Kill()
            throw "$newBinary did not answer 'version' - outdated build without the version/gen-ca/healthcheck subcommands?"
        }
        if ($proc.ExitCode -ne 0) { throw "$newBinary version failed with exit code $($proc.ExitCode)." }
        $newVersion = ([System.IO.File]::ReadAllText($versionOut)).Trim()
    }
    finally { Remove-Item -LiteralPath $versionOut -Force -ErrorAction SilentlyContinue -WhatIf:$false }
    Write-Step "Binary to install: $newBinary (version $newVersion)"
}
elseif (Test-Path -LiteralPath $ExePath) {
    Write-Note "No binary at '$BinaryPath' - keeping the installed one ($ExePath)."
}
else {
    throw "Binary not found: '$BinaryPath'. Pass -BinaryPath <path to aegis-control-plane.exe>."
}

if ($UiDir) {
    $UiDir = (Resolve-Path -LiteralPath $UiDir).ProviderPath
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'index.html'))) {
        throw "$UiDir does not contain index.html - build the console first (npm --prefix frontend run build)."
    }
}

# --- pre-existing directories ------------------------------------------------------------------------
# ProgramData (and the volume root for a custom path) lets every user create directories, so the directories
# may exist before the first installation - created by a local user with a known jwt.key/encryption.key, a CA
# whose key they hold or a state file with their admin account. Such content is only kept on an upgrade of an
# intact installation (service registered, directories owned by Administrators with the ACLs set below) or
# with -AdoptExistingSecrets. Links are refused: ACL changes and deletions would act on their targets (hard-linked
# files: on the file elsewhere). Protect-Directory checks again while it takes the directories over.
try {
    $links = @(Find-ReparsePoint @($InstallDir, $DataDir, $CertsDir, $SecretsDir, $LogsDir))
    if (Test-ReparsePoint $DataRoot) { $links += $DataRoot }
    $trustIssues = @()
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { $trustIssues += "service $ServiceName is not installed (first installation)" }
    else { $trustIssues += @(Get-InstallationAclProblem) }
    $preExisting = @()
    if ($trustIssues.Count -and -not $links.Count) { $preExisting = @(Get-ExistingFile @($InstallDir, $DataDir, $CertsDir, $SecretsDir)) }
}
catch { throw "Cannot inspect the existing installation directories ($($_.Exception.Message)). A directory that Administrators cannot read was not created by this script: remove it and re-run." }
if ($links.Count) { throw "Junctions/symbolic links and hard-linked files are not allowed in the installation directories: $($links -join ', '). Remove them and re-run." }
if ($preExisting.Count -and -not $AdoptExistingSecrets) {
    throw ("Refusing to adopt {0} file(s) that existed before this installation ({1}):`n  {2}`nA local user may have planted them (known keys, CA or admin account). Delete them, or - if they are yours (restored backup, reinstallation after -Uninstall, interrupted first run) - re-run with -AdoptExistingSecrets; the script then takes ownership and resets their ACLs." -f
        $preExisting.Count, ($trustIssues -join '; '), (($preExisting | Select-Object -First 10) -join "`n  "))
}
if ($preExisting.Count) { Write-Note "-AdoptExistingSecrets: keeping $($preExisting.Count) pre-existing file(s) ($($trustIssues -join '; '))." }

# --- stop running instance before touching files -----------------------------------------------------
if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop service for upgrade')) { Stop-AegisService }

# --- directories + base ACL --------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($DataRoot, 'Create directories, take ownership and restrict ACL to SYSTEM/Administrators')) {
    foreach ($dir in @($InstallDir, $DataRoot, $DataDir, $CertsDir, $SecretsDir, $LogsDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
    # Administrators take ownership, foreign explicit ACEs are removed and everything below inherits from the
    # protected roots. A custom -InstallDir outside %ProgramFiles% inherits "create files/folders" for users from
    # the volume root; the binary and the log rotation script must not be replaceable by them.
    $intact = -not $trustIssues.Count
    Protect-Directory -Root $InstallDir -Grant @("${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", "${SidUsers}:(OI)(CI)RX") -Allowed $AclProgram -AllChildren -Trusted:$intact
    # Only the directories of this script are reset below the data root (a data-plane on this host keeps its subtree).
    Protect-Directory -Root $DataRoot -Grant @("${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F") -Allowed $AclAdmins `
        -Children @($DataDir, $CertsDir, $SecretsDir, $LogsDir) -Trusted:$intact
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($SecretsDir, '/inheritance:r', '/grant:r',
        "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F", '/L', '/Q') | Out-Null
    # Nobody else can add files from here on; files that appeared since the inspection above were planted meanwhile
    # (a jwt.key or encryption.key written now would be kept instead of generated).
    if (-not $intact) {
        $planted = @(Get-ExistingFile @($InstallDir, $DataDir, $CertsDir, $SecretsDir) | Where-Object { $preExisting -notcontains $_ })
        if ($planted.Count) {
            throw ("{0} file(s) appeared in the installation directories while this script ran:`n  {1}`nA local user may have planted them. Delete them and re-run." -f
                $planted.Count, (($planted | Select-Object -First 10) -join "`n  "))
        }
    }
    Write-Ok "Directories ready under $DataRoot (owner Administrators, foreign ACEs removed)"
}

# --- program files -----------------------------------------------------------------------------------
if ($newBinary -and $PSCmdlet.ShouldProcess($ExePath, 'Install binary')) {
    Copy-WithRetry -Source $newBinary -Destination $ExePath
    Write-Ok "Installed $ExePath"
}
if ($UiDir -and $PSCmdlet.ShouldProcess($UiTarget, 'Install web console')) {
    $null = Invoke-Native -FilePath 'robocopy.exe' -ArgumentList @($UiDir, $UiTarget, '/MIR', '/XJ', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:2', '/W:2') -SuccessCodes @(0, 1, 2, 3, 4, 5, 6, 7)
    Write-Ok "Web console copied to $UiTarget"
}

# --- secrets -----------------------------------------------------------------------------------------
$jwtFile       = Join-Path $SecretsDir 'jwt.key'
$dpKeyFile     = Join-Path $SecretsDir 'dataplane.key'
$encKeyFile    = Join-Path $SecretsDir 'encryption.key'
$dbUrlFile     = Join-Path $SecretsDir 'database-url'
$bootstrapFile = Join-Path $SecretsDir 'bootstrap-admin-password'
$metricsFile   = Join-Path $SecretsDir 'metrics.token'
$tlsCertTarget = Join-Path $SecretsDir 'tls-cert.pem'
$tlsKeyTarget  = Join-Path $SecretsDir 'tls-key.pem'

if ($PSCmdlet.ShouldProcess($SecretsDir, 'Import/generate secrets')) {
    if ($ImportSecretsDir) {
        foreach ($name in @('jwt.key', 'dataplane.key', 'encryption.key')) {
            $src = Join-Path $ImportSecretsDir $name
            $value = Read-SecretFile $src
            if (-not $value -or $value.Length -lt 32) { throw "$src is missing or shorter than 32 characters." }
            $dst = Join-Path $SecretsDir $name
            $existing = Read-SecretFile $dst
            if ($existing -and $existing -ne $value -and -not $Force) {
                throw "$dst exists with a different value. Re-run with -Force to replace it (invalidates sessions / data-plane trust)."
            }
            Write-SecretFile -Path $dst -Value $value
        }
        Write-Ok "Imported jwt.key, dataplane.key and encryption.key from $ImportSecretsDir"
    }
    foreach ($file in @($jwtFile, $dpKeyFile, $encKeyFile)) {
        $value = Read-SecretFile $file
        if (-not $value -or $value.Length -lt 32) {
            Write-SecretFile -Path $file -Value (Get-RandomHex 32)
            Write-Ok "Generated $file"
        }
    }
    if ($GenerateMetricsToken -and -not (Read-SecretFile $metricsFile)) {
        Write-SecretFile -Path $metricsFile -Value (Get-RandomHex 32)
        Write-Ok "Generated $metricsFile (Prometheus: bearer_token_file)"
    }
    if ($DatabaseUrl) {
        Assert-NoControlChar 'DatabaseUrl' $DatabaseUrl
        if ($DatabaseUrl -notmatch '^postgres(ql)?://') { throw '-DatabaseUrl must start with postgres:// or postgresql://' }
        Write-SecretFile -Path $dbUrlFile -Value $DatabaseUrl
        Write-Ok "Stored database DSN in $dbUrlFile"
    }
    if ($BootstrapAdminPassword) {
        $plain = ConvertFrom-SecureStringPlain $BootstrapAdminPassword
        try {
            if ($plain.Length -lt 12) { throw 'BootstrapAdminPassword must have at least 12 characters.' }
            Write-SecretFile -Path $bootstrapFile -Value $plain
        }
        finally { $plain = $null }
        Write-Ok "Stored bootstrap admin password in $bootstrapFile (delete it after the first login and re-run this script)"
    }
    if ($TlsCertFile) {
        $certText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $TlsCertFile).ProviderPath)
        $keyText  = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $TlsKeyFile).ProviderPath)
        if ($certText -notmatch '-----BEGIN CERTIFICATE-----') { throw "$TlsCertFile is not a PEM certificate." }
        if ($keyText -notmatch '-----BEGIN (RSA |EC )?PRIVATE KEY-----') {
            throw "$TlsKeyFile is not an unencrypted PEM private key (convert PFX: openssl pkcs12 -in x.pfx -nocerts -nodes)."
        }
        Write-SecretFile -Path $tlsCertTarget -Value $certText.Trim()
        Write-SecretFile -Path $tlsKeyTarget -Value $keyText.Trim()
        Write-Ok 'TLS certificate and key stored in the secrets directory.'
    }
}
$tlsEnabled = (Test-Path -LiteralPath $tlsCertTarget) -and (Test-Path -LiteralPath $tlsKeyTarget)

# --- enterprise root CA ------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($CertsDir, 'Provision enterprise root CA')) {
    if ($CaSourceDir) {
        $srcInfo = Get-CaInfo $CaSourceDir
        if (-not $srcInfo) { throw "$CaSourceDir contains no CA certificate (mitmproxy-ca-cert.pem / aegis-enterprise-ca.der)." }
        $curInfo = Get-CaInfo $CertsDir
        if ($curInfo -and $curInfo.Fingerprint -ne $srcInfo.Fingerprint -and -not $Force) {
            throw "A different CA already exists in $CertsDir ($($curInfo.Fingerprint)). Re-run with -Force to replace it - every client must then trust the new CA."
        }
        foreach ($name in @('mitmproxy-ca.pem', 'mitmproxy-ca-cert.pem', 'aegis-enterprise-ca.crt', 'aegis-enterprise-ca.der')) {
            $src = Join-Path $CaSourceDir $name
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $CertsDir $name) -Force }
        }
        Write-Ok "Imported CA from $CaSourceDir"
    }
    elseif (-not (Get-CaInfo $CertsDir)) {
        Write-Step 'Generating the enterprise root CA (RSA 3072, 10 years)'
        Invoke-Native -FilePath $ExePath -ArgumentList @('gen-ca', $CertsDir) | ForEach-Object { Write-Host "    $_" }
    }
    if (Test-Path -LiteralPath $caKey) {
        # The control-plane only reads the public certificate. The CA private key stays admin-only.
        Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($caKey, '/inheritance:r', '/grant:r', "${SidSystem}:F", "${SidAdmins}:F", '/L', '/Q') | Out-Null
    }
}

# --- service registration ----------------------------------------------------------------------------
# "service" selects the SCM dispatcher explicitly (svc.IsWindowsService's parent-process heuristic is not reliable).
$imagePath = '"{0}" service' -f $ExePath
if ($PSCmdlet.ShouldProcess($ServiceName, 'Register/update Windows service')) {
    $existing = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-Service -Name $ServiceName -BinaryPathName $imagePath -DisplayName $DisplayName `
            -Description $Description -StartupType Automatic | Out-Null
        Write-Ok "Service $ServiceName registered."
    }
    else {
        if ($existing.PathName -ne $imagePath) {
            $res = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{ PathName = $imagePath }
            if ($res.ReturnValue -ne 0) { throw "Updating the service binary path failed (Win32_Service.Change = $($res.ReturnValue))." }
        }
        Set-Service -Name $ServiceName -StartupType Automatic -DisplayName $DisplayName -Description $Description
        Write-Ok "Service $ServiceName updated."
    }
    # Virtual account: per-service SID, no password, no interactive logon, network access as computer account.
    Invoke-Native -FilePath 'sc.exe' -ArgumentList @('config', $ServiceName, 'obj=', $ServiceAccount) | Out-Null
    Invoke-Native -FilePath 'sc.exe' -ArgumentList @('sidtype', $ServiceName, 'unrestricted') | Out-Null
    # Least privilege: the process token only keeps SeChangeNotifyPrivilege.
    Invoke-Native -FilePath 'sc.exe' -ArgumentList @('privs', $ServiceName, 'SeChangeNotifyPrivilege') | Out-Null
    # Recovery: restart after 5 s, 5 s, 30 s; reset the failure counter after 24 h. failureflag=1 also
    # triggers the actions when the service stops with an error exit code (e.g. database unreachable).
    Invoke-Native -FilePath 'sc.exe' -ArgumentList @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/30000') | Out-Null
    Invoke-Native -FilePath 'sc.exe' -ArgumentList @('failureflag', $ServiceName, '1') | Out-Null
    Write-Ok "Service runs as $ServiceAccount with restart-on-failure recovery."
}

# --- event log source (errors before/after logging is set up are only visible here) --------------------
if ($PSCmdlet.ShouldProcess($EventLogKey, 'Register Application event log source')) {
    if (-not (Test-Path -LiteralPath $EventLogKey)) { New-Item -Path $EventLogKey | Out-Null }
    New-ItemProperty -Path $EventLogKey -Name 'EventMessageFile' -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force | Out-Null
    New-ItemProperty -Path $EventLogKey -Name 'TypesSupported' -PropertyType DWord -Value 7 -Force | Out-Null
    Write-Ok "Event log source $ServiceName registered (Application log)."
}

# --- ACLs for the service account (requires the service to exist so the SID resolves) ----------------
if ($PSCmdlet.ShouldProcess($DataRoot, "Grant $ServiceAccount access")) {
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($InstallDir, '/grant:r', "${ServiceAccount}:(OI)(CI)RX", '/L', '/Q') | Out-Null
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($DataDir, '/grant:r', "${ServiceAccount}:(OI)(CI)M", '/L', '/Q') | Out-Null
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($LogsDir, '/grant:r', "${ServiceAccount}:(OI)(CI)M", '/L', '/Q') | Out-Null
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($CertsDir, '/grant:r', "${ServiceAccount}:(OI)(CI)RX", '/L', '/Q') | Out-Null
    Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($SecretsDir, '/grant:r', "${ServiceAccount}:(OI)(CI)R", '/L', '/Q') | Out-Null
    if (Test-Path -LiteralPath $caKey) {
        # re-assert after the certs grant: no inherited ACE may reach the CA key
        Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($caKey, '/inheritance:r', '/grant:r', "${SidSystem}:F", "${SidAdmins}:F", '/L', '/Q') | Out-Null
    }
    # Read the result back: only SYSTEM, Administrators, the service (and users: read program files) may have access.
    $aclProblems = @(Get-InstallationAclProblem -IncludeLogs)
    if ($aclProblems.Count) {
        throw ("ACL verification failed - the service was not started:`n  {0}" -f ($aclProblems -join "`n  "))
    }
    Write-Ok 'ACLs verified: program files = read, data/logs = modify, certs = read, secrets = read (no inheritance), CA key = admins only.'
}

# --- service environment (REG_MULTI_SZ "Environment") ------------------------------------------------
$envMap = [ordered]@{}
$envMap['CONTROL_PLANE_PORT'] = "$Port"
if ($ListenAddress) { Assert-NoControlChar 'ListenAddress' $ListenAddress; $envMap['AEGIS_LISTEN_ADDR'] = $ListenAddress }
$envMap['AEGIS_PUBLIC_URL'] = $PublicUrl
if ($DashboardUrl) { Assert-NoControlChar 'DashboardUrl' $DashboardUrl; $envMap['AEGIS_DASHBOARD_URL'] = $DashboardUrl.TrimEnd('/') }
if ($ProxyAddress) { Assert-NoControlChar 'ProxyAddress' $ProxyAddress; $envMap['AEGIS_PROXY_ADDRESS'] = $ProxyAddress }
$envMap['DATA_DIR']  = $DataDir
$envMap['CERTS_DIR'] = $CertsDir
$envMap['AEGIS_STORAGE'] = $Storage
if ($Storage -eq 'postgres') { $envMap['AEGIS_DATABASE_URL_FILE'] = $dbUrlFile }
$envMap['AEGIS_JWT_SECRET_FILE']    = $jwtFile
$envMap['AEGIS_DATAPLANE_KEY_FILE'] = $dpKeyFile
$envMap['AEGIS_ENCRYPTION_KEY_FILE'] = $encKeyFile
if (Test-Path -LiteralPath $bootstrapFile) { $envMap['AEGIS_BOOTSTRAP_ADMIN_PASSWORD_FILE'] = $bootstrapFile }
if (Test-Path -LiteralPath $metricsFile)   { $envMap['AEGIS_METRICS_TOKEN_FILE'] = $metricsFile }
if ($tlsEnabled) {
    $envMap['AEGIS_TLS_CERT_FILE'] = $tlsCertTarget
    $envMap['AEGIS_TLS_KEY_FILE']  = $tlsKeyTarget
}
if (Test-Path -LiteralPath (Join-Path $UiTarget 'index.html')) { $envMap['AEGIS_UI_DIR'] = $UiTarget }
if ($TrustedProxies) { $envMap['AEGIS_TRUSTED_PROXIES'] = ($TrustedProxies -join ',') }
if ($CorsOrigins)    { $envMap['AEGIS_CORS_ORIGINS'] = ($CorsOrigins -join ',') }
$envMap['AEGIS_LOG_FILE']   = $LogFile
$envMap['AEGIS_LOG_FORMAT'] = 'json'
$envMap['AEGIS_DEMO_MODE']  = 'false'
# Keep additional variables of a previous installation (earlier -ExtraEnvironment), then apply the new ones.
# To remove such a variable pass it with an empty value: -ExtraEnvironment @{ AEGIS_LOG_LEVEL = '' }.
foreach ($key in $previousEnv.Keys) {
    if ($ManagedKeys -notcontains $key -and $PlainSecretVars -notcontains $key) { $envMap[$key] = $previousEnv[$key] }
}
if ($ExtraEnvironment) { foreach ($key in $ExtraEnvironment.Keys) { $envMap[$key] = [string]$ExtraEnvironment[$key] } }

# REG_MULTI_SZ cannot hold empty strings - skip empty values.
$envList = @(foreach ($key in $envMap.Keys) { if ("$($envMap[$key])" -ne '') { '{0}={1}' -f $key, $envMap[$key] } })
if ($PSCmdlet.ShouldProcess($ServiceKey, 'Write service environment')) {
    New-ItemProperty -Path $ServiceKey -Name 'Environment' -PropertyType MultiString -Value ([string[]]$envList) -Force | Out-Null
    Write-Ok 'Service environment written (registry value Environment):'
    $envList | ForEach-Object { Write-Host "    $_" }
}

# --- firewall ----------------------------------------------------------------------------------------
$effectivePort = $Port
if ($ListenAddress -and $ListenAddress -match ':(\d+)$') { $effectivePort = [int]$Matches[1] }
if (-not $SkipFirewall -and $PSCmdlet.ShouldProcess($FirewallRule, "Allow inbound TCP $effectivePort")) {
    Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name $FirewallRule -DisplayName "AegisProxy Control-Plane (TCP $effectivePort)" `
        -Group 'AegisProxy' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $effectivePort `
        -Program $ExePath -Profile $FirewallProfile -RemoteAddress $FirewallRemoteAddress | Out-Null
    Write-Ok ("Firewall: inbound TCP {0} allowed (profile {1}, remote {2})." -f $effectivePort, ($FirewallProfile -join ','), ($FirewallRemoteAddress -join ','))
    if ($FirewallRemoteAddress -contains 'Any') {
        Write-Note 'Restrict -FirewallRemoteAddress to admin workstations, data-plane workers and load balancers.'
    }
}

# --- log rotation (AEGIS_LOG_FILE has no built-in rotation) -------------------------------------------
$rotationScript = Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'
if (-not $SkipLogRotationTask -and $PSCmdlet.ShouldProcess($TaskName, 'Register daily log rotation task')) {
    $rotationBody = @'
# Generated by Install-AegisControlPlane.ps1 - daily copy/truncate rotation of the control-plane log.
# The service keeps the file open (append mode, shared read/write), so it cannot be renamed; the content
# is copied, the file truncated in place, the copy zipped and old archives removed.
param([Parameter(Mandatory = $true)][string]$LogFile, [int]$RetentionDays = 30)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $LogFile)) { return }
$item = Get-Item -LiteralPath $LogFile
if ($item.Length -gt 0) {
    $copy = Join-Path $item.DirectoryName ('{0}-{1}{2}' -f $item.BaseName, (Get-Date -Format 'yyyyMMdd-HHmmss'), $item.Extension)
    $in = [System.IO.File]::Open($LogFile, 'Open', 'ReadWrite', 'ReadWrite')
    try {
        $out = [System.IO.File]::Create($copy)
        try { $in.CopyTo($out) } finally { $out.Dispose() }
        $in.SetLength(0)
    }
    finally { $in.Dispose() }
    Compress-Archive -LiteralPath $copy -DestinationPath ($copy + '.zip') -Force
    Remove-Item -LiteralPath $copy -Force
}
Get-ChildItem -LiteralPath $item.DirectoryName -Filter ('{0}-*.zip' -f $item.BaseName) |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } |
    Remove-Item -Force
'@
    [System.IO.File]::WriteAllText($rotationScript, $rotationBody, (New-Object System.Text.UTF8Encoding($true)))
    $rotationProblems = @(Get-AclProblem -Path $rotationScript -Allowed $AclProgram)
    if ($rotationProblems.Count) { throw ("ACL verification failed for the log rotation script:`n  {0}" -f ($rotationProblems -join "`n  ")) }
    $taskArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -LogFile "{1}" -RetentionDays {2}' -f $rotationScript, $LogFile, $LogRetentionDays
    $action    = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $taskArgs
    $trigger   = New-ScheduledTaskTrigger -Daily -At '03:15'
    # Least privilege: the task runs as the service's virtual account, which may modify the log directory anyway
    # (as SYSTEM it would act on files and links the service controls). The script itself stays admin-only.
    $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Rotates the AegisProxy control-plane log file.' -Force | Out-Null
    Write-Ok "Log rotation task registered ($TaskPath$TaskName, daily 03:15 as $ServiceAccount, keep $LogRetentionDays days)."
}

# --- start + health ----------------------------------------------------------------------------------
$healthy = $false
if ($PSCmdlet.ShouldProcess($ServiceName, 'Start service and wait for /healthz')) {
    Write-Step "Starting $ServiceName"
    try { Start-Service -Name $ServiceName }
    catch { Write-Note "Start-Service reported: $($_.Exception.Message)" }
    # The binary's own probe connects to 127.0.0.1:<port>/healthz (https without certificate verification on
    # loopback), so it can only be used when the listener accepts IPv4 loopback connections.
    $probeLoopback = (-not $ListenAddress) -or ($ListenAddress -match '^(|0\.0\.0\.0|127\.0\.0\.1|\[::\]|::):\d+$')
    if ($probeLoopback) {
        $saved = @{ Port = $env:CONTROL_PLANE_PORT; Tls = $env:AEGIS_TLS_CERT_FILE }
        try {
            $env:CONTROL_PLANE_PORT = "$effectivePort"
            if ($tlsEnabled) { $env:AEGIS_TLS_CERT_FILE = $tlsCertTarget } else { Remove-Item Env:\AEGIS_TLS_CERT_FILE -ErrorAction SilentlyContinue }
            $deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
            do {
                Start-Sleep -Seconds 2
                $svc = Get-Service -Name $ServiceName
                $null = & $ExePath healthcheck
                if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
            } while ((Get-Date) -lt $deadline -and $svc.Status -ne 'Stopped')
        }
        finally {
            $env:CONTROL_PLANE_PORT = $saved.Port
            if ($saved.Tls) { $env:AEGIS_TLS_CERT_FILE = $saved.Tls } else { Remove-Item Env:\AEGIS_TLS_CERT_FILE -ErrorAction SilentlyContinue }
        }
    }
    else {
        Start-Sleep -Seconds 5
        $healthy = ((Get-Service -Name $ServiceName).Status -eq 'Running')
        Write-Note "Listener $ListenAddress is not reachable via 127.0.0.1 - check https://<host>:$effectivePort/healthz manually."
    }
    if ($healthy) { Write-Ok "Control-plane is healthy (/healthz)." }
    else {
        Write-Note "Control-plane did not become healthy within $HealthTimeoutSeconds s (service status: $((Get-Service -Name $ServiceName).Status))."
        Show-LogTail
    }
}

# --- summary -----------------------------------------------------------------------------------------
$ca = Get-CaInfo $CertsDir
Write-Host ''
Write-Host '==================== AegisProxy control-plane ====================' -ForegroundColor Cyan
Write-Host "Service           : $ServiceName ($ServiceAccount)"
Write-Host "Public URL        : $PublicUrl"
Write-Host ("Listener          : {0}://<host>:{1}" -f ($(if ($tlsEnabled) { 'https' } else { 'http' })), $effectivePort)
Write-Host "Log file          : $LogFile"
if ($ca) {
    Write-Host "Root CA subject   : $($ca.Subject)"
    Write-Host "Root CA valid to  : $($ca.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "Root CA SHA-256   : $($ca.Fingerprint)" -ForegroundColor Green
}
Write-Host "CA key (data-plane): $caKey   <- admin-only, copy securely to data-plane hosts"
Write-Host "Data-plane key    : $dpKeyFile" -ForegroundColor Green
if (Test-Path -LiteralPath $bootstrapFile) {
    Write-Host "Admin password    : as given (-BootstrapAdminPassword), file $bootstrapFile"
}
else {
    Write-Host "Admin password    : $(Join-Path $DataDir 'secrets\initial-admin-password') (user 'admin', created on first start)"
}
Write-Host ''
Write-Host 'Next step - data-plane on this or another host:' -ForegroundColor Cyan
Write-Host ("  .\Install-AegisDataPlane.ps1 -ControlPlaneUrl {0} -DataPlaneKeyFile '{1}' -CaFile '{2}' -WinSWExe <path>\WinSW-x64.exe" -f $PublicUrl, $dpKeyFile, $caKey)
Write-Host 'Client trust/proxy rollout: <PublicUrl>/api/public/ca/install-windows.ps1 and /api/public/ca/install-linux.sh'
if (-not $healthy -and -not $WhatIfPreference) { exit 1 }
