#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hosts the AegisProxy web console (static SPA, frontend\dist) on IIS 10 with HTTPS.

.DESCRIPTION
    * refuses installation sources that non-administrators can change (this script, -DistDir, the web.config
      template, and every folder above them), before it copies any of them
    * refuses a -PhysicalPath below a directory that non-administrators may rename or replace (every directory up
      to the volume root); directories it creates above the site directory get an ACL of their own
    * installs the required IIS role services (Web-Server, Web-Static-Content, optionally Web-Http-Redirect)
    * verifies that the IIS URL Rewrite module is installed (required by web.config: SPA fallback, HTTPS redirect)
    * creates a dedicated application pool ("No Managed Code", ApplicationPoolIdentity) and site
    * mirrors the built console into the site directory, deploys web.config (security headers, caching rules)
    * writes config.js (window.__AEGIS_CONFIG__.apiBaseUrl) and, for a separate API origin, adds that origin
      to the Content-Security-Policy connect-src directive
    * binds HTTPS (SNI) with a certificate from Cert:\LocalMachine\My (by thumbprint)
    * with -ApiProxyTarget: proxies /api to the control-plane through Application Request Routing (same origin,
      no CORS), authenticates IIS to it with the proxy secret (X-Aegis-Proxy-Auth, from a file that only
      administrators can read and change) and replaces a client's X-Forwarded-For with the address it connected from

    The site directory is readable only by SYSTEM, Administrators and the application pool identity; anonymous
    requests are served with the pool identity (no IUSR access needed). An existing site directory is taken over
    before the files are deployed (owner Administrators, foreign ACEs removed, junctions refused) and the result
    is verified.

    If the console is served by the control-plane itself (AEGIS_UI_DIR) you do not need IIS at all.

.PARAMETER DistDir
    Built console (npm --prefix frontend run build -> frontend\dist). Default: ..\..\frontend\dist.

.PARAMETER ApiBaseUrl
    Origin of the control-plane API when it is NOT reachable under the console's origin, e.g.
    https://aegis-api.corp.example. Empty (default) = same origin (control-plane behind the same host name, or
    -ApiProxyTarget). The control-plane then needs AEGIS_CORS_ORIGINS=<console origin>.

.PARAMETER ApiProxyTarget
    Origin of the control-plane that IIS proxies /api to (Application Request Routing 3.0), e.g. http://127.0.0.1:8081
    for a control-plane on this host (Install-AegisControlPlane.ps1 -ListenAddress 127.0.0.1:8081 -TrustedProxies
    127.0.0.1/32). The rule goes into the deployed web.config together with the proxy secret, which only SYSTEM,
    Administrators and the application pool can read; ARR is enabled server-wide (response buffering off for the
    live-traffic stream, no port in X-Forwarded-For). The rule replaces an X-Forwarded-For header sent by the client
    with the address the client connected from (IIS is the edge). Pass it on every run: a run without it deploys
    web.config without the rule. Excludes -ApiBaseUrl.

.PARAMETER ProxySecretFile
    The control-plane's AEGIS_TRUSTED_PROXY_SECRET_FILE, sent in X-Aegis-Proxy-Auth with -ApiProxyTarget: the
    control-plane trusts the X-Forwarded-For of a loopback peer only with it (every local account can connect from
    loopback). Default: %ProgramData%\AegisProxy\secrets\trusted-proxy-secret, which Install-AegisControlPlane.ps1
    creates on this host. For a control-plane on another host copy that file over a protected channel into a folder
    that only administrators can read and change. The script stops if a non-administrator owns the file, may read or
    change it, or may rename a directory above it, or if a junction or symbolic link is on the way (no override):
    on a host without a control-plane every user may create the default path and so learn or choose the secret.

.PARAMETER CertificateThumbprint
    Thumbprint of the TLS server certificate in Cert:\LocalMachine\My (private key required).

.PARAMETER HostName
    Host name for the SNI binding, e.g. aegis-console.corp.example.

.PARAMETER AddHttpBinding
    Also bind port 80 - web.config redirects every http request to https.

.PARAMETER AllowWritableSource
    Accept installation sources that non-administrators can change: this script, -DistDir (everything below it),
    -WebConfigTemplate and every folder above them up to the volume root. Allowed are only SYSTEM, Administrators and
    TrustedInstaller as owners and as principals that may write, create, delete, rename, change the permissions or
    take ownership (above the sources: rename, delete entries, change the permissions, take ownership). Whoever can
    change them decides what the console serves (scripts in every administrator's browser) and how IIS handles it.
    Not recommended: keep the release in a folder that only administrators control (docs/deployment/windows.md,
    section 2).

.PARAMETER AllowWritableParent
    Accept a -PhysicalPath below a directory that non-administrators own or may rename, delete entries in, change
    the permissions of or take ownership of, or below a junction or symbolic link - every directory up to the volume
    root counts. Whoever may rename such a directory can put another console (scripts in every administrator's
    browser) and web.config in place of the site directory. Directories above it that do not exist yet are not a
    reason: the script creates them with an ACL of their own (owner Administrators; SYSTEM/Administrators full
    control, Users read). Not recommended.

.EXAMPLE
    .\Install-AegisConsole-IIS.ps1 -HostName aegis-console.corp.example -CertificateThumbprint 3F2A...C9 `
        -ApiBaseUrl https://aegis-api.corp.example -AddHttpBinding

.EXAMPLE
    # Console and API on one origin, control-plane on this host behind IIS
    .\Install-AegisConsole-IIS.ps1 -HostName aegis.corp.example -CertificateThumbprint 3F2A...C9 `
        -ApiProxyTarget http://127.0.0.1:8081 -AddHttpBinding

.NOTES
    Download URL Rewrite 2.1: https://www.iis.net/downloads/microsoft/url-rewrite
    Same-origin API (-ApiProxyTarget): Application Request Routing 3.0 (https://www.iis.net/downloads/microsoft/application-request-routing)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DistDir = (Join-Path $PSScriptRoot '..\..\frontend\dist'),

    [string]$WebConfigTemplate = (Join-Path $PSScriptRoot 'iis\web.config'),

    [string]$SiteName = 'AegisConsole',

    [string]$AppPoolName = 'AegisConsole',

    [string]$PhysicalPath = (Join-Path $env:SystemDrive 'inetpub\aegis-console'),

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f\s]{40,}$')]
    [string]$CertificateThumbprint,

    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 443,

    [AllowEmptyString()]
    [string]$ApiBaseUrl = '',

    [AllowEmptyString()]
    [string]$ApiProxyTarget = '',

    [string]$ProxySecretFile = (Join-Path $env:ProgramData 'AegisProxy\secrets\trusted-proxy-secret'),

    [switch]$AddHttpBinding,

    [switch]$InstallHttpRedirectFeature,

    [switch]$AllowHttpApi,

    [switch]$SkipUrlRewriteCheck,

    [switch]$AllowWritableSource,

    [switch]$AllowWritableParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Note([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

function Invoke-Native {
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @(), [int[]]$SuccessCodes = @(0))
    $ErrorActionPreference = 'Continue'
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    if ($SuccessCodes -notcontains $LASTEXITCODE) {
        throw ("'{0} {1}' failed with exit code {2}:`n{3}" -f $FilePath, ($ArgumentList -join ' '), $LASTEXITCODE, ($output -join "`n"))
    }
    return $output
}

function Get-AppPoolSid([string]$Name) {
    # SID of IIS AppPool\<Name>, computed (no lookup needed): S-1-5-82 and the SHA-1 of the lower-case pool name in
    # UTF-16LE as five little-endian DWORDs.
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Name.ToLowerInvariant())) } finally { $sha.Dispose() }
    return 'S-1-5-82-' + ((0..4 | ForEach-Object { [System.BitConverter]::ToUInt32($hash, 4 * $_) }) -join '-')
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
    # -Location takes directories that the installers take over themselves (program, data and site directories) or
    # check otherwise (the Python directory): only the directories above them count, like those above a source.
    # Directories that do not exist yet are skipped: the installers create them with an ACL of their own (Get-NewParent).
    # -Secret takes files whose content is secret (keys, the proxy secret, the CA private key): checked like a source,
    # and reading them (ReadData) counts as well - except for services (NT SERVICE\..., S-1-5-80-...: only an
    # administrator can install one; the control-plane service reads its secrets), which may read but not change them.
    param([string[]]$Path = @(), [string[]]$Location = @(), [string[]]$Secret = @())
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $ownerOnly = @('S-1-3-0', 'S-1-3-1', 'S-1-3-4')
    $names = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-7' = 'ANONYMOUS LOGON'; 'S-1-5-11' = 'Authenticated Users'
        'S-1-5-32-545' = 'Users'; 'S-1-5-32-546' = 'Guests'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE' }
    $starts = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Path | Where-Object { $_ })) {
        if (Test-Path -LiteralPath $p) { $starts.Add(@{ Path = (Resolve-Path -LiteralPath $p).ProviderPath; Above = $false; Secret = $false }) }
    }
    foreach ($p in @($Secret | Where-Object { $_ })) {
        if (Test-Path -LiteralPath $p) { $starts.Add(@{ Path = (Resolve-Path -LiteralPath $p).ProviderPath; Above = $false; Secret = $true }) }
    }
    foreach ($p in @($Location | Where-Object { $_ })) {
        $full = [System.IO.Path]::GetFullPath($p)
        if ($full.Length -gt 3) { $starts.Add(@{ Path = [System.IO.Path]::GetDirectoryName($full.TrimEnd('\', '/')); Above = $true; Secret = $false }) }
    }
    $checks = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($start in $starts) {
        $current = $start.Path
        if ($current.Length -gt 3) { $current = $current.TrimEnd('\', '/') }
        $above = $start.Above
        $isSecret = $start.Secret
        while ($current -and -not $seen.ContainsKey("$above|$isSecret|$current")) {
            $seen["$above|$isSecret|$current"] = $true
            if (Test-Path -LiteralPath $current) { $checks.Add(@{ Path = $current; Above = $above; Secret = $isSecret }) }
            $current = [System.IO.Path]::GetDirectoryName($current)
            $above = $true
            $isSecret = $false
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
                        $rights = ConvertTo-FileRight ([int]$rule.FileSystemRights)
                        $name = if ($names.ContainsKey($sid)) { $names[$sid] } else { $sid }
                        if ($rights -band $mask) { $who += $name }
                        elseif ($check.Secret -and ($rights -band 1) -and $sid -notlike 'S-1-5-80-*') { $who += "${name}: read" }
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

function Assert-TrustedLocation {
    # Stops before the program, data or site directories are created or taken over when Get-WritableSource reports a
    # directory above them (with -Allow: warns), and shows how to give such a directory an ACL of its own.
    param([string[]]$Path = @(), [switch]$Allow)
    $writable = @(Get-WritableSource -Location $Path | Sort-Object -Property Path)
    if (-not $writable.Count) { return }
    $list = @($writable | Select-Object -First 15 | ForEach-Object { '  {0} ({1})' -f $_.Path, $_.Who })
    if ($writable.Count -gt 15) { $list += "  ... and $($writable.Count - 15) more" }
    $folder = @($writable | Where-Object { [System.IO.Path]::GetDirectoryName($_.Path) } | ForEach-Object { $_.Path }) + @('<folder>')
    $message = ("Non-administrators can rename or replace directories above the directories this script installs into:`n{0}`n" +
        'Whoever may rename one of them can put other files in place of the installation (programs that run as a service, ' +
        "its secrets, the console). Keep the default directories, or give the listed directory an ACL that only administrators control:`n" +
        "  icacls `"{1}`" /inheritance:r /grant:r `"*S-1-5-32-544:(OI)(CI)F`" `"*S-1-5-18:(OI)(CI)F`" `"*S-1-5-32-545:(OI)(CI)RX`"`n" +
        "  icacls `"{1}`" /setowner *S-1-5-32-544 /L`n" +
        '(this also changes what the directories below it inherit; docs/deployment/windows.md, troubleshooting) and remove a listed junction or symbolic link') -f
        ($list -join "`n"), $folder[0]
    if (-not $Allow) { throw "$message. Or pass -AllowWritableParent to accept the risk." }
    Write-Note "$message. Continuing because of -AllowWritableParent."
}

function Assert-ProtectedSecret {
    # Stops before a secret file is read when Get-WritableSource -Secret reports it or a directory above it: whoever
    # can read it knows the secret, whoever can replace it chooses the secret. There is no override.
    param([string[]]$Path = @())
    $exposed = @(Get-WritableSource -Secret $Path | Sort-Object -Property Path)
    if (-not $exposed.Count) { return }
    $list = @($exposed | Select-Object -First 15 | ForEach-Object { '  {0} ({1})' -f $_.Path, $_.Who })
    if ($exposed.Count -gt 15) { $list += "  ... and $($exposed.Count - 15) more" }
    $folder = Join-Path $env:SystemDrive 'AegisSecrets'
    throw (("Non-administrators can read or replace secret files that this script reads, or rename a directory above them:`n{0}`n" +
        'Whoever can read a secret knows it, whoever can replace it chooses it. Copy the secret over a protected channel ' +
        "into a folder that only administrators can read and change, and pass that copy:`n" +
        "  New-Item -ItemType Directory -Force `"{1}`"`n" +
        "  icacls `"{1}`" /inheritance:r /grant:r `"*S-1-5-32-544:(OI)(CI)F`" `"*S-1-5-18:(OI)(CI)F`"`n" +
        "  (copy the secret into it)`n" +
        "  icacls `"{1}`" /setowner *S-1-5-32-544 /T /L /C /Q`n" +
        'If others could read it, treat the secret as known and replace it (docs/deployment/windows.md, troubleshooting).') -f
        ($list -join "`n"), $folder)
}

function Get-NewParent([string[]]$Path) {
    # Directories above Path that do not exist yet, top-down. The installers create them together with Path and then
    # give them an ACL of their own: they would inherit what the directory above passes on (on a client edition the
    # volume root passes Modify for authenticated users to every new folder).
    $new = @()
    foreach ($p in @($Path | Where-Object { $_ })) {
        $full = [System.IO.Path]::GetFullPath($p)
        if ($full.Length -le 3) { continue }
        $current = [System.IO.Path]::GetDirectoryName($full.TrimEnd('\', '/'))
        while ($current -and -not (Test-Path -LiteralPath $current)) { $new += $current; $current = [System.IO.Path]::GetDirectoryName($current) }
    }
    return @($new | Sort-Object -Unique | Sort-Object -Property Length)
}

function Get-AclProblem {
    # Deviations of Path from the expected ACL: a directory must be owned by Administrators or SYSTEM, and every
    # allow ACE (explicit or inherited) must belong to a principal of -Allowed (SID -> F|RX) and stay within
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
        if ((ConvertTo-FileRight ([int]$rule.FileSystemRights)) -band -bnot @{ F = 2032127; RX = 1179817 }[$Allowed[$sid]]) {
            $problems += "${Path}: $sid has more than $($Allowed[$sid]) access"
        }
    }
    return $problems
}

function Assert-PlainItem($Item) {
    # Refuses a junction or symbolic link (ACL changes and robocopy /MIR would act on its target) and a file with
    # further hard links (its ACL is shared with a file elsewhere).
    if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Junction/symbolic link in the site directory: $($Item.FullName). Remove it and re-run."
    }
    if (-not $Item.PSIsContainer -and "$($Item.LinkType)" -eq 'HardLink') {
        throw "$($Item.FullName) has further hard links (they share its ACL with a file elsewhere). Remove it and re-run."
    }
}

function Protect-Directory {
    # Takes over a directory that may have existed before the installation, top-down, so that whoever created it
    # cannot swap in a link while it is processed. Root first: owner Administrators and a protected ACL with -Grant
    # (explicit ACEs of principals that are not -Allowed are removed) - from then on nobody else can create, delete
    # or rename entries in it. Then every entry below it (listed after Root was locked), each item only after its
    # parent: owner Administrators, explicit ACEs dropped (it inherits from Root only). icacls always gets /L (a
    # link itself is changed, never its target) and never /T (which follows links). A link or hard-linked file
    # stops the installation; items are checked again once taken over (until then their creator could still turn
    # an empty directory into a junction).
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string[]]$Grant,
        [Parameter(Mandatory = $true)][hashtable]$Allowed)
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/setowner', '*S-1-5-32-544', '/L', '/Q')
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList (@($Root, '/inheritance:r', '/grant:r') + $Grant + @('/L', '/Q'))
    $foreign = @((Get-Acl -LiteralPath $Root).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
            ForEach-Object { "$($_.IdentityReference.Value)" } | Where-Object { -not $Allowed.ContainsKey($_) } | Sort-Object -Unique)
    foreach ($sid in $foreign) { $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($Root, '/remove', "*$sid", '/L', '/Q') }
    Assert-PlainItem (Get-Item -LiteralPath $Root -Force)
    $pending = New-Object System.Collections.Stack
    foreach ($child in @(Get-ChildItem -LiteralPath $Root -Force)) { $pending.Push($child.FullName) }
    while ($pending.Count) {
        $path = [string]$pending.Pop()
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        Assert-PlainItem $item
        $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/setowner', '*S-1-5-32-544', '/L', '/Q')
        $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($path, '/reset', '/L', '/Q')
        Assert-PlainItem (Get-Item -LiteralPath $path -Force)
        if ($item.PSIsContainer) { foreach ($child in @(Get-ChildItem -LiteralPath $path -Force)) { $pending.Push($child.FullName) } }
    }
}

function Find-ReparsePoint([string[]]$Path) {
    # Junctions and symbolic links at or below Path, found without following them (icacls /T and robocopy /MIR
    # would act on their targets), and files with further hard links (they share their ACL with a file elsewhere).
    # Unreadable directories throw.
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

# --- validation --------------------------------------------------------------------------------------
$CertificateThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
$DistDir = [System.IO.Path]::GetFullPath($DistDir)
if (-not (Test-Path -LiteralPath (Join-Path $DistDir 'index.html'))) {
    throw "$DistDir does not contain index.html. Build the console first: npm --prefix frontend ci; npm --prefix frontend run build"
}
if (-not (Test-Path -LiteralPath $WebConfigTemplate)) { throw "web.config template not found: $WebConfigTemplate" }
# The console runs in every administrator's browser and web.config configures IIS: both must be out of reach of other
# accounts, including the folders above them (whoever may rename one can replace the files).
Assert-TrustedSource -Path @($PSCommandPath, $DistDir, $WebConfigTemplate) -Allow:$AllowWritableSource
$PhysicalPath = [System.IO.Path]::GetFullPath($PhysicalPath)
# The site directory is taken over below; whoever may rename a directory above it could put another console in its
# place. Checked again right before the site directory is created (IIS setup creates C:\inetpub in between).
Assert-TrustedLocation -Path @($PhysicalPath) -Allow:$AllowWritableParent
# The site directory may exist already (created by anyone who can write to its parent). Links in it are refused:
# ACL changes and robocopy /MIR would act on their targets (hard-linked files: on the file elsewhere).
# Protect-Directory checks again while it takes the directory over.
$links = @(Find-ReparsePoint @($PhysicalPath))
if ($links.Count) { throw "Junctions/symbolic links and hard-linked files are not allowed in the site directory: $($links -join ', '). Remove them and re-run." }
$SiteAcl = @{ 'S-1-5-18' = 'F'; 'S-1-5-32-544' = 'F'; (Get-AppPoolSid $AppPoolName) = 'RX' }

$ApiBaseUrl = $ApiBaseUrl.Trim().TrimEnd('/')
if ($ApiBaseUrl) {
    # Same rules as frontend/docker/40-aegis-config.sh: URL characters only (embedded verbatim in JS and CSP).
    if ($ApiBaseUrl -notmatch '^https?://[A-Za-z0-9:/._%-]+$') { throw '-ApiBaseUrl must be an http(s) URL consisting of URL characters only.' }
    if ($ApiBaseUrl -notmatch '^https://' -and -not $AllowHttpApi) { throw '-ApiBaseUrl must use https:// (pass -AllowHttpApi for lab setups).' }
    $uri = [System.Uri]$ApiBaseUrl
    $ApiOrigin = $uri.GetLeftPart([System.UriPartial]::Authority)
}
else { $ApiOrigin = '' }

$ApiProxyTarget = $ApiProxyTarget.Trim().TrimEnd('/')
$proxySecret = ''
if ($ApiProxyTarget) {
    if ($ApiBaseUrl) { throw '-ApiProxyTarget (API on the console origin through ARR) and -ApiBaseUrl (API on another origin) exclude each other.' }
    # Scheme, host and port only: the value is embedded verbatim in the rewrite rule.
    if ($ApiProxyTarget -notmatch '^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$') {
        throw '-ApiProxyTarget must be the origin of the control-plane (scheme, host, port), e.g. http://127.0.0.1:8081.'
    }
    # Plain http only to this host: on the network it would carry the proxy secret and the session cookies in clear text.
    $proxyLocal = $ApiProxyTarget -match '^http://(localhost|127(\.\d{1,3}){3}|\[::1\])(:|$)'
    if ($ApiProxyTarget -notmatch '^https://' -and -not $proxyLocal -and -not $AllowHttpApi) {
        throw '-ApiProxyTarget must use https:// for a control-plane on another host (pass -AllowHttpApi for lab setups).'
    }
    # The control-plane trusts the X-Forwarded-For of a loopback peer only together with its proxy secret.
    $ProxySecretFile = [System.IO.Path]::GetFullPath($ProxySecretFile)
    if (-not (Test-Path -LiteralPath $ProxySecretFile -PathType Leaf)) {
        throw ("Proxy secret {0} not found. Install-AegisControlPlane.ps1 creates it (-TrustedProxies 127.0.0.1/32 or -ProxySecret); " +
            'for a control-plane on another host copy its secrets\trusted-proxy-secret over a protected channel and pass -ProxySecretFile.') -f $ProxySecretFile
    }
    # On a host without a control-plane every user may create %ProgramData%\AegisProxy\secrets\trusted-proxy-secret
    # (and learn or choose the secret IIS sends): only administrators may read and change it (the control-plane
    # service may read it), up to the volume root.
    Assert-ProtectedSecret -Path @($ProxySecretFile)
    $proxySecret =([System.IO.File]::ReadAllText($ProxySecretFile)).Trim([char[]]@([char]0xFEFF, ' ', "`t", "`r", "`n"))
    if ($proxySecret.Length -lt 32 -or $proxySecret -cnotmatch '^[A-Za-z0-9._~+/=-]+$') {
        throw "$ProxySecretFile is not a valid proxy secret (at least 32 characters of letters, digits and -._~+/=)."
    }
}

$cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
if (-not $cert) { throw "Certificate $CertificateThumbprint not found in Cert:\LocalMachine\My." }
if (-not $cert.HasPrivateKey) { throw "Certificate $CertificateThumbprint has no private key." }
if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate $CertificateThumbprint expired on $($cert.NotAfter)." }
$dnsNames = @($cert.DnsNameList | ForEach-Object { "$($_.Unicode)" })
$nameMatches = $false
foreach ($n in $dnsNames) {
    if ($n -ieq $HostName -or ($n.StartsWith('*.') -and $HostName -ilike $n -and ($HostName.Split('.').Count -eq $n.Split('.').Count))) { $nameMatches = $true }
}
if (-not $nameMatches) { Write-Note "Certificate SANs ($($dnsNames -join ', ')) do not cover $HostName - browsers will reject it." }

# --- IIS role services -------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess('IIS', 'Install role services')) {
    $features = @('Web-Server', 'Web-Static-Content', 'Web-Default-Doc', 'Web-Http-Errors', 'Web-Http-Logging',
                  'Web-Stat-Compression', 'Web-Filtering', 'Web-Mgmt-Console')
    if ($InstallHttpRedirectFeature) { $features += 'Web-Http-Redirect' }
    if (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue) {
        $result = Install-WindowsFeature -Name $features
        if (-not $result.Success) { throw 'Installing the IIS role services failed.' }
        if ("$($result.RestartNeeded)" -eq 'Yes') { Write-Note 'A restart is required to complete the IIS installation.' }
    }
    else {
        # Windows client SKUs (lab use)
        $clientFeatures = @('IIS-WebServerRole', 'IIS-WebServer', 'IIS-CommonHttpFeatures', 'IIS-StaticContent', 'IIS-DefaultDocument',
                            'IIS-HttpErrors', 'IIS-HttpLogging', 'IIS-HttpCompressionStatic', 'IIS-RequestFiltering', 'IIS-ManagementConsole')
        if ($InstallHttpRedirectFeature) { $clientFeatures += 'IIS-HttpRedirect' }
        Enable-WindowsOptionalFeature -Online -FeatureName $clientFeatures -All -NoRestart | Out-Null
    }
    Write-Ok "IIS role services present: $($features -join ', ')"
}

# --- URL Rewrite module ------------------------------------------------------------------------------
$rewriteDll = Join-Path $env:SystemRoot 'System32\inetsrv\rewrite.dll'
$rewriteReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite' -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath $rewriteDll) -and -not $rewriteReg) {
    Write-Note 'The IIS URL Rewrite module is not installed. web.config needs it (SPA fallback, HTTPS redirect);'
    Write-Note 'without it IIS answers every request with HTTP 500.19.'
    Write-Note 'Download: https://www.iis.net/downloads/microsoft/url-rewrite  (rewrite_amd64_en-US.msi, silent: msiexec /i <msi> /qn)'
    if (-not $SkipUrlRewriteCheck) { throw 'URL Rewrite module missing (re-run with -SkipUrlRewriteCheck to deploy anyway).' }
}
else { Write-Ok "URL Rewrite module found$(if ($rewriteReg -and ($rewriteReg.PSObject.Properties.Name -contains 'Version')) { " (version $($rewriteReg.Version))" })." }

# --- Application Request Routing (only for -ApiProxyTarget) ------------------------------------------------
if ($ApiProxyTarget) {
    $arrDll = Join-Path $env:SystemRoot 'System32\inetsrv\requestRouter.dll'
    $arrReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\IIS Extensions\Application Request Routing' -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $arrDll) -and -not $arrReg) {
        throw ('-ApiProxyTarget needs Application Request Routing 3.0, which is not installed: ' +
            'https://www.iis.net/downloads/microsoft/application-request-routing (requestRouter_amd64.msi, silent: msiexec /i <msi> /qn).')
    }
    Write-Ok 'Application Request Routing found.'
}

Import-Module WebAdministration

# --- application pool --------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($AppPoolName, 'Create/update application pool')) {
    $poolPath = "IIS:\AppPools\$AppPoolName"
    if (-not (Test-Path -LiteralPath $poolPath)) { New-WebAppPool -Name $AppPoolName | Out-Null }
    Set-ItemProperty -LiteralPath $poolPath -Name managedRuntimeVersion -Value ''            # No Managed Code
    Set-ItemProperty -LiteralPath $poolPath -Name managedPipelineMode -Value 'Integrated'
    Set-ItemProperty -LiteralPath $poolPath -Name processModel.identityType -Value 'ApplicationPoolIdentity'
    Set-ItemProperty -LiteralPath $poolPath -Name processModel.loadUserProfile -Value $false
    Set-ItemProperty -LiteralPath $poolPath -Name enable32BitAppOnWin64 -Value $false
    Write-Ok "Application pool $AppPoolName (No Managed Code, ApplicationPoolIdentity)."
}

# --- content -----------------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($PhysicalPath, 'Take ownership, restrict ACL and deploy console files, web.config and config.js')) {
    # Directories above the site directory that do not exist yet are listed before the check: whoever creates them
    # meanwhile, they get an ACL of their own (owner Administrators), top-down, once the site directory exists.
    $newParents = @(Get-NewParent @($PhysicalPath))
    Assert-TrustedLocation -Path @($PhysicalPath) -Allow:$AllowWritableParent
    if (-not (Test-Path -LiteralPath $PhysicalPath)) { New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null }
    foreach ($dir in $newParents) {
        Protect-Directory -Root $dir -Grant @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX') -Allowed @{ 'S-1-5-18' = 'F'; 'S-1-5-32-544' = 'F'; 'S-1-5-32-545' = 'RX' }
    }
    # Before anything is written: Administrators take ownership, only SYSTEM/Administrators (full) and the pool
    # identity (read) keep access, and existing content is reset to inherit that (planted ACEs are removed).
    Protect-Directory -Root $PhysicalPath -Grant @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "IIS AppPool\${AppPoolName}:(OI)(CI)RX") -Allowed $SiteAcl
    # /MIR removes stale hashed assets of previous builds; web.config/config.js are written afterwards.
    $null = Invoke-Native -FilePath 'robocopy.exe' -ArgumentList @($DistDir, $PhysicalPath, '/MIR', '/XJ', '/XF', 'web.config',
        '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:2', '/W:2') -SuccessCodes @(0, 1, 2, 3, 4, 5, 6, 7)

    $webConfig = [System.IO.File]::ReadAllText($WebConfigTemplate)
    if ($ApiOrigin) {
        $before = $webConfig
        $webConfig = $webConfig.Replace("connect-src 'self';", "connect-src 'self' $ApiOrigin;")
        if ($webConfig -eq $before) { throw "Could not add $ApiOrigin to the CSP connect-src in web.config." }
    }
    if ($ApiProxyTarget) {
        # /api through ARR. HTTP_X_AEGIS_PROXY_AUTH replaces an X-Aegis-Proxy-Auth header sent by the client; the
        # https redirect rule runs first, so the proxied request always came in over https. IIS is the edge: an
        # X-Forwarded-For sent by the client is replaced by the address it connected from (REMOTE_ADDR), otherwise a
        # local user connecting through IIS on loopback would choose the client address the control-plane sees (ARR
        # appends REMOTE_ADDR once more: "a, a").
        $nl = if ($webConfig.Contains("`r`n")) { "`r`n" } else { "`n" }
        $rule = @(
            '<rule name="AegisApiReverseProxy" stopProcessing="true">',
            '          <match url="^api/(.*)" />',
            '          <serverVariables>',
            '            <set name="HTTP_X_FORWARDED_FOR" value="{REMOTE_ADDR}" />',
            '            <set name="HTTP_X_FORWARDED_PROTO" value="https" />',
            ('            <set name="HTTP_X_AEGIS_PROXY_AUTH" value="{0}" />' -f $proxySecret),
            '          </serverVariables>',
            ('          <action type="Rewrite" url="{0}/api/{{R:1}}" />' -f $ApiProxyTarget),
            '        </rule>') -join $nl
        $stream = @(
            '<location path="api/flows/stream">',
            '    <system.webServer>',
            '      <urlCompression doStaticCompression="false" doDynamicCompression="false" />',
            '    </system.webServer>',
            '  </location>') -join $nl
        foreach ($marker in @('<!-- aegis:api-proxy-rule -->', '<!-- aegis:api-proxy-location -->')) {
            if (-not $webConfig.Contains($marker)) { throw "web.config template lacks the marker $marker for -ApiProxyTarget." }
        }
        $webConfig = $webConfig.Replace('<!-- aegis:api-proxy-rule -->', $rule).Replace('<!-- aegis:api-proxy-location -->', $stream)
    }
    try { [void][xml]$webConfig } catch { throw "web.config is not well-formed XML: $($_.Exception.Message)" }
    [System.IO.File]::WriteAllText((Join-Path $PhysicalPath 'web.config'), $webConfig, (New-Object System.Text.UTF8Encoding($false)))

    $configJs = @(
        '// AegisProxy console runtime configuration - generated by Install-AegisConsole-IIS.ps1.',
        '// apiBaseUrl "" = API on the same origin; otherwise the API origin (control-plane: AEGIS_CORS_ORIGINS).',
        ('window.__AEGIS_CONFIG__ = {{ apiBaseUrl: "{0}" }};' -f $ApiBaseUrl)
    ) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $PhysicalPath 'config.js'), $configJs + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok "Console deployed to $PhysicalPath (apiBaseUrl: '$ApiBaseUrl')."
}

# --- site + bindings ---------------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($SiteName, 'Create/update site and HTTPS binding')) {
    $site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
    if (-not $site) {
        New-Website -Name $SiteName -PhysicalPath $PhysicalPath -ApplicationPool $AppPoolName `
            -Port $HttpsPort -HostHeader $HostName -Ssl -SslFlags 1 | Out-Null
        Write-Ok "Site $SiteName created."
    }
    else {
        Set-ItemProperty -LiteralPath "IIS:\Sites\$SiteName" -Name physicalPath -Value $PhysicalPath
        Set-ItemProperty -LiteralPath "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName
        if (-not (Get-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostName)) {
            New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostName -SslFlags 1
        }
    }
    # Certificate for the SNI binding (replaces an older certificate on re-run, e.g. after renewal).
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostName
    try { $binding.RemoveSslCertificate() } catch { Write-Verbose "No previous certificate on the binding: $_" }
    $binding.AddSslCertificate($CertificateThumbprint, 'My')
    if ($AddHttpBinding -and -not (Get-WebBinding -Name $SiteName -Protocol http -Port 80 -HostHeader $HostName)) {
        New-WebBinding -Name $SiteName -Protocol http -Port 80 -HostHeader $HostName
    }
    # Serve anonymous requests with the pool identity instead of IUSR (one principal to grant file access to).
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $SiteName `
        -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name 'userName' -Value ''
    Write-Ok ("Binding https://{0}:{1} (SNI) with certificate {2}{3}." -f $HostName, $HttpsPort, $CertificateThumbprint, $(if ($AddHttpBinding) { ', http:80 redirects to https' } else { '' }))
}

# --- ARR reverse proxy for /api (server-wide proxy settings, server variables allowed for this site only) ----
if ($ApiProxyTarget -and $PSCmdlet.ShouldProcess('IIS (applicationHost.config)', 'Enable the ARR proxy and allow the server variables of the /api rule')) {
    $apphost = 'MACHINE/WEBROOT/APPHOST'
    # responseBufferLimit 0: no buffering of the Server-Sent Events stream /api/flows/stream (live traffic).
    # includePortInXForwardedFor false: the control-plane expects plain addresses in X-Forwarded-For.
    $proxySettings = [ordered]@{ enabled = $true; preserveHostHeader = $true; reverseRewriteHostInResponseHeaders = $false
        responseBufferLimit = 0; includePortInXForwardedFor = $false }
    foreach ($name in $proxySettings.Keys) {
        Set-WebConfigurationProperty -PSPath $apphost -Filter 'system.webServer/proxy' -Name $name -Value $proxySettings[$name]
    }
    $allowedFilter = 'system.webServer/rewrite/allowedServerVariables'
    $allowed = @(Get-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter $allowedFilter -Name 'Collection' | ForEach-Object { "$($_.name)" })
    foreach ($var in @('HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_AEGIS_PROXY_AUTH')) {
        if ($allowed -notcontains $var) { Add-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter $allowedFilter -Name '.' -Value @{ name = $var } }
    }
    Write-Ok "ARR: /api proxied to $ApiProxyTarget with X-Aegis-Proxy-Auth from $ProxySecretFile (proxy enabled server-wide, no response buffering)."
}

# --- ACL: site directory readable only by the pool identity (set before the deployment, verified here) ----
if ($PSCmdlet.ShouldProcess($PhysicalPath, 'Verify ACL')) {
    $aclProblems = @(foreach ($path in @($PhysicalPath, (Join-Path $PhysicalPath 'index.html'), (Join-Path $PhysicalPath 'web.config'), (Join-Path $PhysicalPath 'config.js'))) {
            Get-AclProblem -Path $path -Allowed $SiteAcl
        })
    if ($aclProblems.Count) { throw ("ACL verification failed - the site was not started:`n  {0}" -f ($aclProblems -join "`n  ")) }
    Write-Ok "ACL verified: owner Administrators, SYSTEM/Administrators full, IIS AppPool\$AppPoolName read."
}

if ($PSCmdlet.ShouldProcess($SiteName, 'Start site')) {
    Start-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
    Start-Website -Name $SiteName
}

Write-Host ''
Write-Host '==================== AegisProxy console (IIS) ====================' -ForegroundColor Cyan
Write-Host "URL           : https://$HostName$(if ($HttpsPort -ne 443) { ":$HttpsPort" })/"
Write-Host "Site / pool   : $SiteName / $AppPoolName"
Write-Host "Content       : $PhysicalPath"
if ($ApiBaseUrl) {
    Write-Host "API           : $ApiBaseUrl (CSP connect-src extended)"
    Write-Host ("Control-plane : set AEGIS_CORS_ORIGINS=https://{0}{1}  (Install-AegisControlPlane.ps1 -CorsOrigins ...)" -f $HostName, $(if ($HttpsPort -ne 443) { ":$HttpsPort" }))
    Write-Host '                AEGIS_COOKIE_SAMESITE=none only if console and API are on different sites (registrable domains).'
}
elseif ($ApiProxyTarget) {
    Write-Host "API           : /api proxied by ARR to $ApiProxyTarget (X-Aegis-Proxy-Auth from $ProxySecretFile)"
    Write-Host ("Control-plane : AEGIS_PUBLIC_URL=https://{0}{1}, AEGIS_TRUSTED_PROXIES = the address IIS connects from (127.0.0.1/32 on this host)" -f
        $HostName, $(if ($HttpsPort -ne 443) { ":$HttpsPort" }))
    Write-Host '                and AEGIS_TRUSTED_PROXY_SECRET_FILE with this secret (Install-AegisControlPlane.ps1 sets both for -TrustedProxies 127.0.0.1/32).'
}
else {
    Write-Host 'API           : same origin - serve the control-plane under this host name or re-run with -ApiProxyTarget (ARR).'
}
Write-Host 'Upgrade       : rebuild the console and re-run this script with the same parameters (assets are mirrored, web.config and config.js regenerated).'
# robocopy's success codes 1-7 must not become the script's exit code.
exit 0
