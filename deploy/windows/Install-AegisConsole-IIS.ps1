#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hosts the AegisProxy web console (static SPA, frontend\dist) on IIS 10 with HTTPS.

.DESCRIPTION
    * installs the required IIS role services (Web-Server, Web-Static-Content, optionally Web-Http-Redirect)
    * verifies that the IIS URL Rewrite module is installed (required by web.config: SPA fallback, HTTPS redirect)
    * creates a dedicated application pool ("No Managed Code", ApplicationPoolIdentity) and site
    * mirrors the built console into the site directory, deploys web.config (security headers, caching rules)
    * writes config.js (window.__AEGIS_CONFIG__.apiBaseUrl) and, for a separate API origin, adds that origin
      to the Content-Security-Policy connect-src directive
    * binds HTTPS (SNI) with a certificate from Cert:\LocalMachine\My (by thumbprint)
    * with -ApiProxyTarget: proxies /api to the control-plane through Application Request Routing (same origin,
      no CORS) and authenticates IIS to it with the proxy secret (X-Aegis-Proxy-Auth)

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
    live-traffic stream, no port in X-Forwarded-For). Pass it on every run: a run without it deploys web.config
    without the rule. Excludes -ApiBaseUrl.

.PARAMETER ProxySecretFile
    The control-plane's AEGIS_TRUSTED_PROXY_SECRET_FILE, sent in X-Aegis-Proxy-Auth with -ApiProxyTarget: the
    control-plane trusts the X-Forwarded-For of a loopback peer only with it (every local account can connect from
    loopback). Default: %ProgramData%\AegisProxy\secrets\trusted-proxy-secret, which Install-AegisControlPlane.ps1
    creates on this host. For a control-plane on another host copy that file over a protected channel.

.PARAMETER CertificateThumbprint
    Thumbprint of the TLS server certificate in Cert:\LocalMachine\My (private key required).

.PARAMETER HostName
    Host name for the SNI binding, e.g. aegis-console.corp.example.

.PARAMETER AddHttpBinding
    Also bind port 80 - web.config redirects every http request to https.

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

    [switch]$SkipUrlRewriteCheck
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
$PhysicalPath = [System.IO.Path]::GetFullPath($PhysicalPath)
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
    $proxySecret = ([System.IO.File]::ReadAllText($ProxySecretFile)).Trim([char[]]@([char]0xFEFF, ' ', "`t", "`r", "`n"))
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
    if (-not (Test-Path -LiteralPath $PhysicalPath)) { New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null }
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
        # https redirect rule runs first, so the proxied request always came in over https.
        $nl = if ($webConfig.Contains("`r`n")) { "`r`n" } else { "`n" }
        $rule = @(
            '<rule name="AegisApiReverseProxy" stopProcessing="true">',
            '          <match url="^api/(.*)" />',
            '          <serverVariables>',
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
    foreach ($var in @('HTTP_X_FORWARDED_PROTO', 'HTTP_X_AEGIS_PROXY_AUTH')) {
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
