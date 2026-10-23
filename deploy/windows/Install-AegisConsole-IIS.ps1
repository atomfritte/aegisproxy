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

    The site directory is readable only by SYSTEM, Administrators and the application pool identity; anonymous
    requests are served with the pool identity (no IUSR access needed).

    If the console is served by the control-plane itself (AEGIS_UI_DIR) you do not need IIS at all.

.PARAMETER DistDir
    Built console (npm --prefix frontend run build -> frontend\dist). Default: ..\..\frontend\dist.

.PARAMETER ApiBaseUrl
    Origin of the control-plane API when it is NOT reachable under the console's origin, e.g.
    https://aegis-api.corp.example. Empty (default) = same origin (control-plane behind the same host name, or
    the optional ARR /api rule in web.config). The control-plane then needs AEGIS_CORS_ORIGINS=<console origin>.

.PARAMETER CertificateThumbprint
    Thumbprint of the TLS server certificate in Cert:\LocalMachine\My (private key required).

.PARAMETER HostName
    Host name for the SNI binding, e.g. aegis-console.corp.example.

.PARAMETER AddHttpBinding
    Also bind port 80 - web.config redirects every http request to https.

.EXAMPLE
    .\Install-AegisConsole-IIS.ps1 -HostName aegis-console.corp.example -CertificateThumbprint 3F2A...C9 `
        -ApiBaseUrl https://aegis-api.corp.example -AddHttpBinding

.NOTES
    Download URL Rewrite 2.1: https://www.iis.net/downloads/microsoft/url-rewrite
    Optional same-origin API: Application Request Routing 3.0 (https://www.iis.net/downloads/microsoft/application-request-routing)
    and the commented rule in iis\web.config.
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

# --- validation --------------------------------------------------------------------------------------
$CertificateThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
$DistDir = [System.IO.Path]::GetFullPath($DistDir)
if (-not (Test-Path -LiteralPath (Join-Path $DistDir 'index.html'))) {
    throw "$DistDir does not contain index.html. Build the console first: npm --prefix frontend ci; npm --prefix frontend run build"
}
if (-not (Test-Path -LiteralPath $WebConfigTemplate)) { throw "web.config template not found: $WebConfigTemplate" }

$ApiBaseUrl = $ApiBaseUrl.Trim().TrimEnd('/')
if ($ApiBaseUrl) {
    # Same rules as frontend/docker/40-aegis-config.sh: URL characters only (embedded verbatim in JS and CSP).
    if ($ApiBaseUrl -notmatch '^https?://[A-Za-z0-9:/._%-]+$') { throw '-ApiBaseUrl must be an http(s) URL consisting of URL characters only.' }
    if ($ApiBaseUrl -notmatch '^https://' -and -not $AllowHttpApi) { throw '-ApiBaseUrl must use https:// (pass -AllowHttpApi for lab setups).' }
    $uri = [System.Uri]$ApiBaseUrl
    $ApiOrigin = $uri.GetLeftPart([System.UriPartial]::Authority)
}
else { $ApiOrigin = '' }

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
if ($PSCmdlet.ShouldProcess($PhysicalPath, 'Deploy console files, web.config and config.js')) {
    if (-not (Test-Path -LiteralPath $PhysicalPath)) { New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null }
    # /MIR removes stale hashed assets of previous builds; web.config/config.js are written afterwards.
    $null = Invoke-Native -FilePath 'robocopy.exe' -ArgumentList @($DistDir, $PhysicalPath, '/MIR', '/XF', 'web.config',
        '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:2', '/W:2') -SuccessCodes @(0, 1, 2, 3, 4, 5, 6, 7)

    $webConfig = [System.IO.File]::ReadAllText($WebConfigTemplate)
    if ($ApiOrigin) {
        $before = $webConfig
        $webConfig = $webConfig.Replace("connect-src 'self';", "connect-src 'self' $ApiOrigin;")
        if ($webConfig -eq $before) { throw "Could not add $ApiOrigin to the CSP connect-src in web.config." }
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

# --- ACL: site directory readable only by the pool identity ------------------------------------------
if ($PSCmdlet.ShouldProcess($PhysicalPath, 'Restrict ACL')) {
    $null = Invoke-Native -FilePath 'icacls.exe' -ArgumentList @($PhysicalPath, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "IIS AppPool\${AppPoolName}:(OI)(CI)RX", '/Q')
    Write-Ok "ACL: SYSTEM/Administrators full, IIS AppPool\$AppPoolName read."
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
else {
    Write-Host 'API           : same origin - serve the control-plane under this host name or enable the ARR /api rule in web.config.'
}
Write-Host 'Upgrade       : rebuild the console and re-run this script (assets are mirrored, config.js regenerated).'
