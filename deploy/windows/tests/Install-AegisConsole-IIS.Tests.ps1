#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
# Pester tests for Install-AegisConsole-IIS.ps1 against the fake Windows in FakeWindows.ps1 and the fake
# WebAdministration module in fakes\.

BeforeAll {
    . (Join-Path $PSScriptRoot 'FakeWindows.ps1')
    $script:Installer = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\Install-AegisConsole-IIS.ps1')).ProviderPath
    $script:SavedModulePath = $env:PSModulePath
    $env:PSModulePath = (Join-Path $PSScriptRoot 'fakes') + [System.IO.Path]::PathSeparator + $env:PSModulePath
    $script:Thumb = '3F2A9C0B11D4E5F60718293A4B5C6D7E8F901A2B'

    function Add-FakeCertificate {
        param([string]$Thumbprint, [string[]]$DnsNames, [bool]$HasPrivateKey = $true, [int]$ValidDays = 365)
        $global:FakeWin.Certificates[$Thumbprint] = [pscustomobject]@{
            Thumbprint = $Thumbprint; HasPrivateKey = $HasPrivateKey; NotAfter = $global:FakeWin.Now.AddDays($ValidDays)
            DnsNameList = @($DnsNames | ForEach-Object { [pscustomobject]@{ Unicode = $_ } })
        }
    }
}

AfterAll {
    $env:PSModulePath = $SavedModulePath
    Remove-Module -Name WebAdministration -Force -ErrorAction SilentlyContinue
}

Describe 'Install-AegisConsole-IIS.ps1' {
    BeforeEach {
        Initialize-FakeWindows -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        Add-FakeWindowsMock
        Mock Get-Item -ParameterFilter { "$LiteralPath" -like 'Cert:*' } {
            $global:FakeWin.Certificates[("$LiteralPath" -split '\\')[-1]]
        }
        Mock Test-Path -ParameterFilter { "$LiteralPath" -like 'IIS:*' } {
            $global:FakeWin.Iis.AppPools.ContainsKey(("$LiteralPath" -split '\\')[-1])
        }
        Mock Test-Path -ParameterFilter { "$LiteralPath" -like '*rewrite.dll' } { $global:FakeWin.RewriteDll }
        Mock Test-Path -ParameterFilter { "$LiteralPath" -like '*requestRouter.dll' } { $global:FakeWin.ArrDll }
        Mock Set-ItemProperty -ParameterFilter { "$LiteralPath" -like 'IIS:*' } {
            $parts = "$LiteralPath" -split '\\'
            $target = if ($parts[1] -eq 'AppPools') { $global:FakeWin.Iis.AppPools[$parts[2]] } else { $global:FakeWin.Iis.Sites[$parts[2]] }
            $target["$Name"] = $Value
        }

        $script:Dist = Join-Path $FakeWin.Root 'dist'
        New-Item -ItemType Directory -Path (Join-Path $Dist 'assets') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Dist 'index.html') -Value '<!doctype html><title>AegisProxy</title>'
        Set-Content -LiteralPath (Join-Path (Join-Path $Dist 'assets') 'index-abc123.js') -Value 'console.log(1)'
        Set-Content -LiteralPath (Join-Path $Dist 'config.js') -Value 'window.__AEGIS_CONFIG__ = { apiBaseUrl: "" };'
        $script:Site = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'inetpub\aegis-console'))
        Add-FakeCertificate -Thumbprint $Thumb -DnsNames @('aegis-console.corp.example')
        $script:Base = @{ DistDir = $Dist; HostName = 'aegis-console.corp.example'; CertificateThumbprint = $Thumb }
    }
    AfterEach { Remove-FakeWindows }

    Context 'validation' {
        It 'rejects <Name> = <Value>' -TestCases @(
            @{ Name = 'HostName'; Value = 'aegis console' }, @{ Name = 'HostName'; Value = 'a/b' },
            @{ Name = 'CertificateThumbprint'; Value = 'not-a-thumbprint' }, @{ Name = 'HttpsPort'; Value = 0 }
        ) {
            $p = $Base.Clone(); $p[$Name] = $Value
            { & $Installer @p } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }

        It 'requires a built console' {
            Remove-Item -LiteralPath (Join-Path $Dist 'index.html')
            { & $Installer @Base } | Should -Throw '*does not contain index.html*'
        }

        It 'rejects the API URL <Url>' -TestCases @(
            @{ Url = 'http://aegis-api.corp.example'; Message = '*must use https://*' },
            @{ Url = 'https://api.corp.example/;script-src *'; Message = '*URL characters only*' },
            @{ Url = 'https://api.corp.example/"};alert(1)//'; Message = '*URL characters only*' },
            @{ Url = 'javascript:alert(1)'; Message = '*URL characters only*' }
        ) {
            { & $Installer @Base -ApiBaseUrl $Url } | Should -Throw $Message
        }

        It 'allows an http API only with -AllowHttpApi' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ApiBaseUrl = 'http://aegis-api.lab:8081'; AllowHttpApi = $true })).ExitCode | Should -Be 0
        }

        It 'refuses a certificate that is <Case>' -TestCases @(
            @{ Case = 'missing'; Setup = { $global:FakeWin.Certificates.Clear() }; Message = '*not found in Cert:\LocalMachine\My*' },
            @{ Case = 'without private key'; Setup = { $global:FakeWin.Certificates[$Thumb].HasPrivateKey = $false }; Message = '*has no private key*' },
            @{ Case = 'expired'; Setup = { $global:FakeWin.Certificates[$Thumb].NotAfter = $global:FakeWin.Now.AddDays(-1) }; Message = '*expired*' }
        ) {
            & $Setup
            { & $Installer @Base } | Should -Throw $Message
        }

        It 'normalizes a thumbprint copied with spaces and lower case' {
            $spaced = (($Thumb.ToLowerInvariant() -split '(.{4})' | Where-Object { $_ }) -join ' ')
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ CertificateThumbprint = $spaced })).ExitCode | Should -Be 0
            $FakeWin.Iis.Sites['AegisConsole'].Bindings[0].Certificate | Should -Be "My\$Thumb"
        }

        It 'warns when the certificate does not cover the host name (wildcards cover one label)' {
            Add-FakeCertificate -Thumbprint $Thumb -DnsNames @('*.corp.example')
            (Invoke-Installer -Path $Installer -Parameters $Base).Output | Should -Not -Match 'do not cover'
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ HostName = 'a.b.corp.example' })).Output | Should -Match 'do not cover a.b.corp.example'
        }

        It 'stops when the URL Rewrite module is missing unless -SkipUrlRewriteCheck' {
            $FakeWin.RewriteDll = $false
            { & $Installer @Base } | Should -Throw '*URL Rewrite module missing*'
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipUrlRewriteCheck = $true })).Output | Should -Match 'HTTP 500.19'
        }

        It 'accepts URL Rewrite registered in the registry and reports its version' {
            $FakeWin.RewriteDll = $false
            $FakeWin.Registry['HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite'] = @{ Version = '7.2.2' }
            (Invoke-Installer -Path $Installer -Parameters $Base).Output | Should -Match 'URL Rewrite module found \(version 7.2.2\)'
        }
    }

    Context 'deployment with a separate API origin' {
        BeforeEach {
            New-Item -ItemType Directory -Path (Join-Path $Site 'assets') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $Site 'assets') 'index-old999.js') -Value 'stale'
            $script:Run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ApiBaseUrl = 'https://aegis-api.corp.example:8443/'; AddHttpBinding = $true })
        }

        It 'completes and prints the CORS setting for the control-plane' {
            $Run.ExitCode | Should -Be 0
            $Run.Output | Should -Match 'AEGIS_CORS_ORIGINS=https://aegis-console.corp.example '
        }

        It 'installs the IIS role services' {
            foreach ($f in @('Web-Server', 'Web-Static-Content', 'Web-Filtering', 'Web-Http-Logging')) { $FakeWin.Iis.Features | Should -Contain $f }
        }

        It 'creates a No-Managed-Code pool with ApplicationPoolIdentity' {
            $pool = $FakeWin.Iis.AppPools['AegisConsole']
            $pool.managedRuntimeVersion | Should -Be ''
            $pool.managedPipelineMode | Should -Be 'Integrated'
            $pool.'processModel.identityType' | Should -Be 'ApplicationPoolIdentity'
            $pool.'processModel.loadUserProfile' | Should -BeFalse
            $pool.enable32BitAppOnWin64 | Should -BeFalse
            $pool.State | Should -Be 'Started'
        }

        It 'mirrors the build (stale hashed assets removed)' {
            Test-Path -LiteralPath (Join-Path $Site 'index.html') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path (Join-Path $Site 'assets') 'index-abc123.js') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path (Join-Path $Site 'assets') 'index-old999.js') | Should -BeFalse
        }

        It 'adds only the API origin to the CSP connect-src and keeps web.config well-formed' {
            $text = [System.IO.File]::ReadAllText((Join-Path $Site 'web.config'))
            $xml = [xml]$text
            $csp = ($xml.configuration.'system.webServer'.httpProtocol.customHeaders.add | Where-Object name -eq 'Content-Security-Policy').value
            $csp | Should -Match "connect-src 'self' https://aegis-api.corp.example:8443;"
            $csp | Should -Match "frame-ancestors 'none'"
            [System.IO.File]::ReadAllBytes((Join-Path $Site 'web.config'))[0] | Should -Be ([byte][char]'<')
        }

        It 'writes config.js with the API base URL' {
            [System.IO.File]::ReadAllText((Join-Path $Site 'config.js')) | Should -Match ([regex]::Escape('window.__AEGIS_CONFIG__ = { apiBaseUrl: "https://aegis-api.corp.example:8443" };'))
        }

        It 'binds HTTPS with SNI and the certificate, plus an http binding that redirects' {
            $iisSite = $FakeWin.Iis.Sites['AegisConsole']
            $iisSite.physicalPath | Should -Be $Site
            $iisSite.applicationPool | Should -Be 'AegisConsole'
            $iisSite.State | Should -Be 'Started'
            $https = @($iisSite.Bindings | Where-Object Protocol -eq 'https')
            $https.Count | Should -Be 1
            $https[0].Port | Should -Be 443
            $https[0].HostHeader | Should -Be 'aegis-console.corp.example'
            $https[0].SslFlags | Should -Be 1
            $https[0].Certificate | Should -Be "My\$Thumb"
            @($iisSite.Bindings | Where-Object { $_.Protocol -eq 'http' -and $_.Port -eq 80 }).Count | Should -Be 1
        }

        It 'serves anonymous requests with the pool identity' {
            $FakeWin.Iis.Config['MACHINE/WEBROOT/APPHOST|AegisConsole|system.webServer/security/authentication/anonymousAuthentication|userName'] | Should -Be ''
        }

        It 'restricts the site directory to SYSTEM, Administrators and the pool identity (read)' {
            foreach ($path in @($Site, (Join-Path $Site 'index.html'), (Join-Path $Site 'web.config'))) {
                Get-PrincipalList $path | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'IIS AppPool\AegisConsole') -Because $path
            }
            (Get-FakeAccess (Join-Path $Site 'config.js'))['IIS AppPool\AegisConsole'] | Should -Be 'RX'
        }
    }

    Context 'same-origin deployment and re-runs' {
        It 'keeps the CSP unchanged and writes an empty apiBaseUrl' {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            [System.IO.File]::ReadAllText((Join-Path $Site 'web.config')) | Should -Be ([System.IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\iis\web.config')))
            [System.IO.File]::ReadAllText((Join-Path $Site 'config.js')) | Should -Match 'apiBaseUrl: ""'
        }

        It 'replaces the certificate on a re-run without duplicating bindings or the pool' {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $renewed = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333'
            Add-FakeCertificate -Thumbprint $renewed -DnsNames @('aegis-console.corp.example')
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ CertificateThumbprint = $renewed })).ExitCode | Should -Be 0
            $bindings = @($FakeWin.Iis.Sites['AegisConsole'].Bindings)
            $bindings.Count | Should -Be 1
            $bindings[0].Certificate | Should -Be "My\$renewed"
        }

        It 'uses a non-default HTTPS port' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ HttpsPort = 8443 })
            $run.ExitCode | Should -Be 0
            $FakeWin.Iis.Sites['AegisConsole'].Bindings[0].Port | Should -Be 8443
            $run.Output | Should -Match 'URL\s+: https://aegis-console.corp.example:8443/'
        }

        It 'changes nothing with -WhatIf' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ WhatIf = $true })).ExitCode | Should -Be 0
            $FakeWin.Iis.Sites.Count | Should -Be 0
            $FakeWin.Iis.AppPools.Count | Should -Be 0
            Test-Path -LiteralPath $Site | Should -BeFalse
        }
    }

    Context 'same-origin API through ARR (-ApiProxyTarget)' {
        BeforeEach {
            # Written by Install-AegisControlPlane.ps1 for -TrustedProxies 127.0.0.1/32.
            $script:SecretFile = Join-Path $env:ProgramData 'AegisProxy\secrets\trusted-proxy-secret'
            New-Item -ItemType Directory -Path (Split-Path -Parent $SecretFile) -Force | Out-Null
            $script:Secret = '0123456789abcdef' * 4
            [System.IO.File]::WriteAllText($SecretFile, "$Secret`n")
            $script:Proxied = Join-Parameters $Base @{ ApiProxyTarget = 'http://127.0.0.1:8081/'; AddHttpBinding = $true }
            $script:AppHost = 'MACHINE/WEBROOT/APPHOST'
        }

        It 'proxies /api over https only, with the proxy secret in X-Aegis-Proxy-Auth' {
            $run = Invoke-Installer -Path $Installer -Parameters $Proxied
            $run.ExitCode | Should -Be 0
            $xml = [xml][System.IO.File]::ReadAllText((Join-Path $Site 'web.config'))
            $rules = @($xml.configuration.'system.webServer'.rewrite.rules.rule)
            @($rules | ForEach-Object name) | Should -Be @('AegisHttpsRedirect', 'AegisApiReverseProxy', 'AegisSpaFallback') -Because 'http is redirected before the proxy rule'
            $rule = $rules[1]
            $rule.stopProcessing | Should -Be 'true'
            $rule.match.url | Should -Be '^api/(.*)'
            $rule.action.type | Should -Be 'Rewrite'
            $rule.action.url | Should -Be 'http://127.0.0.1:8081/api/{R:1}'
            $vars = @{}
            foreach ($set in @($rule.serverVariables.set)) {
                $set.GetAttribute('replace') | Should -Not -Be 'false' -Because 'a header sent by the client must be replaced'
                $vars[$set.name] = $set.value
            }
            $vars['HTTP_X_AEGIS_PROXY_AUTH'] | Should -Be $Secret
            $vars['HTTP_X_FORWARDED_PROTO'] | Should -Be 'https'
            $stream = @($xml.configuration.location | Where-Object path -eq 'api/flows/stream')
            $stream.Count | Should -Be 1
            $stream[0].'system.webServer'.urlCompression.doDynamicCompression | Should -Be 'false'
            [System.IO.File]::ReadAllText((Join-Path $Site 'config.js')) | Should -Match 'apiBaseUrl: ""'
            ($xml.configuration.'system.webServer'.httpProtocol.customHeaders.add | Where-Object name -eq 'Content-Security-Policy').value | Should -Match "connect-src 'self';"
            $run.Output | Should -Match 'AEGIS_TRUSTED_PROXIES = the address IIS connects from \(127.0.0.1/32'
        }

        It 'enables the ARR proxy server-wide and allows the server variables for this site only, once' {
            (Invoke-Installer -Path $Installer -Parameters $Proxied).ExitCode | Should -Be 0
            (Invoke-Installer -Path $Installer -Parameters $Proxied).ExitCode | Should -Be 0
            $expected = @{ enabled = $true; preserveHostHeader = $true; reverseRewriteHostInResponseHeaders = $false; responseBufferLimit = 0; includePortInXForwardedFor = $false }
            foreach ($name in $expected.Keys) {
                $FakeWin.Iis.Config["$AppHost||system.webServer/proxy|$name"] | Should -Be $expected[$name] -Because $name
            }
            $allowed = $FakeWin.Iis.Collections["$AppHost|AegisConsole|system.webServer/rewrite/allowedServerVariables"]
            @($allowed | ForEach-Object { $_.name }) | Should -Be @('HTTP_X_FORWARDED_PROTO', 'HTTP_X_AEGIS_PROXY_AUTH')
            @($FakeWin.Iis.Collections.Keys | Where-Object { $_ -like '*allowedServerVariables' }).Count | Should -Be 1 -Because 'only this site may set them'
        }

        It 'keeps the secret readable only by SYSTEM, Administrators and the pool, and never prints or passes it on a command line' {
            $run = Invoke-Installer -Path $Installer -Parameters $Proxied
            $run.ExitCode | Should -Be 0
            $webConfig = Join-Path $Site 'web.config'
            Get-PrincipalList $webConfig | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'IIS AppPool\AegisConsole')
            (Get-FakeAccess $webConfig)['IIS AppPool\AegisConsole'] | Should -Be 'RX'
            $run.Output | Should -Not -Match $Secret
            (@($FakeWin.Calls | ForEach-Object { "$($_.Command) $($_.Args -join ' ')" }) -join "`n") | Should -Not -Match $Secret
            [System.IO.File]::ReadAllText((Join-Path $Site 'config.js')) | Should -Not -Match $Secret
        }

        It 'removes the rule and the secret from web.config on a run without -ApiProxyTarget' {
            (Invoke-Installer -Path $Installer -Parameters $Proxied).ExitCode | Should -Be 0
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            [System.IO.File]::ReadAllText((Join-Path $Site 'web.config')) | Should -Be ([System.IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\iis\web.config')))
        }

        It 'proxies to a control-plane on another host with a copied secret (-ProxySecretFile)' {
            $copied = Join-Path $FakeWin.Root 'cp-secret.txt'
            [System.IO.File]::WriteAllText($copied, ('Zz9-._~+/=' * 4))
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ApiProxyTarget = 'https://aegis-cp.corp.example:8443'; ProxySecretFile = $copied })
            $run.ExitCode | Should -Be 0
            $rule = @(([xml][System.IO.File]::ReadAllText((Join-Path $Site 'web.config'))).configuration.'system.webServer'.rewrite.rules.rule)[1]
            $rule.action.url | Should -Be 'https://aegis-cp.corp.example:8443/api/{R:1}'
            (@($rule.serverVariables.set) | Where-Object name -eq 'HTTP_X_AEGIS_PROXY_AUTH').value | Should -Be ('Zz9-._~+/=' * 4)
        }

        It 'refuses the proxy target <Target>' -TestCases @(
            @{ Target = 'http://127.0.0.1:8081/api'; Message = '*must be the origin of the control-plane*' },
            @{ Target = 'http://127.0.0.1:8081"/><rule name="x'; Message = '*must be the origin of the control-plane*' },
            @{ Target = 'javascript:alert(1)'; Message = '*must be the origin of the control-plane*' },
            @{ Target = 'http://aegis-cp.corp.example:8081'; Message = '*must use https:// for a control-plane on another host*' },
            @{ Target = 'http://127.0.0.1.evil.example:8081'; Message = '*must use https:// for a control-plane on another host*' }
        ) {
            { & $Installer @Base -ApiProxyTarget $Target } | Should -Throw $Message
            $FakeWin.Iis.Sites.Count | Should -Be 0
        }

        It 'allows plain http to another host only with -AllowHttpApi' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ApiProxyTarget = 'http://aegis-cp.lab:8081'; AllowHttpApi = $true })).ExitCode | Should -Be 0
        }

        It 'does not combine -ApiProxyTarget with -ApiBaseUrl' {
            { & $Installer @Proxied -ApiBaseUrl 'https://aegis-api.corp.example' } | Should -Throw '*exclude each other*'
        }

        It 'requires the proxy secret of the control-plane (<Case>) before changing anything' -TestCases @(
            @{ Case = 'missing'; Value = $null; Message = '*Proxy secret*trusted-proxy-secret not found*Install-AegisControlPlane.ps1*-ProxySecretFile*' },
            @{ Case = 'too short'; Value = 'abc123'; Message = '*is not a valid proxy secret*' },
            @{ Case = 'quote'; Value = ('a' * 40) + '"'; Message = '*is not a valid proxy secret*' }
        ) {
            if ($null -eq $Value) { Remove-Item -LiteralPath $SecretFile } else { [System.IO.File]::WriteAllText($SecretFile, $Value) }
            { & $Installer @Proxied } | Should -Throw $Message
            $FakeWin.Iis.Sites.Count | Should -Be 0
            Test-Path -LiteralPath $Site | Should -BeFalse
        }

        It 'requires Application Request Routing (requestRouter.dll or its registry key)' {
            $FakeWin.ArrDll = $false
            { & $Installer @Proxied } | Should -Throw '*needs Application Request Routing 3.0*'
            $FakeWin.Iis.Sites.Count | Should -Be 0
            $FakeWin.Registry['HKLM:\SOFTWARE\Microsoft\IIS Extensions\Application Request Routing'] = @{ Version = '7.1.1952.0' }
            (Invoke-Installer -Path $Installer -Parameters $Proxied).ExitCode | Should -Be 0
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0 -Because 'without -ApiProxyTarget ARR is not needed'
        }
    }

    Context 'site directory that existed before' {
        BeforeEach {
            # Created by a non-administrator (the volume root lets users create folders), who granted users modify on
            # the directory and full control on a subfolder.
            New-Item -ItemType Directory -Path (Join-Path $Site 'assets') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $Site 'assets') 'index-abc123.js') -Value 'planted'
            $FakeWin.Acl[(Get-FakeFullPath $Site)] = @{ Protected = $false; Grants = [ordered]@{ '*S-1-5-32-545' = '(OI)(CI)M' } }
            $FakeWin.Acl[(Get-FakeFullPath (Join-Path $Site 'assets'))] = @{ Protected = $false; Grants = [ordered]@{ '*S-1-1-0' = '(OI)(CI)F' } }
            Set-FakeOwner -Path $Site -Sid 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        }

        It 'takes ownership and removes the planted ACEs before deploying, then verifies the ACL' {
            $run = Invoke-Installer -Path $Installer -Parameters $Base
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'ACL verified'
            $assets = Join-Path $Site 'assets'
            foreach ($path in @($Site, $assets, (Join-Path $assets 'index-abc123.js'), (Join-Path $Site 'index.html'))) {
                (Get-Acl -LiteralPath $path).GetOwner($null).Value | Should -Be 'S-1-5-32-544' -Because $path
                Get-PrincipalList $path | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'IIS AppPool\AegisConsole') -Because $path
                Test-FakeWritable -Path $path -Principals @('*S-1-5-32-545', '*S-1-1-0') | Should -BeFalse -Because $path
            }
            [System.IO.File]::ReadAllText((Join-Path $assets 'index-abc123.js')).Trim() | Should -Be 'console.log(1)'
            # The ACL is in place before robocopy writes the first file.
            $order = @($FakeWin.Calls | Where-Object { $_.Command -in @('icacls.exe', 'robocopy.exe') } | ForEach-Object Command)
            $order[0] | Should -Be 'icacls.exe'
            $order[-1] | Should -Be 'robocopy.exe'
        }

        It 'does not start the site when the resulting ACL cannot be verified' {
            $FakeWin.IcaclsIgnore = @('/remove')
            { & $Installer @Base } | Should -Throw '*ACL verification failed*: access for S-1-5-32-545 is not expected*'
            $FakeWin.Iis.Sites['AegisConsole'].State | Should -Be 'Stopped'
        }

        It 'refuses a junction in the site directory and leaves its target alone' {
            $target = Join-Path $FakeWin.Root 'elsewhere'
            New-Item -ItemType Directory -Path $target | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'x'
            New-Item -ItemType SymbolicLink -Path (Join-Path $Site 'static') -Target $target | Out-Null
            { & $Installer @Base } | Should -Throw '*Junctions/symbolic links and hard-linked files are not allowed in the site directory*static*'
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
            (Get-FakeCall 'robocopy.exe').Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $target 'keep.txt') | Should -BeTrue
        }

        It 'refuses a hard-linked file in the site directory' {
            $outside = Join-Path $FakeWin.Root 'outside.js'
            Set-Content -LiteralPath $outside -Value 'x'
            New-Item -ItemType HardLink -Path (Join-Path $Site 'assets\old.js') -Target $outside | Out-Null
            { & $Installer @Base } | Should -Throw '*hard-linked files are not allowed in the site directory*old.js (hard link)*'
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
        }

        It 'takes the directory over top-down with /L and without /T' {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $calls = @(Get-FakeCall 'icacls.exe')
            @($calls | Where-Object { $_.Args -notcontains '/L' }).Count | Should -Be 0
            @($calls | Where-Object { $_.Args -contains '/T' }).Count | Should -Be 0 -Because 'icacls /T follows junctions'
            $order = @($calls | ForEach-Object { Get-FakeFullPath $_.Args[0] })
            $assets = Join-Path $Site 'assets'
            $first = @($Site, $assets, (Join-Path $assets 'index-abc123.js')) | ForEach-Object { $order.IndexOf((Get-FakeFullPath $_)) }
            $first | Should -Not -Contain -1
            $first[0] | Should -BeLessThan $first[1]
            $first[1] | Should -BeLessThan $first[2]
        }

        It 'refuses a symbolic link that the owner of a subdirectory swaps in while the installer runs, and leaves its target alone' {
            $target = Join-Path $FakeWin.Root 'victim'
            New-Item -ItemType Directory -Path $target | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'x'
            # Everyone may still write to assets until the installer has taken it over.
            $race = @{ Done = $false; Dir = (Get-FakeFullPath (Join-Path $Site 'assets')); Link = (Join-Path $Site 'assets\link'); Target = $target }
            $FakeWin.IcaclsHook = {
                param($a)
                if (-not $race.Done -and (Get-FakeFullPath $a[0]) -eq $race.Dir) {
                    $race.Done = $true
                    New-Item -ItemType SymbolicLink -Path $race.Link -Target $race.Target | Out-Null
                }
            }.GetNewClosure()
            { & $Installer @Base } | Should -Throw '*Junction/symbolic link in the site directory*link*'
            $race.Done | Should -BeTrue
            $FakeWin.Owner.ContainsKey((Get-FakeFullPath $target)) | Should -BeFalse
            $FakeWin.Acl.ContainsKey((Get-FakeFullPath $target)) | Should -BeFalse
            (Get-FakeCall 'robocopy.exe').Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $target 'keep.txt') | Should -BeTrue
        }
    }
}
