#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
# Pester tests for Install-AegisControlPlane.ps1 against the fake Windows in FakeWindows.ps1.

BeforeAll {
    . (Join-Path $PSScriptRoot 'FakeWindows.ps1')
    $script:Installer = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\Install-AegisControlPlane.ps1')).ProviderPath
    $script:ServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\AegisControlPlane'
    $script:EventLogKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\AegisControlPlane'

    function Get-SecretValues {
        # Every secret value the installation holds (to prove none of them leaks into env/registry/output).
        Get-ChildItem -LiteralPath $script:SecretsDir -File | Where-Object { $_.Name -notlike 'tls-cert.pem' } |
            ForEach-Object { ([System.IO.File]::ReadAllText($_.FullName)).Trim() } | Where-Object { $_ }
    }
}

Describe 'Install-AegisControlPlane.ps1' {
    BeforeEach {
        Initialize-FakeWindows -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        Add-FakeWindowsMock
        $script:InstallDir = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'AegisProxy\control-plane'))
        $script:DataRoot = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramData 'AegisProxy'))
        $script:SecretsDir = Join-Path $DataRoot 'secrets'
        $script:CertsDir = Join-Path $DataRoot 'certs'
        $script:ExePath = Join-Path $InstallDir 'aegis-control-plane.exe'
        Register-FakeExecutable -Path $ExePath -Function FakeControlPlaneExe
        $script:Binary = Join-Path $FakeWin.Root 'dist/aegis-control-plane.exe'
        New-FakeBinary -Path $Binary
        $script:Base = @{ BinaryPath = $Binary; PublicUrl = 'https://aegis.corp.example:8081' }
    }
    AfterEach { Remove-FakeWindows }

    Context 'parameter validation' {
        It 'declares PublicUrl mandatory for installs and Uninstall as its own parameter set' {
            $cmd = Get-Command -Name $Installer
            $publicUrl = $cmd.Parameters['PublicUrl'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $publicUrl.Mandatory | Should -BeTrue
            $publicUrl.ParameterSetName | Should -Be 'Install'
            @($cmd.ParameterSets.Name | Sort-Object) | Should -Be @('Install', 'Uninstall')
            ($cmd.ScriptBlock.Ast.ParamBlock.Attributes.NamedArguments | Where-Object ArgumentName -eq 'DefaultParameterSetName').Argument.Value | Should -Be 'Install'
        }

        It 'rejects <Url> as PublicUrl' -TestCases @(
            @{ Url = 'aegis.corp.example' }, @{ Url = 'ftp://aegis.corp.example' }, @{ Url = 'https://' }
        ) {
            { & $Installer -BinaryPath $Binary -PublicUrl $Url } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }

        It 'rejects an unknown storage backend and out-of-range ports' {
            { & $Installer @Base -Storage mysql } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
            { & $Installer @Base -Port 0 } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
            { & $Installer @Base -Port 70000 } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }

        It 'does not combine -Uninstall with install parameters' {
            { & $Installer -Uninstall -PublicUrl 'https://x.example' } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }

        It 'requires -TlsCertFile and -TlsKeyFile together' {
            { & $Installer @Base -TlsCertFile (Join-Path $FakeWin.Root 'c.pem') } | Should -Throw '*must be given together*'
        }

        It 'requires -DatabaseUrl for the first PostgreSQL installation and validates its scheme' {
            { & $Installer @Base -Storage postgres } | Should -Throw '*requires -DatabaseUrl*'
            { & $Installer @Base -Storage postgres -DatabaseUrl 'mysql://u:p@db/aegis' -SkipFirewall } | Should -Throw '*must start with postgres*'
        }

        It 'refuses the plain secret <Name> in -ExtraEnvironment (registry environment is readable by local users)' -TestCases @(
            @{ Name = 'AEGIS_JWT_SECRET' }, @{ Name = 'AEGIS_DATAPLANE_KEY' }, @{ Name = 'AEGIS_BOOTSTRAP_ADMIN_PASSWORD' },
            @{ Name = 'AEGIS_METRICS_TOKEN' }, @{ Name = 'AEGIS_DATABASE_URL' }, @{ Name = 'AEGIS_ENCRYPTION_KEY' },
            @{ Name = 'AEGIS_ENCRYPTION_KEY_PREVIOUS' }, @{ Name = 'AEGIS_TRUSTED_PROXY_SECRET' }
        ) {
            { & $Installer @Base -ExtraEnvironment @{ $Name = 'x' * 40 } } | Should -Throw "*$Name must not be passed as plain value*"
            $FakeWin.Services.Count | Should -Be 0
        }

        It 'rejects invalid variable names and control characters' {
            { & $Installer @Base -ExtraEnvironment @{ 'AEGIS=X' = '1' } } | Should -Throw '*Invalid environment variable name*'
            { & $Installer @Base -ExtraEnvironment @{ 'AEGIS X' = '1' } } | Should -Throw '*Invalid environment variable name*'
            { & $Installer @Base -ExtraEnvironment @{ AEGIS_X = "a`nAEGIS_DEMO_MODE=true" } } | Should -Throw '*control characters*'
            { & $Installer -BinaryPath $Binary -PublicUrl "https://aegis.example/`r" } | Should -Throw '*control characters*'
        }

        It 'rejects a bootstrap password shorter than 12 characters without echoing it' {
            $pw = ConvertTo-SecureString 'Short-Pw-1' -AsPlainText -Force
            $err = { & $Installer @Base -BootstrapAdminPassword $pw -SkipFirewall } | Should -Throw '*at least 12 characters*' -PassThru
            "$err" | Should -Not -Match 'Short-Pw-1'
        }

        It 'rejects a binary that is not a Windows executable' {
            [System.IO.File]::WriteAllText($Binary, '#!/bin/sh')
            { & $Installer @Base } | Should -Throw '*is not a Windows executable*'
        }

        It 'stops a binary that does not answer "version" (outdated build) and keeps the service untouched' {
            $FakeWin.VersionHangs = $true
            { & $Installer @Base } | Should -Throw "*did not answer 'version'*"
            $FakeWin.VersionKilled | Should -BeTrue
            (Get-FakeCall 'Stop-Service').Count | Should -Be 0
        }

        It 'fails when neither a new nor an installed binary exists' {
            { & $Installer -BinaryPath (Join-Path $FakeWin.Root 'missing.exe') -PublicUrl 'https://aegis.example' } | Should -Throw '*Binary not found*'
        }
    }

    Context 'installation sources' {
        BeforeEach {
            # A release that an administrator copied into C:\Install\AegisProxy on a client edition: C:\Install, created
            # in the volume root, inherits Modify for authenticated users.
            $script:InstallFolder = Join-Path $env:SystemDrive 'Install'
            $script:ReleaseBinary = Join-Path $InstallFolder 'AegisProxy\aegis-control-plane.exe'
            New-FakeBinary -Path $ReleaseBinary
            $script:Ui = Join-Path $InstallFolder 'AegisProxy\frontend\dist'
            New-Item -ItemType Directory -Path (Join-Path $Ui 'assets') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Ui 'index.html') -Value '<!doctype html>'
            Set-Content -LiteralPath (Join-Path $Ui 'assets\index-abc123.js') -Value 'console.log(1)'
            $script:Params = Join-Parameters $Base @{ BinaryPath = $ReleaseBinary; UiDir = $Ui; SkipFirewall = $true }
        }

        It 'refuses a release that non-administrators can change before it runs the binary' {
            $err = { & $Installer @Params } | Should -Throw '*Non-administrators can change installation sources*-AllowWritableSource*' -PassThru
            foreach ($path in @($InstallFolder, $ReleaseBinary, (Join-Path $Ui 'assets\index-abc123.js'))) {
                "$err" | Should -Match ([regex]::Escape("$(Get-FakeFullPath $path) (Authenticated Users)"))
            }
            "$err" | Should -Not -Match ([regex]::Escape("$(Get-FakeFullPath $env:SystemDrive) (")) -Because 'users may create folders in the volume root, but not change those of others'
            "$err" | Should -Match ([regex]::Escape("icacls `"$InstallFolder`" /inheritance:r /grant:r `"*S-1-5-32-544:(OI)(CI)F`" `"*S-1-5-18:(OI)(CI)F`""))
            (Get-FakeCall 'Start-Process').Count | Should -Be 0
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
            $FakeWin.Services.Count | Should -Be 0
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
        }

        It 'installs from the release once its folder in the volume root has its own ACL (Windows guide, section 2)' {
            icacls.exe $InstallFolder /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
            $run = Invoke-Installer -Path $Installer -Parameters $Params
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Not -Match 'Non-administrators can change'
            Get-FakeFullPath ((Get-FakeCall 'Start-Process')[0].Args[0]) | Should -Be (Get-FakeFullPath $ReleaseBinary)
        }

        It 'continues with -AllowWritableSource and repeats the warning' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Params @{ AllowWritableSource = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'Non-administrators can change installation sources'
            $run.Output | Should -Match 'Continuing because of -AllowWritableSource'
        }

        It 'refuses a protected release when <Case>' -TestCases @(
            @{ Case = 'another account owns the binary'; Relative = 'AegisProxy\aegis-control-plane.exe'; Owner = 'S-1-5-21-111-222-333-1007'; Expect = 'owner S-1-5-21-111-222-333-1007' },
            @{ Case = 'users may change a script of the console'; Relative = 'AegisProxy\frontend\dist\assets\index-abc123.js'; Grantee = '*S-1-5-32-545'; Ace = 'M'; Expect = 'Users' },
            @{ Case = 'users get write access to new files of the console (inherit-only)'; Relative = 'AegisProxy\frontend\dist'; Grantee = '*S-1-5-32-545'; Ace = '(OI)(IO)W'; Expect = 'Users' },
            @{ Case = 'everyone may rename the release folder'; Relative = 'AegisProxy'; Grantee = '*S-1-1-0'; Ace = '(D)'; Expect = 'Everyone' },
            @{ Case = 'users may delete entries of the protected folder'; Relative = ''; Grantee = '*S-1-5-32-545'; Ace = '(DC)'; Expect = 'Users' },
            @{ Case = 'a group may change the permissions of a folder above the release'; Relative = '..'; Grantee = '*S-1-5-21-111-222-333-1105'; Ace = '(WDAC)'; Expect = 'S-1-5-21-111-222-333-1105' }
        ) {
            icacls.exe $InstallFolder /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
            $weak = Get-FakeFullPath $(if ($Relative -eq '..') { $env:SystemDrive } elseif ($Relative) { Join-Path $InstallFolder $Relative } else { $InstallFolder })
            if ($Owner) { $FakeWin.Owner[$weak] = $Owner }
            else {
                if (-not $FakeWin.Acl.ContainsKey($weak)) { $FakeWin.Acl[$weak] = @{ Protected = $false; Grants = [ordered]@{} } }
                $FakeWin.Acl[$weak].Grants[$Grantee] = $Ace
            }
            $err = { & $Installer @Params } | Should -Throw '*Non-administrators can change installation sources*' -PassThru
            "$err" | Should -Match ([regex]::Escape("$weak ($Expect)"))
            (Get-FakeCall 'Start-Process').Count | Should -Be 0
        }

        It 'refuses a junction on the way to the release (its target is not checked)' {
            $elsewhere = Join-Path $FakeWin.Root 'elsewhere'
            New-Item -ItemType Directory -Path $elsewhere | Out-Null
            Move-Item -LiteralPath (Join-Path $InstallFolder 'AegisProxy') -Destination (Join-Path $elsewhere 'AegisProxy')
            icacls.exe $InstallFolder /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
            New-Item -ItemType SymbolicLink -Path (Join-Path $InstallFolder 'AegisProxy') -Target (Join-Path $elsewhere 'AegisProxy') | Out-Null
            $err = { & $Installer @Params } | Should -Throw '*Non-administrators can change installation sources*' -PassThru
            "$err" | Should -Match ([regex]::Escape("$(Get-FakeFullPath (Join-Path $InstallFolder 'AegisProxy')) (junction/symbolic link, its target is not checked)"))
        }
    }

    Context 'directories above the program and data directories' {
        BeforeEach {
            # C:\Tools, created in the volume root of a client edition: it inherits Modify for authenticated users, who may
            # therefore rename it and put another C:\Tools\AegisProxy in its place.
            $script:Tools = Join-Path $env:SystemDrive 'Tools'
            New-Item -ItemType Directory -Path $Tools | Out-Null
            $script:CustomInstall = [System.IO.Path]::GetFullPath((Join-Path $Tools 'AegisProxy\control-plane'))
            $script:CustomData = [System.IO.Path]::GetFullPath((Join-Path $Tools 'AegisData'))
            Register-FakeExecutable -Path (Join-Path $CustomInstall 'aegis-control-plane.exe') -Function FakeControlPlaneExe
            $script:Custom = @{ InstallDir = @{ InstallDir = $CustomInstall }; DataRoot = @{ DataRoot = $CustomData } }
        }

        It 'refuses a -<Parameter> below a directory that non-administrators may rename, before it changes or runs anything' -TestCases @(
            @{ Parameter = 'InstallDir' }, @{ Parameter = 'DataRoot' }
        ) {
            $p = Join-Parameters $Base $Custom[$Parameter]
            $err = { & $Installer @p } | Should -Throw '*Non-administrators can rename or replace directories above the directories this script installs into*-AllowWritableParent*' -PassThru
            "$err" | Should -Match ([regex]::Escape("$(Get-FakeFullPath $Tools) (Authenticated Users)"))
            "$err" | Should -Not -Match ([regex]::Escape("$(Get-FakeFullPath $env:SystemDrive) (")) -Because 'users may create folders in the volume root, not rename those of others'
            "$err" | Should -Match ([regex]::Escape("icacls `"$(Get-FakeFullPath $Tools)`" /inheritance:r /grant:r `"*S-1-5-32-544:(OI)(CI)F`" `"*S-1-5-18:(OI)(CI)F`" `"*S-1-5-32-545:(OI)(CI)RX`""))
            (Get-FakeCall 'Start-Process').Count | Should -Be 0
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
            $FakeWin.Services.Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $Tools 'AegisProxy') | Should -BeFalse
            Test-Path -LiteralPath $CustomData | Should -BeFalse
        }

        It 'installs into -<Parameter> once that directory has an ACL that only administrators control (the commands of the message)' -TestCases @(
            @{ Parameter = 'InstallDir' }, @{ Parameter = 'DataRoot' }
        ) {
            icacls.exe $Tools /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
            icacls.exe $Tools /setowner '*S-1-5-32-544' /L | Out-Null
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters (Join-Parameters $Base $Custom[$Parameter]) @{ SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Not -Match 'rename or replace directories above'
        }

        It 'continues with -AllowWritableParent and repeats the warning' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $CustomInstall; AllowWritableParent = $true; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'Non-administrators can rename or replace directories above'
            $run.Output | Should -Match 'Continuing because of -AllowWritableParent'
        }

        It 'refuses -InstallDir below a protected directory when <Case>' -TestCases @(
            @{ Case = 'a non-administrator owns a directory above'; Relative = 'AegisProxy'; Owner = 'S-1-5-21-111-222-333-1007'; Expect = 'owner S-1-5-21-111-222-333-1007' },
            @{ Case = 'users may rename the directory above'; Relative = 'AegisProxy'; Grantee = '*S-1-5-32-545'; Ace = '(D)'; Expect = 'Users' },
            @{ Case = 'users may delete entries of a directory above'; Relative = ''; Grantee = '*S-1-5-32-545'; Ace = '(DC)'; Expect = 'Users' },
            @{ Case = 'everyone may change the permissions of a directory above'; Relative = 'AegisProxy'; Grantee = '*S-1-1-0'; Ace = '(WDAC)'; Expect = 'Everyone' },
            @{ Case = 'a group may take ownership of a directory above'; Relative = ''; Grantee = '*S-1-5-21-111-222-333-1105'; Ace = '(WO)'; Expect = 'S-1-5-21-111-222-333-1105' },
            @{ Case = 'a directory above passes Modify on to the existing one below it'; Relative = ''; Grantee = '*S-1-5-11'; Ace = '(CI)(IO)M'; Expect = 'Authenticated Users'; At = 'AegisProxy' }
        ) {
            icacls.exe $Tools /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $Tools 'AegisProxy') | Out-Null
            $weak = Get-FakeFullPath $(if ($Relative) { Join-Path $Tools $Relative } else { $Tools })
            if ($Owner) { $FakeWin.Owner[$weak] = $Owner }
            else {
                if (-not $FakeWin.Acl.ContainsKey($weak)) { $FakeWin.Acl[$weak] = @{ Protected = $false; Grants = [ordered]@{} } }
                $FakeWin.Acl[$weak].Grants[$Grantee] = $Ace
            }
            $reported = if ($At) { Get-FakeFullPath (Join-Path $Tools $At) } else { $weak }
            $err = { & $Installer @Base -InstallDir $CustomInstall } | Should -Throw '*Non-administrators can rename or replace directories above*' -PassThru
            "$err" | Should -Match ([regex]::Escape("$reported ($Expect)"))
            if ($At) { "$err" | Should -Not -Match ([regex]::Escape("$weak (")) -Because 'an inherit-only ACE does not apply to the directory itself' }
            (Get-FakeCall 'Start-Process').Count | Should -Be 0
            $FakeWin.Services.Count | Should -Be 0
        }

        It 'refuses a junction above -InstallDir (its target is not checked)' {
            icacls.exe $Tools /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
            $elsewhere = Join-Path $FakeWin.Root 'elsewhere'
            New-Item -ItemType Directory -Path $elsewhere | Out-Null
            New-Item -ItemType SymbolicLink -Path (Join-Path $Tools 'AegisProxy') -Target $elsewhere | Out-Null
            $err = { & $Installer @Base -InstallDir $CustomInstall } | Should -Throw '*Non-administrators can rename or replace directories above*' -PassThru
            "$err" | Should -Match ([regex]::Escape("$(Get-FakeFullPath (Join-Path $Tools 'AegisProxy')) (junction/symbolic link, its target is not checked)"))
            @(Get-ChildItem -LiteralPath $elsewhere -Force).Count | Should -Be 0
        }

        It 'accepts a directory above that lets users create folders in it (Windows Server volume root)' {
            icacls.exe $Tools /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 'BUILTIN\Users:(CI)(AD)' | Out-Null
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $CustomInstall; SkipFirewall = $true })).ExitCode | Should -Be 0
        }

        It 'creates missing directories above -InstallDir and -DataRoot with an ACL of their own, top-down' {
            $install = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'New\Deep\control-plane'))
            $data = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'NewData\aegis'))
            Register-FakeExecutable -Path (Join-Path $install 'aegis-control-plane.exe') -Function FakeControlPlaneExe
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $install; DataRoot = $data; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $created = @((Join-Path $env:SystemDrive 'New'), (Join-Path $env:SystemDrive 'New\Deep'), (Join-Path $env:SystemDrive 'NewData'))
            foreach ($dir in $created) {
                (Get-Acl -LiteralPath $dir).GetOwner($null).Value | Should -Be 'S-1-5-32-544' -Because $dir
                Get-PrincipalList $dir | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', '*S-1-5-32-545') -Because $dir
                Test-FakeWritable $dir | Should -BeFalse -Because "$dir would inherit Modify for authenticated users from the volume root"
            }
            $order = @(Get-FakeCall 'icacls.exe' | ForEach-Object { Get-FakeFullPath $_.Args[0] })
            $order.IndexOf((Get-FakeFullPath $created[0])) | Should -BeLessThan $order.IndexOf((Get-FakeFullPath $created[1]))
            $order.IndexOf((Get-FakeFullPath $created[1])) | Should -BeLessThan $order.IndexOf((Get-FakeFullPath $install))
            # A re-run finds them protected.
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $install; DataRoot = $data; SkipFirewall = $true })).ExitCode | Should -Be 0
        }

        It 'gives %ProgramFiles%\AegisProxy, created by the first installation, an ACL of its own' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            $parent = Split-Path -Parent $InstallDir
            (Get-Acl -LiteralPath $parent).GetOwner($null).Value | Should -Be 'S-1-5-32-544'
            Get-PrincipalList $parent | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', '*S-1-5-32-545')
        }

        It 'takes over a directory above that a non-administrator creates after the check' {
            $install = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'Race\control-plane'))
            Register-FakeExecutable -Path (Join-Path $install 'aegis-control-plane.exe') -Function FakeControlPlaneExe
            $global:RaceDir = Join-Path $env:SystemDrive 'Race'
            # The binary's version probe runs after the check: a local user creates C:\Race meanwhile and owns it.
            Mock Start-Process -ParameterFilter { @($ArgumentList) -contains 'version' } {
                New-Item -ItemType Directory -Path $global:RaceDir | Out-Null
                $global:FakeWin.Owner[(Get-FakeFullPath $global:RaceDir)] = 'S-1-5-21-111-222-333-1007'
                $global:FakeWin.Acl[(Get-FakeFullPath $global:RaceDir)] = @{ Protected = $false; Grants = [ordered]@{ '*S-1-5-21-111-222-333-1007' = '(OI)(CI)F' } }
                [System.IO.File]::WriteAllText($RedirectStandardOutput, "2.1.0-test`n")
                $proc = [pscustomobject]@{ ExitCode = 0 }
                Add-Member -InputObject $proc -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true }
                $proc
            }
            try { (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $install; SkipFirewall = $true })).ExitCode | Should -Be 0 }
            finally { Remove-Variable -Name RaceDir -Scope Global }
            (Get-Acl -LiteralPath (Join-Path $env:SystemDrive 'Race')).GetOwner($null).Value | Should -Be 'S-1-5-32-544'
            Get-PrincipalList (Join-Path $env:SystemDrive 'Race') | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', '*S-1-5-32-545')
            @(Get-FakeCall 'icacls.exe' | Where-Object { $_.Args[1] -eq '/remove' -and $_.Args[2] -eq '*S-1-5-21-111-222-333-1007' }).Count | Should -Be 1 -Because "the local user's ACE is removed"
        }
    }

    Context 'fresh installation' {
        BeforeEach {
            $script:Password = 'Correct-Horse-Battery-2026'
            $script:Run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{
                    ProxyAddress = 'proxy.corp.example:8080'; GenerateMetricsToken = $true
                    BootstrapAdminPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
                    TrustedProxies = @('10.0.0.10/32', '10.0.0.11/32'); CorsOrigins = @('https://console.corp.example')
                    ExtraEnvironment = @{ AEGIS_INTERNAL_DOMAINS = '.corp.example,.local' }
                    FirewallRemoteAddress = @('10.20.0.0/16')
                })
            $script:SvcEnv = Get-RegistryEnvironment 'AegisControlPlane'
        }

        It 'completes with exit code 0 and reports the CA fingerprint' {
            $Run.ExitCode | Should -Be 0
            $Run.Output | Should -Match 'Control-plane is healthy'
            $fp = ($Run.Output | Select-String -Pattern 'Root CA SHA-256\s+:\s+(?<fp>[0-9A-F:]{95})').Matches[0].Groups['fp'].Value
            $der = [System.IO.File]::ReadAllBytes((Join-Path $CertsDir 'aegis-enterprise-ca.der'))
            $fp | Should -Be ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($der))).Replace('-', ':')
        }

        It 'installs the binary and registers an automatic service under its virtual account with least privilege' {
            Test-Path -LiteralPath $ExePath | Should -BeTrue
            $svc = $FakeWin.Services['AegisControlPlane']
            $svc.PathName | Should -Be ('"{0}" service' -f $ExePath)
            $svc.PathName | Should -Match '^"[^"]+\.exe" service$' -Because 'the quoted path survives spaces in Program Files; "service" selects the SCM dispatcher'
            $svc.StartType | Should -Be 'Automatic'
            $svc.ObjectName | Should -Be 'NT SERVICE\AegisControlPlane'
            $svc.SidType | Should -Be 'unrestricted'
            $svc.Privileges | Should -Be 'SeChangeNotifyPrivilege'
            $svc.FailureActions | Should -Be 'restart/5000/restart/5000/restart/30000'
            $svc.FailureReset | Should -Be '86400'
            $svc.FailureFlag | Should -Be '1'
            $svc.Status | Should -Be 'Running'
        }

        It 'generates three distinct 256-bit secrets as UTF-8 files without BOM' {
            $values = foreach ($name in @('jwt.key', 'dataplane.key', 'encryption.key')) {
                $bytes = [System.IO.File]::ReadAllBytes((Join-Path $SecretsDir $name))
                $bytes[0] | Should -Not -Be 0xEF
                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                $text | Should -Match '^[0-9a-f]{64}\n$'
                $text.Trim()
            }
            @($values | Sort-Object -Unique).Count | Should -Be 3
            ([System.IO.File]::ReadAllText((Join-Path $SecretsDir 'metrics.token'))).Trim() | Should -Match '^[0-9a-f]{64}$'
            ([System.IO.File]::ReadAllText((Join-Path $SecretsDir 'bootstrap-admin-password'))).Trim() | Should -Be $Password
        }

        It 'passes secrets to the service only as *_FILE references' {
            $SvcEnv['AEGIS_JWT_SECRET_FILE'] | Should -Be (Join-Path $SecretsDir 'jwt.key')
            $SvcEnv['AEGIS_DATAPLANE_KEY_FILE'] | Should -Be (Join-Path $SecretsDir 'dataplane.key')
            $SvcEnv['AEGIS_ENCRYPTION_KEY_FILE'] | Should -Be (Join-Path $SecretsDir 'encryption.key')
            $SvcEnv['AEGIS_BOOTSTRAP_ADMIN_PASSWORD_FILE'] | Should -Be (Join-Path $SecretsDir 'bootstrap-admin-password')
            $SvcEnv['AEGIS_METRICS_TOKEN_FILE'] | Should -Be (Join-Path $SecretsDir 'metrics.token')
            foreach ($secret in Get-SecretValues) {
                $SvcEnv.Values | Should -Not -Contain $secret
                ($SvcEnv.Values -join "`n") | Should -Not -Match ([regex]::Escape($secret))
            }
            $FakeWin.RegistryTypes["$ServiceKey|Environment"] | Should -Be 'MultiString'
        }

        It 'writes the documented service environment' {
            $SvcEnv['CONTROL_PLANE_PORT'] | Should -Be '8081'
            $SvcEnv['AEGIS_PUBLIC_URL'] | Should -Be 'https://aegis.corp.example:8081'
            $SvcEnv['AEGIS_PROXY_ADDRESS'] | Should -Be 'proxy.corp.example:8080'
            $SvcEnv['DATA_DIR'] | Should -Be (Join-Path $DataRoot 'data')
            $SvcEnv['CERTS_DIR'] | Should -Be $CertsDir
            $SvcEnv['AEGIS_STORAGE'] | Should -Be 'file'
            $SvcEnv['AEGIS_TRUSTED_PROXIES'] | Should -Be '10.0.0.10/32,10.0.0.11/32'
            $SvcEnv['AEGIS_CORS_ORIGINS'] | Should -Be 'https://console.corp.example'
            $SvcEnv['AEGIS_LOG_FILE'] | Should -Be (Join-Path (Join-Path $DataRoot 'logs') 'control-plane.log')
            $SvcEnv['AEGIS_LOG_FORMAT'] | Should -Be 'json'
            $SvcEnv['AEGIS_DEMO_MODE'] | Should -Be 'false'
            $SvcEnv['AEGIS_INTERNAL_DOMAINS'] | Should -Be '.corp.example,.local'
            $SvcEnv.Contains('AEGIS_DATABASE_URL_FILE') | Should -BeFalse
            $SvcEnv.Contains('AEGIS_TLS_CERT_FILE') | Should -BeFalse
        }

        It 'never prints a secret value' {
            $Run.Output | Should -Not -Match ([regex]::Escape($Password))
            foreach ($secret in Get-SecretValues) { $Run.Output | Should -Not -Match ([regex]::Escape($secret)) }
        }

        It 'restricts the secrets to SYSTEM, Administrators and the service account (read)' {
            foreach ($path in @($SecretsDir) + @(Get-ChildItem -LiteralPath $SecretsDir -File | ForEach-Object FullName)) {
                Get-PrincipalList $path | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisControlPlane') -Because $path
                (Get-FakeAccess $path)['NT SERVICE\AegisControlPlane'] | Should -Be 'R'
            }
        }

        It 'keeps the CA private key admin-only while the service can read the public certificates' {
            Get-PrincipalList (Join-Path $CertsDir 'mitmproxy-ca.pem') | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544')
            (Get-FakeAccess (Join-Path $CertsDir 'mitmproxy-ca-cert.pem'))['NT SERVICE\AegisControlPlane'] | Should -Be 'RX'
            (Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'gen-ca' }).Args[1] | Should -Be $CertsDir
        }

        It 'gives the service modify access to data and logs only, and no access for users to the data root' {
            (Get-FakeAccess (Join-Path $DataRoot 'data'))['NT SERVICE\AegisControlPlane'] | Should -Be 'M'
            (Get-FakeAccess (Join-Path $DataRoot 'logs'))['NT SERVICE\AegisControlPlane'] | Should -Be 'M'
            foreach ($dir in @('', 'data', 'certs', 'secrets', 'logs')) {
                $access = Get-FakeAccess (Join-Path $DataRoot $dir)
                $access.ContainsKey('*S-1-5-32-545') | Should -BeFalse -Because "users must not read $dir"
                $access.ContainsKey('*S-1-5-11') | Should -BeFalse -Because "authenticated users must not read $dir"
            }
        }

        It 'gives users and the service read/execute access to the program files only' {
            Test-FakeWritable $ExePath | Should -BeFalse
            (Get-FakeAccess $ExePath)['NT SERVICE\AegisControlPlane'] | Should -Be 'RX'
        }

        It 'registers the Application event log source like eventlog.InstallAsEventCreate, before the first start' {
            $FakeWin.Registry[$EventLogKey]['EventMessageFile'] | Should -Be '%SystemRoot%\System32\EventCreate.exe'
            $FakeWin.RegistryTypes["$EventLogKey|EventMessageFile"] | Should -Be 'ExpandString'
            $FakeWin.Registry[$EventLogKey]['TypesSupported'] | Should -Be 7
            $FakeWin.RegistryTypes["$EventLogKey|TypesSupported"] | Should -Be 'DWord'
            $order = @($FakeWin.Calls | Where-Object { $_.Command -in @('New-Item', 'Start-Service') } | ForEach-Object Command)
            $order | Should -Be @('New-Item', 'Start-Service')
        }

        It 'opens the listener port only for the given remote addresses and the service binary' {
            $rule = $FakeWin.Firewall['AegisProxy-ControlPlane-In']
            $rule.LocalPort | Should -Be 8081
            $rule.Program | Should -Be $ExePath
            $rule.Profile | Should -Be @('Domain')
            $rule.RemoteAddress | Should -Be @('10.20.0.0/16')
            $rule.Direction | Should -Be 'Inbound'
        }

        It 'registers the daily log rotation as the service account (not SYSTEM) with a quoted command line' {
            $task = $FakeWin.Tasks['\AegisProxy\AegisProxy Control-Plane Log Rotation']
            $task.Principal.UserId | Should -Be 'NT SERVICE\AegisControlPlane' -Because 'as SYSTEM it would act on files and links in a directory the service can modify'
            $task.Principal.LogonType | Should -Be 'ServiceAccount'
            $task.Principal.RunLevel | Should -Be 'Limited'
            $task.Trigger.Daily | Should -BeTrue
            $task.Action.Argument | Should -BeLike ('*-File "{0}" -LogFile "{1}" -RetentionDays 30' -f (Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'), (Join-Path (Join-Path $DataRoot 'logs') 'control-plane.log'))
            $rotation = Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'
            (Get-FakeAccess $rotation)['NT SERVICE\AegisControlPlane'] | Should -Be 'RX' -Because 'the account running the script must not be able to change it'
            Test-FakeWritable $rotation | Should -BeFalse
            [System.IO.File]::ReadAllBytes($rotation)[0..2] | Should -Be @(0xEF, 0xBB, 0xBF) -Because 'Windows PowerShell 5.1 runs the task'
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($rotation, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'probes /healthz on the configured port without leaking the probe settings into the session' {
            $probe = @(Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'healthcheck' })
            $probe.Count | Should -BeGreaterThan 0
            $probe[-1].Port | Should -Be '8081'
            $probe[-1].Tls | Should -BeNullOrEmpty
            $env:CONTROL_PLANE_PORT | Should -BeNullOrEmpty
        }
    }

    Context 'custom installation directory' {
        It 'does not let users replace the binary or the SYSTEM log rotation script outside %ProgramFiles%' {
            # The volume root of the fake (like C:\ on client SKUs) lets authenticated users modify what they create.
            $custom = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'AegisProxy\control-plane'))
            Register-FakeExecutable -Path (Join-Path $custom 'aegis-control-plane.exe') -Function FakeControlPlaneExe
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $custom; SkipFirewall = $true })).ExitCode | Should -Be 0
            foreach ($path in @($custom, (Join-Path $custom 'aegis-control-plane.exe'), (Join-Path $custom 'Invoke-AegisLogRotation.ps1'))) {
                Test-FakeWritable $path | Should -BeFalse -Because "$path runs with service or SYSTEM rights"
            }
            (Get-FakeAccess (Join-Path $custom 'aegis-control-plane.exe'))['NT SERVICE\AegisControlPlane'] | Should -Be 'RX'
        }
    }

    Context 'directories that existed before the first installation' {
        BeforeEach {
            # A local user created the data directories in advance (ProgramData allows that), owns them and granted
            # Authenticated Users modify explicitly - on the data root and on secrets.
            $script:Planter = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            $script:LogsDir = Join-Path $DataRoot 'logs'
            foreach ($dir in @($SecretsDir, $CertsDir, $LogsDir, (Join-Path $DataRoot 'data'))) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            foreach ($dir in @($DataRoot, $SecretsDir)) {
                $FakeWin.Acl[(Get-FakeFullPath $dir)] = @{ Protected = $false; Grants = [ordered]@{ '*S-1-5-11' = '(OI)(CI)M' } }
            }
            Set-FakeOwner -Path $DataRoot -Sid $Planter
        }

        It 'refuses a pre-seeded <Name> on a first installation and changes nothing' -TestCases @(
            @{ Name = 'JWT key'; PlantIn = 'SecretsDir'; PlantFile = 'jwt.key' }, @{ Name = 'encryption key'; PlantIn = 'SecretsDir'; PlantFile = 'encryption.key' },
            @{ Name = 'data-plane key'; PlantIn = 'SecretsDir'; PlantFile = 'dataplane.key' }, @{ Name = 'TLS key'; PlantIn = 'SecretsDir'; PlantFile = 'tls-key.pem' },
            @{ Name = 'bootstrap password'; PlantIn = 'SecretsDir'; PlantFile = 'bootstrap-admin-password' }, @{ Name = 'metrics token'; PlantIn = 'SecretsDir'; PlantFile = 'metrics.token' },
            @{ Name = 'CA'; PlantIn = 'CertsDir'; PlantFile = 'mitmproxy-ca.pem' }, @{ Name = 'state file'; PlantIn = 'DataRoot'; PlantFile = 'data\aegis_state.json' },
            @{ Name = 'binary'; PlantIn = 'InstallDir'; PlantFile = 'aegis-control-plane.exe' }
        ) {
            $planted = Join-Path (Get-Variable -Name $PlantIn -ValueOnly) $PlantFile
            New-Item -ItemType Directory -Path (Split-Path -Parent $planted) -Force | Out-Null
            Set-Content -LiteralPath $planted -Value ('p' * 64)
            Set-FakeOwner -Path $planted -Sid $Planter
            $err = { & $Installer @Base } | Should -Throw '*Refusing to adopt 1 file(s)*service AegisControlPlane is not installed*-AdoptExistingSecrets*' -PassThru
            "$err" | Should -Match ([regex]::Escape((Split-Path -Leaf $planted)))
            $FakeWin.Services.Count | Should -Be 0
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
            Get-Content -LiteralPath $planted | Should -Be ('p' * 64)
        }

        It 'keeps restored secrets and CA with -AdoptExistingSecrets, but takes ownership and removes the planted ACEs' {
            $preJwt = 'p' * 64
            [System.IO.File]::WriteAllText((Join-Path $SecretsDir 'jwt.key'), $preJwt)
            $preFp = New-TestCa -Dir $CertsDir -Subject 'CN=Restored CA'
            Set-FakeOwner -Path $DataRoot -Sid $Planter
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ AdoptExistingSecrets = $true; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'AdoptExistingSecrets: keeping 5 pre-existing file'
            ([System.IO.File]::ReadAllText((Join-Path $SecretsDir 'jwt.key'))).Trim() | Should -Be $preJwt
            @(Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'gen-ca' }).Count | Should -Be 0
            $run.Output | Should -Match ([regex]::Escape($preFp))
            foreach ($path in @($DataRoot, $SecretsDir, $CertsDir, (Join-Path $SecretsDir 'jwt.key'), (Join-Path $CertsDir 'mitmproxy-ca.pem'))) {
                (Get-Acl -LiteralPath $path).GetOwner($null).Value | Should -Be 'S-1-5-32-544' -Because $path
                (Get-FakeAccess $path).ContainsKey('*S-1-5-11') | Should -BeFalse -Because $path
            }
            Get-PrincipalList $SecretsDir | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisControlPlane')
            Get-PrincipalList (Join-Path $CertsDir 'mitmproxy-ca.pem') | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544')
            Test-FakeWritable (Join-Path $SecretsDir 'jwt.key') | Should -BeFalse
        }

        It 'takes over empty pre-existing directories (and old logs) without -AdoptExistingSecrets' {
            $oldLog = Join-Path $LogsDir 'control-plane.log'
            Set-Content -LiteralPath $oldLog -Value 'log line'
            $FakeWin.Acl[(Get-FakeFullPath $oldLog)] = @{ Protected = $false; Grants = [ordered]@{ '*S-1-1-0' = 'F' } }
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'ACLs verified'
            $FakeWin.Acl[(Get-FakeFullPath $DataRoot)].Grants.Contains('*S-1-5-11') | Should -BeFalse -Because 'the explicit ACE on the data root itself is removed'
            @(Get-FakeCall 'icacls.exe' | Where-Object { $_.Args[1] -eq '/remove' -and $_.Args[2] -eq '*S-1-5-11' }).Count | Should -Be 1
            foreach ($path in @($DataRoot, $SecretsDir, $LogsDir, $oldLog)) {
                (Get-Acl -LiteralPath $path).GetOwner($null).Value | Should -Be 'S-1-5-32-544' -Because $path
                Test-FakeWritable -Path $path -Principals @('*S-1-5-11', '*S-1-1-0', '*S-1-5-32-545') | Should -BeFalse -Because $path
            }
            Get-PrincipalList $DataRoot | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544')
            Get-PrincipalList $LogsDir | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisControlPlane')
        }

        It 'aborts before starting the service when the resulting ACL cannot be verified' {
            $FakeWin.IcaclsIgnore = @('/remove')
            { & $Installer @Base -SkipFirewall } | Should -Throw '*ACL verification failed*: access for S-1-5-11 is not expected*'
            $FakeWin.Services['AegisControlPlane'].Status | Should -Be 'Stopped'
            @(Get-FakeCall 'Start-Service').Count | Should -Be 0
        }

        It 'refuses a junction in the data directories and leaves its target alone' {
            $target = Join-Path $FakeWin.Root 'elsewhere'
            New-Item -ItemType Directory -Path $target | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'x'
            Remove-Item -LiteralPath $SecretsDir -Recurse -Force
            New-Item -ItemType SymbolicLink -Path $SecretsDir -Target $target | Out-Null
            { & $Installer @Base } | Should -Throw '*Junctions/symbolic links and hard-linked files are not allowed*secrets*'
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
            $FakeWin.Owner.ContainsKey((Get-FakeFullPath $target)) | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $target 'keep.txt') | Should -BeTrue
        }

        It 'refuses a hard-linked key file (its ACL is shared with the file elsewhere)' {
            $outside = Join-Path $FakeWin.Root 'outside.key'
            Set-Content -LiteralPath $outside -Value ('p' * 64)
            New-Item -ItemType HardLink -Path (Join-Path $SecretsDir 'jwt.key') -Target $outside | Out-Null
            { & $Installer @Base -AdoptExistingSecrets } | Should -Throw '*hard-linked files are not allowed*jwt.key (hard link)*'
            (Get-FakeCall 'icacls.exe').Count | Should -Be 0
        }

        It 'takes the directories over top-down with /L and without /T' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $calls = @(Get-FakeCall 'icacls.exe')
            @($calls | Where-Object { $_.Args -notcontains '/L' }).Count | Should -Be 0
            @($calls | Where-Object { $_.Args -contains '/T' }).Count | Should -Be 0 -Because 'icacls /T follows junctions'
            $order = @($calls | ForEach-Object { Get-FakeFullPath $_.Args[0] })
            $first = @($DataRoot, $SecretsDir) | ForEach-Object { $order.IndexOf((Get-FakeFullPath $_)) }
            $first | Should -Not -Contain -1
            $first[0] | Should -BeLessThan $first[1]
        }

        It 'refuses a symbolic link that the owner of secrets swaps in while the installer runs, and leaves its target alone' {
            $target = Join-Path $FakeWin.Root 'victim'
            New-Item -ItemType Directory -Path $target | Out-Null
            Set-Content -LiteralPath (Join-Path $target 'keep.txt') -Value 'x'
            $race = @{ Done = $false; Dir = (Get-FakeFullPath $SecretsDir); Link = (Join-Path $SecretsDir 'link'); Target = $target }
            $FakeWin.IcaclsHook = {
                param($a)
                if (-not $race.Done -and (Get-FakeFullPath $a[0]) -eq $race.Dir) {
                    $race.Done = $true
                    New-Item -ItemType SymbolicLink -Path $race.Link -Target $race.Target | Out-Null
                }
            }.GetNewClosure()
            { & $Installer @Base -SkipFirewall } | Should -Throw '*Junction/symbolic link in the installation directories*link*'
            $race.Done | Should -BeTrue
            $FakeWin.Owner.ContainsKey((Get-FakeFullPath $target)) | Should -BeFalse
            $FakeWin.Acl.ContainsKey((Get-FakeFullPath $target)) | Should -BeFalse
            $FakeWin.Services.Count | Should -Be 0
        }

        It 'refuses a <Name> planted after the inspection, before the directories were locked' -TestCases @(
            @{ Name = 'JWT key'; PlantIn = 'SecretsDir'; PlantFile = 'jwt.key' }, @{ Name = 'CA'; PlantIn = 'CertsDir'; PlantFile = 'mitmproxy-ca.pem' }
        ) {
            $planted = Join-Path (Get-Variable -Name $PlantIn -ValueOnly) $PlantFile
            $FakeWin.IcaclsHook = { param($a) if (-not [System.IO.File]::Exists($planted)) { [System.IO.File]::WriteAllText($planted, 'p' * 64) } }.GetNewClosure()
            { & $Installer @Base -SkipFirewall } | Should -Throw "*1 file(s) appeared in the installation directories while this script ran*$PlantFile*"
            $FakeWin.Services.Count | Should -Be 0
        }
    }

    Context 're-run (upgrade)' {
        BeforeEach {
            $first = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{
                    TrustedProxies = @('10.0.0.10/32'); ExtraEnvironment = @{ AEGIS_LOG_LEVEL = 'debug'; AEGIS_INTERNAL_DOMAINS = '.corp'; AEGIS_AUDIT_ROTATE_MB = '512' }
                    ListenAddress = '127.0.0.1:9443'; SkipFirewall = $true })
            $first.ExitCode | Should -Be 0
            $script:SecretsBefore = @{}
            foreach ($f in Get-ChildItem -LiteralPath $SecretsDir -File) { $SecretsBefore[$f.Name] = [System.IO.File]::ReadAllText($f.FullName) }
            $script:CaBefore = [System.IO.File]::ReadAllText((Join-Path $CertsDir 'mitmproxy-ca.pem'))
            New-FakeBinary -Path $Binary -Marker 'v2'
        }

        It 'keeps secrets, CA and earlier settings and replaces the binary after stopping the service' {
            $run = Invoke-Installer -Path $Installer -Parameters $Base
            $run.ExitCode | Should -Be 0
            foreach ($name in $SecretsBefore.Keys) { [System.IO.File]::ReadAllText((Join-Path $SecretsDir $name)) | Should -Be $SecretsBefore[$name] }
            [System.IO.File]::ReadAllText((Join-Path $CertsDir 'mitmproxy-ca.pem')) | Should -Be $CaBefore
            @(Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'gen-ca' }).Count | Should -Be 1
            [System.IO.File]::ReadAllText($ExePath) | Should -Match 'fake v2'
            @(Get-FakeCall 'Stop-Service').Count | Should -Be 1
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv['AEGIS_LISTEN_ADDR'] | Should -Be '127.0.0.1:9443'
            $svcEnv['AEGIS_TRUSTED_PROXIES'] | Should -Be '10.0.0.10/32'
            $svcEnv['AEGIS_LOG_LEVEL'] | Should -Be 'debug'
            $svcEnv['AEGIS_AUDIT_ROTATE_MB'] | Should -Be '512'
            @(Get-FakeCall 'New-Service').Count | Should -Be 1
            @(Get-FakeCall 'New-Item').Count | Should -Be 1 -Because 'the existing event log source is kept'
            $FakeWin.Registry[$EventLogKey]['TypesSupported'] | Should -Be 7
            @(Get-FakeCall 'Invoke-CimMethod').Count | Should -Be 0
        }

        It 'does not vouch for the secrets once a foreign ACE was added to the secrets directory, and repairs it with -AdoptExistingSecrets' {
            $FakeWin.Acl[(Get-FakeFullPath $SecretsDir)].Grants['*S-1-5-11'] = '(OI)(CI)R'
            { & $Installer @Base } | Should -Throw '*Refusing to adopt*secrets: access for S-1-5-11 is not expected*'
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ AdoptExistingSecrets = $true })).ExitCode | Should -Be 0
            (Get-FakeAccess $SecretsDir).ContainsKey('*S-1-5-11') | Should -BeFalse
            foreach ($name in $SecretsBefore.Keys) { [System.IO.File]::ReadAllText((Join-Path $SecretsDir $name)) | Should -Be $SecretsBefore[$name] }
        }

        It 'removes an earlier extra variable passed with an empty value' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ExtraEnvironment = @{ AEGIS_LOG_LEVEL = '' } })).ExitCode | Should -Be 0
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv.Contains('AEGIS_LOG_LEVEL') | Should -BeFalse
            $svcEnv['AEGIS_INTERNAL_DOMAINS'] | Should -Be '.corp'
        }

        It 'drops plain secret variables of an older installation from the service environment' {
            $key = $FakeWin.Registry[$ServiceKey]
            $key['Environment'] = [string[]](@($key['Environment']) + @('AEGIS_ENCRYPTION_KEY=' + ('k' * 64), 'AEGIS_JWT_SECRET=' + ('j' * 64)))
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv.Contains('AEGIS_ENCRYPTION_KEY') | Should -BeFalse
            $svcEnv.Contains('AEGIS_JWT_SECRET') | Should -BeFalse
        }

        It 'updates the image path when the installation directory changes' {
            $FakeWin.Services['AegisControlPlane'].PathName = '"C:\old\aegis-control-plane.exe"'
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $FakeWin.Services['AegisControlPlane'].PathName | Should -Be ('"{0}" service' -f $ExePath)
            @(Get-FakeCall 'Invoke-CimMethod').Count | Should -Be 1
        }

        It 'adds the service argument to a registration of an older version' {
            $FakeWin.Services['AegisControlPlane'].PathName = '"{0}"' -f $ExePath
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $FakeWin.Services['AegisControlPlane'].PathName | Should -Be ('"{0}" service' -f $ExePath)
            (Get-FakeCall 'Invoke-CimMethod')[0].Args[2] | Should -Be ('"{0}" service' -f $ExePath)
        }

        It 'keeps the installed binary when no new one is given' {
            Remove-Item -LiteralPath $Binary
            $run = Invoke-Installer -Path $Installer -Parameters $Base
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'keeping the installed one'
            [System.IO.File]::ReadAllText($ExePath) | Should -Match 'fake v1'
        }
    }

    Context 'PostgreSQL cluster nodes' {
        BeforeEach {
            $script:Node1 = Join-Path $FakeWin.Root 'node1'
            New-Item -ItemType Directory -Path (Join-Path $Node1 'secrets') -Force | Out-Null
            foreach ($name in @('jwt.key', 'dataplane.key', 'encryption.key')) {
                [System.IO.File]::WriteAllText((Join-Path (Join-Path $Node1 'secrets') $name), ("{0}`n" -f ($name.Substring(0, 1) * 64)))
            }
            $script:Node1Fp = New-TestCa -Dir (Join-Path $Node1 'certs')
            $script:Dsn = 'postgres://aegis:S3cr3t-Db-Pass@db.corp.example:5432/aegis?sslmode=verify-full'
            $script:Cluster = Join-Parameters $Base @{ Storage = 'postgres'; DatabaseUrl = $Dsn; ImportSecretsDir = (Join-Path $Node1 'secrets')
                CaSourceDir = (Join-Path $Node1 'certs'); SkipFirewall = $true }
        }

        It 'imports the shared secrets and CA and references the DSN only as a file' {
            $run = Invoke-Installer -Path $Installer -Parameters $Cluster
            $run.ExitCode | Should -Be 0
            foreach ($name in @('jwt.key', 'dataplane.key', 'encryption.key')) {
                ([System.IO.File]::ReadAllText((Join-Path $SecretsDir $name))).Trim() | Should -Be ($name.Substring(0, 1) * 64)
            }
            @(Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'gen-ca' }).Count | Should -Be 0
            $run.Output | Should -Match ([regex]::Escape($Node1Fp))
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv['AEGIS_STORAGE'] | Should -Be 'postgres'
            $svcEnv['AEGIS_DATABASE_URL_FILE'] | Should -Be (Join-Path $SecretsDir 'database-url')
            ($svcEnv.Values -join ' ') | Should -Not -Match 'S3cr3t-Db-Pass'
            $run.Output | Should -Not -Match 'S3cr3t-Db-Pass'
            Get-PrincipalList (Join-Path $CertsDir 'mitmproxy-ca.pem') | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544')
        }

        It 'keeps postgres storage on a plain re-run without asking for the DSN again' {
            (Invoke-Installer -Path $Installer -Parameters $Cluster).ExitCode | Should -Be 0
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            (Get-RegistryEnvironment 'AegisControlPlane')['AEGIS_STORAGE'] | Should -Be 'postgres'
        }

        It 'refuses to replace different secrets or a different CA without -Force' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            { & $Installer @Cluster } | Should -Throw '*exists with a different value*'
            $noSecrets = $Cluster.Clone(); $noSecrets.Remove('ImportSecretsDir')
            { & $Installer @noSecrets } | Should -Throw '*A different CA already exists*'
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Cluster @{ Force = $true })).ExitCode | Should -Be 0
            ([System.IO.File]::ReadAllText((Join-Path $SecretsDir 'jwt.key'))).Trim() | Should -Be ('j' * 64)
        }

        It 'rejects imported secrets shorter than 32 characters' {
            [System.IO.File]::WriteAllText((Join-Path (Join-Path $Node1 'secrets') 'jwt.key'), 'too-short')
            { & $Installer @Cluster } | Should -Throw '*shorter than 32 characters*'
        }

        It 'imports the proxy secret of the first node when it has one, and only a valid one' {
            $nodeSecret = Join-Path (Join-Path $Node1 'secrets') 'trusted-proxy-secret'
            [System.IO.File]::WriteAllText($nodeSecret, ('p' * 63) + '=' + "`n")
            (Invoke-Installer -Path $Installer -Parameters $Cluster).ExitCode | Should -Be 0
            ([System.IO.File]::ReadAllText((Join-Path $SecretsDir 'trusted-proxy-secret'))).Trim() | Should -Be (('p' * 63) + '=')
            (Get-RegistryEnvironment 'AegisControlPlane')['AEGIS_TRUSTED_PROXY_SECRET_FILE'] | Should -Be (Join-Path $SecretsDir 'trusted-proxy-secret')
            [System.IO.File]::WriteAllText($nodeSecret, ('p' * 40) + '"')
            { & $Installer @Cluster } | Should -Throw '*trusted-proxy-secret is not a valid proxy secret*'
        }

        It 'refuses -<Parameter> from an SMB share without encryption before changing anything' -TestCases @(
            @{ Parameter = 'ImportSecretsDir'; Leaf = 'secrets' }, @{ Parameter = 'CaSourceDir'; Leaf = 'certs' }
        ) {
            $FakeWin.Smb.Connections = @([pscustomobject]@{ ServerName = 'node1'; ShareName = 'c$'; Encrypted = $false })
            $p = Join-Parameters $Cluster @{ $Parameter = "\\node1\c$\ProgramData\AegisProxy\$Leaf" }
            { & $Installer @p } | Should -Throw "*-$Parameter reads secrets from \\node1\c$ over an SMB connection that is not encrypted*-RequirePrivacy*-AllowUnencryptedImport*"
            $FakeWin.Services.Count | Should -Be 0
            Test-Path -LiteralPath $DataRoot | Should -BeFalse
            # Encrypted: the check passes (the share itself does not exist in the fake, so the import fails later).
            $FakeWin.Smb.Connections[0].Encrypted = $true
            $err = { & $Installer @p } | Should -Throw -PassThru
            "$err" | Should -Not -Match 'SMB connection'
        }
    }

    Context 'reverse-proxy secret' {
        BeforeEach {
            $script:ProxySecretFile = Join-Path $SecretsDir 'trusted-proxy-secret'
        }

        It 'creates the proxy secret when -TrustedProxies <Trusted> covers loopback, and passes it only as a file' -TestCases @(
            @{ Trusted = @('127.0.0.1/32') }, @{ Trusted = @('::1/128') }, @{ Trusted = @('127.0.0.1') },
            @{ Trusted = @('10.0.0.10/32', '127.0.0.0/8') }, @{ Trusted = @('0.0.0.0/0') }, @{ Trusted = @('10.0.0.10/32,127.10.0.1/32') }
        ) {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ TrustedProxies = $Trusted; ListenAddress = '127.0.0.1:8081'; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $text = [System.IO.File]::ReadAllText($ProxySecretFile)
            $text | Should -Match '^[0-9a-f]{64}\n$'
            $secret = $text.Trim()
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv['AEGIS_TRUSTED_PROXY_SECRET_FILE'] | Should -Be $ProxySecretFile
            $svcEnv['AEGIS_TRUSTED_PROXIES'] | Should -Be ($Trusted -join ',')
            ($svcEnv.Values -join "`n") | Should -Not -Match $secret
            $run.Output | Should -Not -Match $secret
            $run.Output | Should -Match 'New proxy secret'
            $run.Output | Should -Match ([regex]::Escape('-ApiProxyTarget http://127.0.0.1:8081'))
            Get-PrincipalList $ProxySecretFile | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisControlPlane')
            (Get-FakeAccess $ProxySecretFile)['NT SERVICE\AegisControlPlane'] | Should -Be 'R'
        }

        It 'creates no proxy secret for -TrustedProxies <Trusted>' -TestCases @(
            @{ Trusted = @('10.0.0.10/32') }, @{ Trusted = @('126.0.0.0/8', '128.0.0.0/1') }, @{ Trusted = @('::2/128') }, @{ Trusted = @() }
        ) {
            $p = Join-Parameters $Base @{ SkipFirewall = $true }
            if ($Trusted.Count) { $p.TrustedProxies = $Trusted }
            (Invoke-Installer -Path $Installer -Parameters $p).ExitCode | Should -Be 0
            Test-Path -LiteralPath $ProxySecretFile | Should -BeFalse
            (Get-RegistryEnvironment 'AegisControlPlane').Contains('AEGIS_TRUSTED_PROXY_SECRET_FILE') | Should -BeFalse
        }

        It 'creates it with -ProxySecret for a proxy on another host' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ TrustedProxies = @('10.0.0.10/32'); ProxySecret = $true; SkipFirewall = $true })).ExitCode | Should -Be 0
            ([System.IO.File]::ReadAllText($ProxySecretFile)).Trim() | Should -Match '^[0-9a-f]{64}$'
            (Get-RegistryEnvironment 'AegisControlPlane')['AEGIS_TRUSTED_PROXY_SECRET_FILE'] | Should -Be $ProxySecretFile
        }

        It 'treats loopback trusted through -ExtraEnvironment like -TrustedProxies' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ExtraEnvironment = @{ AEGIS_TRUSTED_PROXIES = '127.0.0.1/32' }; SkipFirewall = $true })).ExitCode | Should -Be 0
            Test-Path -LiteralPath $ProxySecretFile | Should -BeTrue
            (Get-RegistryEnvironment 'AegisControlPlane')['AEGIS_TRUSTED_PROXY_SECRET_FILE'] | Should -Be $ProxySecretFile
        }

        It 'refuses to drop the secret variable while loopback is trusted' {
            { & $Installer @Base -TrustedProxies '127.0.0.1/32' -ExtraEnvironment @{ AEGIS_TRUSTED_PROXY_SECRET_FILE = '' } } | Should -Throw '*trusts a loopback address: AEGIS_TRUSTED_PROXY_SECRET_FILE cannot be removed*'
            $FakeWin.Services.Count | Should -Be 0
        }

        It 'keeps the proxy secret on a re-run and replaces an invalid one' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ TrustedProxies = @('127.0.0.1/32'); SkipFirewall = $true })).ExitCode | Should -Be 0
            $before = [System.IO.File]::ReadAllText($ProxySecretFile)
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            [System.IO.File]::ReadAllText($ProxySecretFile) | Should -Be $before
            $run.Output | Should -Not -Match 'New proxy secret'
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv['AEGIS_TRUSTED_PROXIES'] | Should -Be '127.0.0.1/32'
            $svcEnv['AEGIS_TRUSTED_PROXY_SECRET_FILE'] | Should -Be $ProxySecretFile
            # The control-plane refuses to start with a secret it cannot use (too short, characters outside -._~+/=).
            [System.IO.File]::WriteAllText($ProxySecretFile, ('x' * 40) + '"')
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'New proxy secret'
            ([System.IO.File]::ReadAllText($ProxySecretFile)).Trim() | Should -Match '^[0-9a-f]{64}$'
        }
    }

    Context 'native HTTPS' {
        BeforeEach {
            $dir = Join-Path $FakeWin.Root 'pki'
            New-TestCa -Dir $dir | Out-Null
            $script:CertFile = Join-Path $dir 'mitmproxy-ca-cert.pem'
            $script:KeyFile = Join-Path $dir 'key.pem'
            $text = [System.IO.File]::ReadAllText((Join-Path $dir 'mitmproxy-ca.pem'))
            [System.IO.File]::WriteAllText($KeyFile, ($text -split '(?=-----BEGIN CERTIFICATE-----)')[0])
        }

        It 'stores certificate and key in the secrets directory and probes via https' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ TlsCertFile = $CertFile; TlsKeyFile = $KeyFile; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $svcEnv = Get-RegistryEnvironment 'AegisControlPlane'
            $svcEnv['AEGIS_TLS_CERT_FILE'] | Should -Be (Join-Path $SecretsDir 'tls-cert.pem')
            $svcEnv['AEGIS_TLS_KEY_FILE'] | Should -Be (Join-Path $SecretsDir 'tls-key.pem')
            (Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'healthcheck' })[-1].Tls | Should -Be (Join-Path $SecretsDir 'tls-cert.pem')
            $env:AEGIS_TLS_CERT_FILE | Should -BeNullOrEmpty
            $run.Output | Should -Match 'Listener\s+: https://'
        }

        It 'rejects an encrypted private key' {
            [System.IO.File]::WriteAllText($KeyFile, "-----BEGIN ENCRYPTED PRIVATE KEY-----`nAAAA`n-----END ENCRYPTED PRIVATE KEY-----`n")
            { & $Installer @Base -TlsCertFile $CertFile -TlsKeyFile $KeyFile -SkipFirewall } | Should -Throw '*not an unencrypted PEM private key*'
        }
    }

    Context 'health check and listener variants' {
        It 'exits 1 and shows the log tail when the service does not become healthy' {
            $FakeWin.Healthy = $false
            New-Item -ItemType Directory -Path (Join-Path $DataRoot 'logs') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path (Join-Path $DataRoot 'logs') 'control-plane.log') -Value '{"level":"ERROR","msg":"AEGIS_DATABASE_URL_FILE: unreachable"}'
            $start = $FakeWin.Now
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ HealthTimeoutSeconds = 20; SkipFirewall = $true })
            $run.ExitCode | Should -Be 1
            $run.Output | Should -Match 'did not become healthy within 20 s'
            $run.Output | Should -Match 'unreachable'
            ($FakeWin.Now - $start).TotalSeconds | Should -BeLessThan 30
        }

        It 'explains the foreground run (binary without the service argument) when there is no log yet' {
            $FakeWin.Healthy = $false
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ HealthTimeoutSeconds = 10; SkipFirewall = $true })
            $run.ExitCode | Should -Be 1
            $run.Output | Should -Match ([regex]::Escape("run & '$ExePath' (without the 'service' argument, in the foreground)"))
        }

        It 'uses the port of -ListenAddress for the firewall rule and the probe' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ListenAddress = '0.0.0.0:9443' })).ExitCode | Should -Be 0
            $FakeWin.Firewall['AegisProxy-ControlPlane-In'].LocalPort | Should -Be 9443
            (Get-FakeCall 'aegis-control-plane' | Where-Object { $_.Args[0] -eq 'healthcheck' })[-1].Port | Should -Be '9443'
        }

        It 'does not report an IPv6-loopback-only listener as unhealthy (the probe uses 127.0.0.1)' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ListenAddress = '[::1]:8081'; SkipFirewall = $true })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'not reachable via 127.0.0.1'
        }

        It 'creates no firewall rule with -SkipFirewall and no task with -SkipLogRotationTask' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true; SkipLogRotationTask = $true })).ExitCode | Should -Be 0
            $FakeWin.Firewall.Count | Should -Be 0
            $FakeWin.Tasks.Count | Should -Be 0
        }

        It 'changes nothing with -WhatIf and leaves no temporary file behind' {
            $temp = Join-Path $FakeWin.Root 'temp'
            New-Item -ItemType Directory -Path $temp | Out-Null
            $env:TEMP = $temp; $env:TMP = $temp; $env:TMPDIR = $temp
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ WhatIf = $true })
            $run.ExitCode | Should -Be 0
            $FakeWin.Services.Count | Should -Be 0
            $FakeWin.Registry.ContainsKey($EventLogKey) | Should -BeFalse
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
            Test-Path -LiteralPath $DataRoot | Should -BeFalse
            @(Get-ChildItem -LiteralPath $temp -Force).Count | Should -Be 0
        }
    }

    Context 'uninstall' {
        It 'removes service, firewall rule, task and program files but keeps data, secrets and CA' {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $run = Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; Confirm = $false }
            $run.ExitCode | Should -Be 0
            $FakeWin.Services.ContainsKey('AegisControlPlane') | Should -BeFalse
            $FakeWin.Registry.ContainsKey($ServiceKey) | Should -BeFalse
            $FakeWin.Registry.ContainsKey($EventLogKey) | Should -BeFalse
            $FakeWin.Firewall.Count | Should -Be 0
            $FakeWin.Tasks.Count | Should -Be 0
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $SecretsDir 'encryption.key') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $CertsDir 'mitmproxy-ca.pem') | Should -BeTrue
            (Get-FakeCall 'sc.exe' | Where-Object { $_.Args[0] -eq 'delete' }).Count | Should -Be 1
        }

        It 'is a no-op when nothing is installed' {
            $run = Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; Confirm = $false }
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'is not installed'
        }

        It 'removes the program files without following a junction inside them' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            $outside = Join-Path $FakeWin.Root 'outside'
            New-Item -ItemType Directory -Path $outside | Out-Null
            Set-Content -LiteralPath (Join-Path $outside 'keep.txt') -Value 'x'
            New-Item -ItemType SymbolicLink -Path (Join-Path $InstallDir 'link') -Target $outside | Out-Null
            # Windows PowerShell 5.1's Remove-Item -Recurse deletes the content of junction targets.
            Mock Remove-Item -ParameterFilter { $Recurse -and "$LiteralPath$Path" -notlike 'HKLM:*' } { throw 'Remove-Item -Recurse follows junctions in Windows PowerShell 5.1' }
            $run = Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; Confirm = $false }
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'only with -AdoptExistingSecrets'
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $outside 'keep.txt') | Should -BeTrue
        }

        It 'keeps everything with -WhatIf' {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; WhatIf = $true } | Out-Null
            $FakeWin.Services.ContainsKey('AegisControlPlane') | Should -BeTrue
            $FakeWin.Registry.ContainsKey($EventLogKey) | Should -BeTrue
            Test-Path -LiteralPath $ExePath | Should -BeTrue
        }
    }

    Context 'generated log rotation script' {
        BeforeEach {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            $script:Rotation = Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'
            $script:LogDir = Join-Path $FakeWin.Root 'rotation'
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            $script:Log = Join-Path $LogDir 'control-plane.log'
        }

        It 'archives and truncates the log in place and removes archives past the retention' {
            Set-Content -LiteralPath $Log -Value @('{"msg":"line 1"}', '{"msg":"line 2"}')
            $old = Join-Path $LogDir 'control-plane-20250101-031500.log.zip'
            $recent = Join-Path $LogDir 'control-plane-20991231-031500.log.zip'
            Set-Content -LiteralPath $old, $recent -Value 'zip'
            (Get-Item -LiteralPath $old).LastWriteTime = (Get-Date).AddDays(-40)
            # The service keeps the file open (shared read/write) while the task runs.
            $writer = [System.IO.File]::Open($Log, 'Open', 'Write', 'ReadWrite')
            try { & $Rotation -LogFile $Log -RetentionDays 30 }
            finally { $writer.Dispose() }
            (Get-Item -LiteralPath $Log).Length | Should -Be 0
            Test-Path -LiteralPath $old | Should -BeFalse
            Test-Path -LiteralPath $recent | Should -BeTrue
            $zip = @(Get-ChildItem -LiteralPath $LogDir -Filter 'control-plane-*.log.zip' | Where-Object FullName -ne $recent)
            $zip.Count | Should -Be 1
            $extract = Join-Path $LogDir 'x'
            Expand-Archive -LiteralPath $zip[0].FullName -DestinationPath $extract
            (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $extract -File)[0].FullName) | Should -Be @('{"msg":"line 1"}', '{"msg":"line 2"}')
            @(Get-ChildItem -LiteralPath $LogDir -Filter '*.log' | Where-Object Name -ne 'control-plane.log').Count | Should -Be 0
        }

        It 'does nothing for an empty or missing log' {
            & $Rotation -LogFile (Join-Path $LogDir 'missing.log')
            New-Item -ItemType File -Path $Log | Out-Null
            & $Rotation -LogFile $Log
            @(Get-ChildItem -LiteralPath $LogDir -Filter '*.zip').Count | Should -Be 0
        }
    }

    Context 'helpers' {
        BeforeAll {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'Invoke-Native', 'Read-SecretFile', 'Write-SecretFile', 'Get-CaInfo')))
        }

        It 'Invoke-Native returns output and throws with the output on unexpected exit codes' {
            Invoke-Native -FilePath 'sc.exe' -ArgumentList @('privs', 'Nope', 'x') -SuccessCodes @(1060) | Should -Contain '[SC] OpenService FAILED 1060:'
            { Invoke-Native -FilePath 'sc.exe' -ArgumentList @('privs', 'Nope', 'x') } | Should -Throw "*exit code 1060*does not exist*"
        }

        It 'Read-SecretFile strips BOM and whitespace, Write-SecretFile writes no BOM' {
            $p = Join-Path $FakeWin.Root 's.key'
            [System.IO.File]::WriteAllText($p, " abc `r`n", (New-Object System.Text.UTF8Encoding($true)))
            Read-SecretFile $p | Should -Be 'abc'
            Write-SecretFile -Path $p -Value 'xyz'
            [System.IO.File]::ReadAllBytes($p) | Should -Be ([System.Text.Encoding]::ASCII.GetBytes("xyz`n"))
            Read-SecretFile (Join-Path $FakeWin.Root 'missing') | Should -BeNullOrEmpty
        }

        It 'Assert-EncryptedSmbSource accepts encrypted connections, resolves mapped drives and refuses the rest' {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'Assert-EncryptedSmbSource', 'Write-Ok', 'Write-Note')))
            $FakeWin.Smb.Connections = @([pscustomobject]@{ ServerName = 'node1'; ShareName = 'c$'; Encrypted = $true },
                [pscustomobject]@{ ServerName = 'fs'; ShareName = 'aegis'; Encrypted = $false })
            $FakeWin.Smb.Mappings['Z:'] = '\\fs\aegis'
            Assert-EncryptedSmbSource -Name '-X' -Path '\\node1\c$\ProgramData\AegisProxy\secrets' 6>&1 | Should -Match 'is encrypted'
            Assert-EncryptedSmbSource -Name '-X' -Path '\\?\UNC\node1\c$\ProgramData' 6>&1 | Should -Match 'is encrypted'
            { Assert-EncryptedSmbSource -Name '-X' -Path 'Z:\secrets' } | Should -Throw '*\\fs\aegis over an SMB connection that is not encrypted*'
            { Assert-EncryptedSmbSource -Name '-X' -Path '\\other\share\secrets' } | Should -Throw '*\\other\share*not encrypted*'
            Assert-EncryptedSmbSource -Name '-X' -Path 'Z:\secrets' -AllowUnencrypted 6>&1 | Should -Match 'Continuing because of -AllowUnencryptedImport'
            Assert-EncryptedSmbSource -Name '-X' -Path 'C:\Backup\secrets' 6>&1 | Should -BeNullOrEmpty
            Assert-EncryptedSmbSource -Name '-X' -Path (Join-Path $FakeWin.Root 'secrets') 6>&1 | Should -BeNullOrEmpty
        }

        It 'Assert-EncryptedSmbSource recognises the unencrypted share written as <Form>' -TestCases @(
            @{ Form = 'forward slashes'; Path = '//fs/aegis/secrets' },
            @{ Form = 'mixed separators'; Path = '\\fs/aegis\secrets' },
            @{ Form = 'an extra leading separator'; Path = '\\\fs\aegis\secrets' },
            @{ Form = 'a \\?\UNC\ path'; Path = '\\?\UNC\fs\aegis\secrets' },
            @{ Form = 'a \\.\UNC\ path with forward slashes'; Path = '//./UNC/fs/aegis/secrets' },
            @{ Form = 'an NT \??\UNC\ path'; Path = '\??\UNC\fs\aegis\secrets' },
            @{ Form = 'a provider path'; Path = 'FileSystem::\\fs\aegis\secrets' },
            @{ Form = 'a mapped drive'; Path = 'z:/secrets' },
            @{ Form = 'a mapped drive as device path'; Path = '\\?\Z:\secrets' }
        ) {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'Assert-EncryptedSmbSource', 'Write-Ok', 'Write-Note')))
            $FakeWin.Smb.Connections = @([pscustomobject]@{ ServerName = 'fs'; ShareName = 'aegis'; Encrypted = $false })
            $FakeWin.Smb.Mappings['Z:'] = '\\fs\aegis'
            { Assert-EncryptedSmbSource -Name '-X' -Path $Path } | Should -Throw '*\\fs\aegis over an SMB connection that is not encrypted*'
        }

        It 'Assert-EncryptedSmbSource treats loopback shares as local and refuses other device paths' {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'Assert-EncryptedSmbSource', 'Write-Ok', 'Write-Note')))
            foreach ($path in @('\\localhost\c$\ProgramData\AegisProxy\secrets', '//127.0.0.1/c$/secrets', '\\.\UNC\127.0.0.1\c$\secrets', '\\[::1]\c$\secrets')) {
                Assert-EncryptedSmbSource -Name '-X' -Path $path 6>&1 | Should -Match 'share of this host' -Because $path
            }
            foreach ($path in @('\\?\GLOBALROOT\Device\Mup\fs\aegis\secrets', '\\.\pipe\secrets', '\\?\Volume{00000000-0000-0000-0000-000000000000}\secrets')) {
                { Assert-EncryptedSmbSource -Name '-X' -Path $path } | Should -Throw '*is a device path*' -Because $path
            }
        }

        It 'Get-ServiceSid computes virtual account SIDs like Windows' {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'Get-ServiceSid')))
            Get-ServiceSid 'TrustedInstaller' | Should -Be 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
            Get-ServiceSid 'AegisControlPlane' | Should -Be (Get-FakeSid 'NT SERVICE\AegisControlPlane')
        }

        It 'Get-CaInfo prefers the DER file and returns the SHA-256 fingerprint' {
            $dir = Join-Path $FakeWin.Root 'ca'
            $fp = New-TestCa -Dir $dir
            (Get-CaInfo $dir).Fingerprint | Should -Be $fp
            Remove-Item -LiteralPath (Join-Path $dir 'aegis-enterprise-ca.der')
            (Get-CaInfo $dir).Fingerprint | Should -Be $fp
            Get-CaInfo (Join-Path $FakeWin.Root 'empty') | Should -BeNullOrEmpty
        }
    }
}
