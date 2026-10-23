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
            @{ Name = 'AEGIS_ENCRYPTION_KEY_PREVIOUS' }
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

        It 'registers the daily log rotation as SYSTEM with a quoted command line' {
            $task = $FakeWin.Tasks['\AegisProxy\AegisProxy Control-Plane Log Rotation']
            $task.Principal.UserId | Should -Be 'S-1-5-18'
            $task.Trigger.Daily | Should -BeTrue
            $task.Action.Argument | Should -BeLike ('*-File "{0}" -LogFile "{1}" -RetentionDays 30' -f (Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'), (Join-Path (Join-Path $DataRoot 'logs') 'control-plane.log'))
            $rotation = Join-Path $InstallDir 'Invoke-AegisLogRotation.ps1'
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
