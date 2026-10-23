#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
# Pester tests for Install-AegisDataPlane.ps1 against the fake Windows in FakeWindows.ps1.

BeforeAll {
    . (Join-Path $PSScriptRoot 'FakeWindows.ps1')
    $script:Installer = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\Install-AegisDataPlane.ps1')).ProviderPath
    $script:SecurityRequirements = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\data-plane\requirements-security.txt'))

    function Get-RenderedService {
        # The WinSW configuration as written next to the wrapper: [xml] plus an env name -> value map.
        $xml = [xml][System.IO.File]::ReadAllText($script:WrapperXml)
        $envMap = [ordered]@{}
        foreach ($e in $xml.service.env) { $envMap[$e.name] = $e.value }
        [pscustomobject]@{ Xml = $xml; Env = $envMap; Names = @($xml.service.env | ForEach-Object name) }
    }

    function Get-PipCall([string]$Command = 'install') {
        @(Get-FakeCall 'python' | Where-Object { $_.Args[0] -eq '-m' -and $_.Args[1] -eq 'pip' -and $_.Args[2] -eq $Command })
    }
}

Describe 'Install-AegisDataPlane.ps1' {
    BeforeEach {
        Initialize-FakeWindows -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        Add-FakeWindowsMock
        $script:InstallDir = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'AegisProxy\data-plane'))
        $script:DataRoot = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramData 'AegisProxy\data-plane'))
        $script:WrapperExe = Join-Path $InstallDir 'aegis-dataplane.exe'
        $script:WrapperXml = Join-Path $InstallDir 'aegis-dataplane.xml'
        $script:VenvDir = Join-Path $InstallDir 'venv'
        $script:VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
        $script:AppDir = Join-Path $InstallDir 'app'
        $script:ConfDir = Join-Path $DataRoot 'confdir'
        $script:SecretsDir = Join-Path $DataRoot 'secrets'
        $script:LogsDir = Join-Path $DataRoot 'logs'
        $script:RuntimeDir = Join-Path $DataRoot 'runtime'
        $script:StagedKey = Join-Path $SecretsDir 'dataplane.key'
        $script:StagedCa = Join-Path $ConfDir 'mitmproxy-ca.pem'

        $script:PythonExe = Join-Path $env:ProgramFiles 'Python312\python.exe'
        New-FakeBinary -Path $PythonExe
        Register-FakeExecutable -Path $PythonExe -Function FakePython
        Register-FakeExecutable -Path $VenvPython -Function FakePython
        Register-FakeExecutable -Path $WrapperExe -Function FakeWinSW
        Register-FakeExecutable -Path 'Get-HttpStatus' -Function FakeHttpStatus

        $script:WinSW = Join-Path (Join-Path $FakeWin.Root 'install') 'WinSW-x64.exe'
        New-FakeBinary -Path $WinSW -Marker 'winsw'
        $script:WinSWHash = (Get-FileHash -LiteralPath $WinSW -Algorithm SHA256).Hash
        $cp = Join-Path $FakeWin.Root 'from-control-plane'
        $script:CaFingerprint = New-TestCa -Dir $cp
        $script:CaFile = Join-Path $cp 'mitmproxy-ca.pem'
        $script:KeyValue = '0123456789abcdef' * 4
        $script:KeyFile = Join-Path $cp 'dataplane.key'
        [System.IO.File]::WriteAllText($KeyFile, "$KeyValue`r`n")
        $script:Base = @{ ControlPlaneUrl = 'https://aegis.corp.example'; DataPlaneKeyFile = $KeyFile; CaFile = $CaFile
            WinSWExe = $WinSW; WinSWSha256 = $WinSWHash; PythonExe = $PythonExe }
    }
    AfterEach { Remove-FakeWindows }

    Context 'parameter validation' {
        It 'declares ControlPlaneUrl, DataPlaneKeyFile and WinSWExe mandatory for installs' {
            $cmd = Get-Command -Name $Installer
            foreach ($name in @('ControlPlaneUrl', 'DataPlaneKeyFile', 'WinSWExe')) {
                $attr = $cmd.Parameters[$name].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
                $attr.Mandatory | Should -BeTrue -Because $name
                $attr.ParameterSetName | Should -Be 'Install'
            }
        }

        It 'rejects <Name> = <Value>' -TestCases @(
            @{ Name = 'ControlPlaneUrl'; Value = 'aegis.corp.example' }, @{ Name = 'ListenHost'; Value = 'a b' },
            @{ Name = 'OpsAddr'; Value = '127.0.0.1' }, @{ Name = 'BodySizeLimit'; Value = '1t' },
            @{ Name = 'MitmLogLevel'; Value = 'trace' }, @{ Name = 'FailMode'; Value = 'ignore' },
            @{ Name = 'ServiceAccount'; Value = 'LocalSystem' }, @{ Name = 'WinSWSha256'; Value = 'abc' }
        ) {
            $p = $Base.Clone(); $p[$Name] = $Value
            { & $Installer @p } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }

        It 'stops when WinSW is missing' {
            $p = $Base.Clone(); $p.WinSWExe = Join-Path $FakeWin.Root 'missing.exe'
            { & $Installer @p } | Should -Throw '*WinSW executable not found*'
        }

        It 'refuses a WinSW executable that does not match the pinned SHA-256 before changing anything' {
            $p = $Base.Clone(); $p.Remove('WinSWSha256')
            { & $Installer @p } | Should -Throw '*expected 05B82D46AD331CC16BDC00DE5C6332C1EF818DF8CEEFCD49C726553209B3A0DA*'
            $p.WinSWSha256 = '0' * 64
            { & $Installer @p } | Should -Throw "*SHA-256 of*is $WinSWHash*"
            $FakeWin.Services.Count | Should -Be 0
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
        }

        It 'accepts the pinned hash in lower case' {
            $p = $Base.Clone(); $p.WinSWSha256 = $WinSWHash.ToLowerInvariant()
            (Invoke-Installer -Path $Installer -Parameters $p).ExitCode | Should -Be 0
        }

        It 'rejects a data-plane key that is <Case>' -TestCases @(
            @{ Case = 'missing'; Content = $null }, @{ Case = 'too short'; Content = 'abc' }, @{ Case = 'not a single token'; Content = ('a' * 20) + ' ' + ('b' * 20) }
        ) {
            if ($null -eq $Content) { Remove-Item -LiteralPath $KeyFile } else { [System.IO.File]::WriteAllText($KeyFile, $Content) }
            { & $Installer @Base } | Should -Throw '*data-plane key*'
        }

        It 'requires the CA private key, not only the certificate' {
            $p = $Base.Clone(); $p.CaFile = Join-Path (Split-Path -Parent $CaFile) 'mitmproxy-ca-cert.pem'
            { & $Installer @p } | Should -Throw '*must contain the CA private key AND certificate*'
        }

        It 'requires -CaFile unless a CA is staged or the control-plane CA is on this host' {
            $p = $Base.Clone(); $p.Remove('CaFile')
            { & $Installer @p } | Should -Throw '*-CaFile is required*'
            New-TestCa -Dir (Join-Path $env:ProgramData 'AegisProxy\certs') | Out-Null
            $run = Invoke-Installer -Path $Installer -Parameters $p
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'Using the control-plane CA on this host'
        }

        It 'rejects clamd address <Address>' -TestCases @(@{ Address = 'unix:///var/run/clamd.ctl' }, @{ Address = 'clamd' }, @{ Address = 'tcp://h:p' }) {
            { & $Installer @Base -ClamdAddress $Address } | Should -Throw
        }

        It 'requires an existing -ControlPlaneCaFile' {
            { & $Installer @Base -ControlPlaneCaFile (Join-Path $FakeWin.Root 'missing.pem') } | Should -Throw '*-ControlPlaneCaFile*not found*'
        }

        It 'refuses -ExtraEnvironment for the managed variable <Name>' -TestCases @(
            @{ Name = 'AEGIS_DATAPLANE_KEY' }, @{ Name = 'CONTROL_PLANE_URL' }, @{ Name = 'AEGIS_FAIL_MODE' }, @{ Name = 'AEGIS_PROXY_MODE' },
            @{ Name = 'AEGIS_CLAMD_ADDRESS' }, @{ Name = 'AEGIS_WORKER_ID' }, @{ Name = 'PYTHONNOUSERSITE' }
        ) {
            { & $Installer @Base -ExtraEnvironment @{ $Name = 'x' } } | Should -Throw "*$Name is managed by this script*"
        }

        It 'rejects invalid variable names' {
            { & $Installer @Base -ExtraEnvironment @{ 'A=B' = 'x' } } | Should -Throw '*Invalid environment variable name*'
        }

        It 'refuses a per-user Python installation' {
            $userPython = Join-Path $env:SystemDrive 'Users\alice\AppData\Local\Programs\Python\Python312\python.exe'
            New-FakeBinary -Path $userPython
            Register-FakeExecutable -Path $userPython -Function FakePython
            { & $Installer @Base -PythonExe $userPython } | Should -Throw '*per-user installation*'
        }

        It 'refuses Python older than 3.12' {
            $FakeWin.Python.Version = '3.11.9'
            { & $Installer @Base } | Should -Throw '*Python 3.11.9*too old*'
        }

        It 'finds Python with the launcher (first working of py -3.12/-3.13/-3.14)' {
            $bin = Join-Path $FakeWin.Root 'bin'
            New-FakeBinary -Path (Join-Path $bin 'py.exe')
            if (-not $IsWindows) { [System.IO.File]::SetUnixFileMode((Join-Path $bin 'py.exe'), [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute') }
            $env:PATH = $bin
            Register-FakeExecutable -Path (Join-Path $bin 'py.exe') -Function FakePython
            $FakeWin.Python.Launcher['-3.13'] = $PythonExe
            $p = $Base.Clone(); $p.Remove('PythonExe')
            $run = Invoke-Installer -Path $Installer -Parameters $p
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match ([regex]::Escape("Python 3.12.10 at $PythonExe"))
            @(Get-FakeCall 'python' | Where-Object { $_.Args[0] -match '^-3\.' } | ForEach-Object { $_.Args[0] }) | Should -Be @('-3.12', '-3.13')
        }

        It 'fails without the launcher and without -PythonExe' {
            $env:PATH = Join-Path $FakeWin.Root 'empty'
            $p = $Base.Clone(); $p.Remove('PythonExe')
            { & $Installer @p } | Should -Throw '*Python launcher (py.exe) not found*'
        }
    }

    Context 'fresh installation' {
        BeforeEach {
            $script:CpCa = Join-Path $FakeWin.Root 'pki-chain.pem'
            [System.IO.File]::WriteAllText($CpCa, [System.IO.File]::ReadAllText((Join-Path (Split-Path -Parent $CaFile) 'mitmproxy-ca-cert.pem')))
            $script:Run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{
                    ControlPlaneCaFile = $CpCa; PublicUrl = 'https://aegis.corp.example/'; DashboardUrl = 'https://console.corp.example'
                    WorkerId = 'dp-win-01'; OpsAddr = '0.0.0.0:9091'; AllowedRemoteAddress = @('10.20.0.0/16', '10.30.0.0/16')
                    MonitoringRemoteAddress = @('10.99.0.5'); ExtraEnvironment = @{ AEGIS_LOG_LEVEL = 'DEBUG'; AEGIS_MAGIC_HOSTS = 'a&b<c>"d''e' }
                })
            $script:Svc = Get-RenderedService
        }

        It 'completes with exit code 0 once /readyz answers' {
            $Run.ExitCode | Should -Be 0
            $Run.Output | Should -Match 'Data-plane is ready'
            $Run.Output | Should -Match ([regex]::Escape("Root CA SHA-256 : $CaFingerprint"))
            $FakeWin.HttpProbes | Should -Contain 'http://127.0.0.1:9091/readyz'
        }

        It 'renders a well-formed WinSW configuration for mitmdump with the hardened arguments' {
            $s = $Svc.Xml.service
            $s.id | Should -Be 'AegisDataPlane'
            $s.executable | Should -Be (Join-Path $VenvDir 'Scripts\mitmdump.exe')
            $s.workingdirectory | Should -Be $AppDir
            $s.logpath | Should -Be $LogsDir
            $s.startmode | Should -Be 'Automatic'
            $s.arguments | Should -BeLike ('-s "{0}" --set "confdir={1}" --listen-host 0.0.0.0 --listen-port 8080 *' -f (Join-Path $AppDir 'aegis_addon.py'), $ConfDir)
            foreach ($opt in @('connection_strategy=lazy', 'rawtcp=false', 'ssl_insecure=false', 'tls_version_server_min=TLS1_2', 'body_size_limit=1g', 'termlog_verbosity=info')) {
                $s.arguments | Should -Match ([regex]::Escape("--set $opt"))
            }
            [System.IO.File]::ReadAllText($WrapperXml) | Should -Not -Match '@@'
            [System.IO.File]::ReadAllText($WrapperXml) | Should -Match '<!-- Generated by Install-AegisDataPlane.ps1'
            [System.IO.File]::ReadAllBytes($WrapperXml)[0] | Should -Be ([byte][char]'<')
        }

        It 'sets each worker variable exactly once and escapes values' {
            $Svc.Names.Count | Should -Be (@($Svc.Names | Sort-Object -Unique).Count)
            $Svc.Env['CONTROL_PLANE_URL'] | Should -Be 'https://aegis.corp.example'
            $Svc.Env['AEGIS_DATAPLANE_KEY_FILE'] | Should -Be $StagedKey
            $Svc.Env['AEGIS_OPS_ADDR'] | Should -Be '0.0.0.0:9091'
            $Svc.Env['AEGIS_FAIL_MODE'] | Should -Be 'closed'
            $Svc.Env['AEGIS_PROXY_MODE'] | Should -Be 'regular'
            $Svc.Env['AEGIS_CLAMD_ADDRESS'] | Should -Be 'tcp://127.0.0.1:3310'
            $Svc.Env['AEGIS_CONTROL_PLANE_CA_FILE'] | Should -Be (Join-Path $SecretsDir 'control-plane-ca.pem')
            $Svc.Env['AEGIS_PUBLIC_URL'] | Should -Be 'https://aegis.corp.example'
            $Svc.Env['DASHBOARD_URL'] | Should -Be 'https://console.corp.example'
            $Svc.Env['AEGIS_WORKER_ID'] | Should -Be 'dp-win-01'
            $Svc.Env['AEGIS_LOG_LEVEL'] | Should -Be 'DEBUG'
            $Svc.Env['AEGIS_MAGIC_HOSTS'] | Should -Be 'a&b<c>"d''e'
            $Svc.Env['PYTHONNOUSERSITE'] | Should -Be '1'
        }

        It 'never writes or prints the data-plane key itself' {
            [System.IO.File]::ReadAllText($WrapperXml) | Should -Not -Match $KeyValue
            $Run.Output | Should -Not -Match $KeyValue
            ($FakeWin.Registry['HKLM:\SYSTEM\CurrentControlSet\Services\AegisDataPlane']['Environment'] -join ' ') | Should -Not -Match $KeyValue
        }

        It 'stages key and CA byte-exact (no BOM) and copies the control-plane CA bundle' {
            [System.IO.File]::ReadAllText($StagedKey) | Should -Be "$KeyValue`n"
            [System.IO.File]::ReadAllBytes($StagedKey)[0] | Should -Not -Be 0xEF
            [System.IO.File]::ReadAllText($StagedCa) | Should -Be ([System.IO.File]::ReadAllText($CaFile))
            Test-Path -LiteralPath (Join-Path $SecretsDir 'control-plane-ca.pem') | Should -BeTrue
        }

        It 'switches the service to its virtual account with recovery before the first start' {
            $svc = $FakeWin.Services['AegisDataPlane']
            $svc.ObjectName | Should -Be 'NT SERVICE\AegisDataPlane'
            $svc.SidType | Should -Be 'unrestricted'
            $svc.FailureActions | Should -Be 'restart/5000/restart/5000/restart/30000'
            $svc.FailureReset | Should -Be '3600'
            $svc.FailureFlag | Should -Be '1'
            $svc.Status | Should -Be 'Running'
            $order = @($FakeWin.Calls | Where-Object { ($_.Command -eq 'sc.exe' -and $_.Args[0] -eq 'config') -or $_.Command -eq 'Start-Service' } | ForEach-Object Command)
            $order | Should -Be @('sc.exe', 'Start-Service')
            (Get-RegistryEnvironment 'AegisDataPlane')['DOTNET_BUNDLE_EXTRACT_BASE_DIR'] | Should -Be $RuntimeDir
        }

        It 'lets only SYSTEM, Administrators and the service read the staged secrets' {
            foreach ($path in @($SecretsDir, $StagedKey, (Join-Path $SecretsDir 'control-plane-ca.pem'))) {
                Get-PrincipalList $path | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisDataPlane') -Because $path
                (Get-FakeAccess $path)['NT SERVICE\AegisDataPlane'] | Should -Be 'R'
            }
            Get-PrincipalList $StagedCa | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544', 'NT SERVICE\AegisDataPlane')
            (Get-FakeAccess $ConfDir)['NT SERVICE\AegisDataPlane'] | Should -Be 'M'
            (Get-FakeAccess $LogsDir)['NT SERVICE\AegisDataPlane'] | Should -Be 'M'
            (Get-FakeAccess $RuntimeDir)['NT SERVICE\AegisDataPlane'] | Should -Be 'M'
            Get-PrincipalList $DataRoot | Should -Be (Join-Sorted '*S-1-5-18', '*S-1-5-32-544')
        }

        It 'gives the service read/execute access to venv, addon and wrapper' {
            foreach ($path in @($VenvPython, (Join-Path $AppDir 'aegis_addon.py'), $WrapperExe, $WrapperXml)) {
                (Get-FakeAccess $path)['NT SERVICE\AegisDataPlane'] | Should -Be 'RX' -Because $path
                Test-FakeWritable $path | Should -BeFalse -Because $path
            }
        }

        It 'installs pinned mitmproxy and YARA-X (binary wheel) and the security overrides into the venv' {
            $pip = Get-PipCall
            $pip.Count | Should -Be 2
            $pip[0].Exe | Should -Be $VenvPython
            foreach ($arg in @('--require-virtualenv', '--no-input', 'mitmproxy==12.3.0', 'yara-x==1.22.0')) { $pip[0].Args | Should -Contain $arg }
            $pip[0].Args | Should -Not -Contain '--no-deps' -Because 'without a lock file pip resolves the dependencies'
            (Get-PipCall 'check').Count | Should -Be 0
            ($pip[0].Args -join ' ') | Should -Match '--only-binary yara-x'
            ($pip[1].Args -join ' ') | Should -Match '--no-deps --only-binary=:all: -r '
            $pip[1].Args[-1] | Should -Be $SecurityRequirements
            $FakeWin.Python.Packages['brotli'] | Should -Be '1.2.1'
            $Run.Output | Should -Match 'YARA-X available'
        }

        It 'copies the addon without tests and caches, then byte-compiles and import-checks it' {
            Test-Path -LiteralPath (Join-Path $AppDir 'aegis_addon.py') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path (Join-Path $AppDir 'aegis_dp') 'addon.py') | Should -BeTrue
            @(Get-ChildItem -LiteralPath $AppDir -Recurse -Directory | Where-Object Name -in @('tests', '__pycache__')).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $AppDir -Recurse -Filter '*.pyc').Count | Should -Be 0
            @(Get-FakeCall 'python' | Where-Object { $_.Args[1] -eq 'compileall' }).Count | Should -Be 1
            @(Get-FakeCall 'python' | Where-Object { $_.Args[1] -like 'import sys; sys.path.insert*' }).Count | Should -Be 1
        }

        It 'opens the proxy port for the server subnets and the ops port for monitoring only' {
            $proxy = $FakeWin.Firewall['AegisProxy-DataPlane-Proxy-In']
            $proxy.LocalPort | Should -Be 8080
            $proxy.RemoteAddress | Should -Be @('10.20.0.0/16', '10.30.0.0/16')
            $proxy.Profile | Should -Be @('Domain')
            $ops = $FakeWin.Firewall['AegisProxy-DataPlane-Ops-In']
            $ops.LocalPort | Should -Be 9091
            $ops.RemoteAddress | Should -Be @('10.99.0.5')
        }
    }

    Context 'variants' {
        It 'skips YARA-X with -NoYara' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ NoYara = $true })
            $run.ExitCode | Should -Be 0
            (Get-PipCall)[0].Args | Should -Not -Contain 'yara-x==1.22.0'
            $run.Output | Should -Match 'YARA-X is not installed'
        }

        It 'installs only the complete hash-pinned lock (--no-deps) with -RequirementsFile, then runs pip check' {
            $req = Join-Path $FakeWin.Root 'requirements-win.txt'
            Set-Content -LiteralPath $req -Value @('mitmproxy==12.3.0 --hash=sha256:aa', 'Brotli==1.2.1 --hash=sha256:bb', 'yara-x==1.22.0 --hash=sha256:cc')
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ RequirementsFile = $req; PipArgs = @('--no-index', '--find-links', '\\fs\wheels') })
            $run.ExitCode | Should -Be 0
            $pip = Get-PipCall
            $pip.Count | Should -Be 1
            ($pip[0].Args -join ' ') | Should -Match ([regex]::Escape("--require-hashes --no-deps -r $req --no-index --find-links \\fs\wheels"))
            $pip[0].Args | Should -Not -Contain 'mitmproxy==12.3.0'
            (Get-PipCall 'check').Count | Should -Be 1
        }

        It 'tolerates pip check conflicts caused by the baseline overrides only' {
            $req = Join-Path $FakeWin.Root 'requirements-win.txt'
            Set-Content -LiteralPath $req -Value @('mitmproxy==12.3.0 --hash=sha256:aa', 'Brotli==1.2.1 --hash=sha256:bb')
            $FakeWin.Python.PipCheck = @('mitmproxy 12.3.0 has requirement Brotli<=1.2.0,>=1.0, but you have brotli 1.2.1.')
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ RequirementsFile = $req })).ExitCode | Should -Be 0
        }

        It 'refuses a lock file that pip check reports as <Case>' -TestCases @(
            @{ Case = 'incomplete'; Line = 'mitmproxy 12.3.0 requires h11, which is not installed.' },
            @{ Case = 'inconsistent beyond the overrides'; Line = 'mitmproxy 12.3.0 has requirement h2<=4.2.0,>=4.1, but you have h2 4.3.0.' }
        ) {
            $req = Join-Path $FakeWin.Root 'requirements-win.txt'
            Set-Content -LiteralPath $req -Value @('mitmproxy==12.3.0 --hash=sha256:aa', 'Brotli==1.2.1 --hash=sha256:bb')
            $FakeWin.Python.PipCheck = @('mitmproxy 12.3.0 has requirement Brotli<=1.2.0,>=1.0, but you have brotli 1.2.1.', $Line)
            $err = { & $Installer @Base -RequirementsFile $req } | Should -Throw '*hash-pinned requirements file is incomplete or inconsistent*' -PassThru
            "$err" | Should -Match ([regex]::Escape($Line))
            "$err" | Should -Not -Match 'but you have brotli'
            $FakeWin.Services.Count | Should -Be 0
        }

        It 'refuses a hash-pinned requirements file below the security baseline' {
            $req = Join-Path $FakeWin.Root 'requirements-win.txt'
            Set-Content -LiteralPath $req -Value @('mitmproxy==12.3.0 --hash=sha256:aa', 'Brotli==1.1.0 --hash=sha256:bb')
            { & $Installer @Base -RequirementsFile $req } | Should -Throw '*Brotli 1.1.0*requires >= 1.2.1*'
        }

        It 'appends -PipArgs to both pip runs' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ PipArgs = @('--index-url', 'https://nexus.corp.example/simple') })).ExitCode | Should -Be 0
            $calls = Get-PipCall
            $calls.Count | Should -Be 2
            foreach ($call in $calls) { ($call.Args -join ' ') | Should -Match '--index-url https://nexus.corp.example/simple$' }
        }

        It 'runs as LocalService with -ServiceAccount LocalService' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ServiceAccount = 'LocalService' })).ExitCode | Should -Be 0
            $FakeWin.Services['AegisDataPlane'].ObjectName | Should -Be 'NT AUTHORITY\LocalService'
            (Get-FakeAccess $StagedKey)['*S-1-5-19'] | Should -Be 'R'
            (Get-FakeAccess $StagedKey).ContainsKey('NT SERVICE\AegisDataPlane') | Should -BeFalse
        }

        It 'creates no firewall rules with -SkipFirewall and no ops rule for a loopback ops address' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ SkipFirewall = $true })).ExitCode | Should -Be 0
            $FakeWin.Firewall.Count | Should -Be 0
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            @($FakeWin.Firewall.Keys) | Should -Be @('AegisProxy-DataPlane-Proxy-In')
        }

        It 'warns instead of opening a non-loopback ops port without -MonitoringRemoteAddress' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ OpsAddr = '10.0.0.5:9091' })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'no firewall rule created'
            $FakeWin.Firewall.Contains('AegisProxy-DataPlane-Ops-In') | Should -BeFalse
            $FakeWin.HttpProbes[0] | Should -Be 'http://10.0.0.5:9091/healthz'
        }

        It 'passes the access-log settings of the worker through -ExtraEnvironment' {
            $accessLog = @{ AEGIS_ACCESS_LOG = (Join-Path $LogsDir 'access.log'); AEGIS_ACCESS_LOG_FORMAT = 'json'
                AEGIS_ACCESS_LOG_ROTATE_MB = '100'; AEGIS_ACCESS_LOG_KEEP = '10' }
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ExtraEnvironment = $accessLog })).ExitCode | Should -Be 0
            $rendered = (Get-RenderedService).Env
            foreach ($name in $accessLog.Keys) { $rendered[$name] | Should -Be $accessLog[$name] }
        }

        It 'disables antivirus with an empty -ClamdAddress' {
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ClamdAddress = '' })
            $run.ExitCode | Should -Be 0
            (Get-RenderedService).Env.Contains('AEGIS_CLAMD_ADDRESS') | Should -BeFalse
            $run.Output | Should -Match 'Antivirus\s+: disabled'
        }

        It 'exits 1 with diagnostics when the worker never loads a policy' {
            $FakeWin.Ready = $false
            New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $LogsDir 'aegisdataplane.out.log') -Value 'policy sync failed: HTTP 401'
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ReadyTimeoutSeconds = 10 })
            $run.ExitCode | Should -Be 1
            $run.Output | Should -Match 'has not loaded a policy yet'
            $run.Output | Should -Match 'HTTP 401'
        }

        It 'exits 1 when the worker process never comes up' {
            $FakeWin.Alive = $false
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ ReadyTimeoutSeconds = 10 })
            $run.ExitCode | Should -Be 1
            $run.Output | Should -Match 'did not come up within 10 s'
        }

        It 'changes nothing with -WhatIf' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ WhatIf = $true })).ExitCode | Should -Be 0
            $FakeWin.Services.Count | Should -Be 0
            Test-Path -LiteralPath $InstallDir | Should -BeFalse
            Test-Path -LiteralPath $DataRoot | Should -BeFalse
        }
    }

    Context 'custom installation directory' {
        It 'does not let users plant modules or DLLs next to the service outside %ProgramFiles%' {
            $custom = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'AegisProxy\data-plane'))
            Register-FakeExecutable -Path (Join-Path (Join-Path $custom 'venv') 'Scripts\python.exe') -Function FakePython
            Register-FakeExecutable -Path (Join-Path $custom 'aegis-dataplane.exe') -Function FakeWinSW
            $script:WrapperXml = Join-Path $custom 'aegis-dataplane.xml'
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ InstallDir = $custom })).ExitCode | Should -Be 0
            foreach ($path in @($custom, (Join-Path $custom 'app'), (Join-Path (Join-Path $custom 'venv') 'Scripts'), (Join-Path $custom 'aegis-dataplane.exe'))) {
                Test-FakeWritable $path | Should -BeFalse -Because "$path is loaded by the service"
            }
        }
    }

    Context 're-run (upgrade)' {
        BeforeEach {
            (Invoke-Installer -Path $Installer -Parameters $Base).ExitCode | Should -Be 0
            $script:CaText = [System.IO.File]::ReadAllText($StagedCa)
        }

        It 'reinstalls the service, reuses the venv and keeps the staged CA without -CaFile' {
            $p = $Base.Clone(); $p.Remove('CaFile')
            (Invoke-Installer -Path $Installer -Parameters $p).ExitCode | Should -Be 0
            @(Get-FakeCall 'winsw' | ForEach-Object { $_.Args[0] }) | Should -Be @('install', 'uninstall', 'install')
            $FakeWin.Python.VenvsCreated | Should -Be 1
            [System.IO.File]::ReadAllText($StagedCa) | Should -Be $CaText
            $FakeWin.Services['AegisDataPlane'].ObjectName | Should -Be 'NT SERVICE\AegisDataPlane'
        }

        It 'keeps the CA when -CaFile points at the staged file itself' {
            $p = $Base.Clone(); $p.CaFile = $StagedCa
            (Invoke-Installer -Path $Installer -Parameters $p).ExitCode | Should -Be 0
            [System.IO.File]::ReadAllText($StagedCa) | Should -Be $CaText
        }

        It 'replaces the staged CA and removes artefacts of the previous one' {
            Set-Content -LiteralPath (Join-Path $ConfDir 'mitmproxy-ca-cert.p12') -Value 'old'
            $newDir = Join-Path $FakeWin.Root 'new-ca'
            New-TestCa -Dir $newDir | Out-Null
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ CaFile = (Join-Path $newDir 'mitmproxy-ca.pem') })).ExitCode | Should -Be 0
            [System.IO.File]::ReadAllText($StagedCa) | Should -Be ([System.IO.File]::ReadAllText((Join-Path $newDir 'mitmproxy-ca.pem')))
            Test-Path -LiteralPath (Join-Path $ConfDir 'mitmproxy-ca-cert.p12') | Should -BeFalse
        }

        It 'recreates the venv for another Python installation or with -RecreateVenv' {
            $py313 = Join-Path $env:ProgramFiles 'Python313\python.exe'
            New-FakeBinary -Path $py313
            Register-FakeExecutable -Path $py313 -Function FakePython
            $run = Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ PythonExe = $py313 })
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'recreating it for'
            $FakeWin.Python.VenvsCreated | Should -Be 2
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ PythonExe = $py313; RecreateVenv = $true })).ExitCode | Should -Be 0
            $FakeWin.Python.VenvsCreated | Should -Be 3
        }
    }

    Context 'uninstall' {
        It 'removes service, firewall rules, program files and the staged CA/key copies, but keeps the logs' {
            (Invoke-Installer -Path $Installer -Parameters (Join-Parameters $Base @{ OpsAddr = '0.0.0.0:9091'; MonitoringRemoteAddress = @('10.99.0.5') })).ExitCode | Should -Be 0
            Set-Content -LiteralPath (Join-Path $LogsDir 'aegisdataplane.out.log') -Value 'log'
            $run = Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; Confirm = $false }
            $run.ExitCode | Should -Be 0
            $FakeWin.Services.ContainsKey('AegisDataPlane') | Should -BeFalse
            $FakeWin.Firewall.Count | Should -Be 0
            foreach ($path in @($InstallDir, $ConfDir, $SecretsDir, $RuntimeDir)) { Test-Path -LiteralPath $path | Should -BeFalse -Because $path }
            Test-Path -LiteralPath (Join-Path $LogsDir 'aegisdataplane.out.log') | Should -BeTrue
            (Get-FakeCall 'winsw')[-1].Args[0] | Should -Be 'uninstall'
        }

        It 'is a no-op when nothing is installed' {
            $run = Invoke-Installer -Path $Installer -Parameters @{ Uninstall = $true; Confirm = $false }
            $run.ExitCode | Should -Be 0
            $run.Output | Should -Match 'is not installed'
        }
    }

    Context 'helpers' {
        BeforeAll {
            . ([scriptblock]::Create((Import-ScriptFunction -Path $Installer -Name 'ConvertTo-XmlText', 'Get-PemCertificateInfo', 'Get-HttpStatus', 'Invoke-Native')))
        }

        It 'ConvertTo-XmlText escapes markup and rejects control characters' {
            ConvertTo-XmlText 'a&b<c>"d''e' | Should -Be 'a&amp;b&lt;c&gt;&quot;d&apos;e'
            { ConvertTo-XmlText "a`nb" } | Should -Throw '*control characters*'
        }

        It 'Get-PemCertificateInfo reads the certificate from a key+certificate bundle' {
            (Get-PemCertificateInfo $CaFile).Fingerprint | Should -Be $CaFingerprint
            Set-Content -LiteralPath $KeyFile -Value 'no pem'
            Get-PemCertificateInfo $KeyFile | Should -BeNullOrEmpty
        }

        It 'Invoke-Native -NoThrow returns the exit code instead of throwing' {
            (Invoke-Native -FilePath 'sc.exe' -ArgumentList @('privs', 'Nope', 'x') -NoThrow).ExitCode | Should -Be 1060
            { Invoke-Native -FilePath 'sc.exe' -ArgumentList @('privs', 'Nope', 'x') } | Should -Throw '*exit code 1060*'
        }

        It 'Get-HttpStatus returns the status of a direct HTTP request, also for errors, and 0 if unreachable' {
            Remove-Alias -Name 'Get-HttpStatus' -Scope Global -Force
            $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add("http://127.0.0.1:$port/")
            $listener.Start()
            $job = Start-ThreadJob -ArgumentList $listener -ScriptBlock {
                param($l)
                for ($i = 0; $i -lt 2; $i++) {
                    $ctx = $l.GetContext()
                    $ctx.Response.StatusCode = if ($ctx.Request.Url.AbsolutePath -eq '/readyz') { 503 } else { 200 }
                    $ctx.Response.Close()
                }
            }
            try {
                Get-HttpStatus "http://127.0.0.1:$port/healthz" | Should -Be 200
                Get-HttpStatus "http://127.0.0.1:$port/readyz" | Should -Be 503
            }
            finally { $job | Wait-Job -Timeout 10 | Out-Null; $job | Remove-Job -Force; $listener.Stop() }
            Get-HttpStatus "http://127.0.0.1:$port/healthz" | Should -Be 0
        }
    }
}
