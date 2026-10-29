# Test doubles for the Windows installers (dot-sourced by the *.Tests.ps1 files).
#
# A small in-memory "Windows" - services, registry values, firewall rules, scheduled tasks, IIS objects,
# SMB connections and NTFS ACLs with owners and inheritance - sits behind stub commands, so the installers
# run unchanged under Pester on Linux and on Windows. Stubs are global functions (they take precedence over
# cmdlets and executables); executables the scripts start by full path (control-plane binary, WinSW,
# python.exe) are global aliases named after that path. Nothing here changes the real system: every
# system-changing command the installers use is replaced, and all files live below the per-test root.
# Junctions are modelled by real symbolic links below the root (both carry the ReparsePoint attribute).

$script:FakeStubFunctions = @(
    'Get-Service', 'Start-Service', 'Stop-Service', 'New-Service', 'Set-Service', 'Get-CimInstance', 'Invoke-CimMethod',
    'Get-NetFirewallRule', 'New-NetFirewallRule', 'Remove-NetFirewallRule',
    'Get-ScheduledTask', 'Register-ScheduledTask', 'Unregister-ScheduledTask', 'New-ScheduledTaskAction',
    'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'Get-WinEvent',
    'Install-WindowsFeature', 'Enable-WindowsOptionalFeature', 'Get-Acl', 'Get-SmbConnection', 'Get-SmbMapping',
    'sc.exe', 'icacls.exe', 'robocopy.exe',
    'FakeControlPlaneExe', 'FakePython', 'FakeWinSW', 'FakeHttpStatus')

$script:SidSystem = '*S-1-5-18'
$script:SidAdmins = '*S-1-5-32-544'
$script:SidUsers = '*S-1-5-32-545'
$script:SidAuthenticatedUsers = '*S-1-5-11'

function Initialize-FakeWindows {
    # Creates a fresh fake system below $Root and points the installers' environment variables at it.
    param([Parameter(Mandatory = $true)][string]$Root)
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $Root = (Resolve-Path -LiteralPath $Root).ProviderPath
    $global:FakeWin = @{
        Root          = $Root
        Now           = [datetime]::Now
        Services      = @{}
        Registry      = @{}
        RegistryTypes = @{}
        Firewall      = [ordered]@{}
        Tasks         = @{}
        Acl           = @{}
        Owner         = @{}        # full path -> owner SID; everything else is owned by Administrators
        IcaclsIgnore  = @()        # icacls switches that report success but change nothing (broken ACL tooling)
        IcaclsHook    = $null      # scriptblock run before each icacls call (args), e.g. a local user racing the installer
        Smb           = @{ Connections = @(); Mappings = @{} }
        Calls         = New-Object System.Collections.Generic.List[object]
        Aliases       = New-Object System.Collections.Generic.List[string]
        Healthy       = $true      # control-plane /healthz once running
        StartFails    = $false
        Alive         = $true      # data-plane /healthz once running
        Ready         = $true      # data-plane /readyz once running
        HttpProbes    = New-Object System.Collections.Generic.List[string]
        BinaryVersion = '2.1.0-test'
        VersionHangs  = $false
        VersionKilled = $false
        Python        = @{ Version = '3.12.10'; Packages = @{}; VenvsCreated = 0; PipCheck = @(); Requirements = @() }
        Iis           = @{ AppPools = @{}; Sites = @{}; Features = @(); Config = @{}; Collections = @{} }
        RewriteDll    = $true
        ArrDll        = $true
        RewriteReg    = $null
        Certificates  = @{}
    }
    $global:FakeWinSavedEnv = @{}
    foreach ($name in @('ProgramData', 'ProgramFiles', 'SystemDrive', 'SystemRoot', 'PATH', 'TEMP', 'TMP', 'TMPDIR', 'CONTROL_PLANE_PORT', 'AEGIS_TLS_CERT_FILE')) {
        $global:FakeWinSavedEnv[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $drive = Join-Path $Root 'C'
    $env:SystemDrive = $drive
    $env:ProgramData = Join-Path $drive 'ProgramData'
    $env:ProgramFiles = Join-Path $drive 'Program Files'
    if (-not $env:SystemRoot -or -not $IsWindows) { $env:SystemRoot = Join-Path $drive 'Windows' }
    foreach ($dir in @($env:ProgramData, $env:ProgramFiles)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # %ProgramFiles% as shipped: read/execute for users.
    $global:FakeWin.Acl[(Get-FakeFullPath $env:ProgramFiles)] = @{ Protected = $true; Grants = [ordered]@{
            $script:SidSystem = '(OI)(CI)F'; $script:SidAdmins = '(OI)(CI)F'; $script:SidUsers = '(OI)(CI)RX' } }
    # %ProgramData% as shipped: users may read and add files and folders (that they then own), not rename or delete those
    # of others.
    $global:FakeWin.Acl[(Get-FakeFullPath $env:ProgramData)] = @{ Protected = $true; Grants = [ordered]@{
            $script:SidSystem = '(OI)(CI)F'; $script:SidAdmins = '(OI)(CI)F'; $script:SidUsers = '(OI)(CI)RX'; 'BUILTIN\Users' = '(CI)(WD,AD,WEA,WA)' } }
    # System drive as on a Windows client SKU: authenticated users may create folders in the volume root and modify
    # everything below it. Paths there that the installers do not lock down explicitly show up as user-writable.
    $global:FakeWin.Acl[(Get-FakeFullPath $drive)] = @{ Protected = $true; Grants = [ordered]@{
            $script:SidSystem = '(OI)(CI)F'; $script:SidAdmins = '(OI)(CI)F'; $script:SidUsers = '(OI)(CI)RX'
            $script:SidAuthenticatedUsers = '(OI)(CI)(IO)M'; 'NT AUTHORITY\Authenticated Users' = '(AD)' } }
    # Everything else below the root (test sources, copied secrets, link targets) is a package folder as in the Windows
    # guide, section 2: only administrators can read and change it.
    $global:FakeWin.Acl[$Root] = @{ Protected = $true; Grants = [ordered]@{ $script:SidSystem = '(OI)(CI)F'; $script:SidAdmins = '(OI)(CI)F' } }

    function global:Get-Service {
        [CmdletBinding()]
        param([Parameter(Position = 0)][string[]]$Name)
        foreach ($n in $Name) {
            $svc = $global:FakeWin.Services[$n]
            if ($svc) { [pscustomobject]@{ Name = $n; Status = $svc.Status; StartType = $svc.StartType } }
            else { Write-Error -Message "Cannot find any service with service name '$n'." -Category ObjectNotFound }
        }
    }
    function global:Start-Service {
        [CmdletBinding()]
        param([string]$Name)
        Add-FakeCall 'Start-Service' @($Name)
        $svc = $global:FakeWin.Services[$Name]
        if (-not $svc) { throw "Cannot find any service with service name '$Name'." }
        if ($global:FakeWin.StartFails) { $svc.Status = 'Stopped'; throw "Service '$Name' failed to start." }
        $svc.Status = 'Running'
    }
    function global:Stop-Service {
        [CmdletBinding()]
        param([string]$Name, [switch]$Force)
        Add-FakeCall 'Stop-Service' @($Name)
        $svc = $global:FakeWin.Services[$Name]
        if (-not $svc) { throw "Cannot find any service with service name '$Name'." }
        $svc.Status = 'Stopped'
    }
    function global:New-Service {
        [CmdletBinding()]
        param([string]$Name, [string]$BinaryPathName, [string]$DisplayName, [string]$Description, [string]$StartupType)
        Add-FakeCall 'New-Service' @($Name, $BinaryPathName)
        if ($global:FakeWin.Services.ContainsKey($Name)) { throw "Service $Name already exists." }
        $global:FakeWin.Services[$Name] = @{ Status = 'Stopped'; PathName = $BinaryPathName; DisplayName = $DisplayName
            Description = $Description; StartType = $StartupType; ObjectName = 'LocalSystem' }
        $global:FakeWin.Registry["HKLM:\SYSTEM\CurrentControlSet\Services\$Name"] = @{}
        [pscustomobject]@{ Name = $Name }
    }
    function global:Set-Service {
        [CmdletBinding()]
        param([string]$Name, [string]$StartupType, [string]$DisplayName, [string]$Description)
        $svc = $global:FakeWin.Services[$Name]
        if (-not $svc) { throw "Cannot find any service with service name '$Name'." }
        if ($StartupType) { $svc.StartType = $StartupType }
        if ($DisplayName) { $svc.DisplayName = $DisplayName }
        if ($Description) { $svc.Description = $Description }
    }
    function global:Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string]$Filter)
        if ($ClassName -ne 'Win32_Service' -or $Filter -notmatch "^Name='(?<n>[^']+)'$") { throw "unsupported CIM query: $ClassName $Filter" }
        $svc = $global:FakeWin.Services[$Matches['n']]
        if ($svc) { [pscustomobject]@{ Name = $Matches['n']; PathName = $svc.PathName } }
    }
    function global:Invoke-CimMethod {
        [CmdletBinding()]
        param($InputObject, [string]$MethodName, [hashtable]$Arguments)
        Add-FakeCall 'Invoke-CimMethod' @($InputObject.Name, $MethodName, $Arguments.PathName)
        $global:FakeWin.Services[$InputObject.Name].PathName = $Arguments.PathName
        [pscustomobject]@{ ReturnValue = 0 }
    }

    function global:Get-NetFirewallRule {
        [CmdletBinding()]
        param([string[]]$Name)
        foreach ($n in $Name) {
            if ($global:FakeWin.Firewall.Contains($n)) { [pscustomobject]@{ Name = $n } }
            else { Write-Error -Message "No MSFT_NetFirewallRule objects found with property 'InstanceID' equal to '$n'." -Category ObjectNotFound }
        }
    }
    function global:Remove-NetFirewallRule {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process { $global:FakeWin.Firewall.Remove($InputObject.Name) }
    }
    function global:New-NetFirewallRule {
        [CmdletBinding()]
        param([string]$Name, [string]$DisplayName, [string]$Group, [string]$Direction, [string]$Action, [string]$Protocol,
            $LocalPort, [string]$Program, [string[]]$Profile, [string[]]$RemoteAddress)
        if ($global:FakeWin.Firewall.Contains($Name)) { throw "A rule with the name $Name already exists." }
        $global:FakeWin.Firewall[$Name] = @{ DisplayName = $DisplayName; Group = $Group; Direction = $Direction; Action = $Action
            Protocol = $Protocol; LocalPort = $LocalPort; Program = $Program; Profile = @($Profile); RemoteAddress = @($RemoteAddress) }
    }

    function global:New-ScheduledTaskAction { param([string]$Execute, [string]$Argument) [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
    function global:New-ScheduledTaskTrigger { param([switch]$Daily, $At) [pscustomobject]@{ Daily = [bool]$Daily; At = "$At" } }
    function global:New-ScheduledTaskPrincipal { param([string]$UserId, [string]$LogonType, [string]$RunLevel) [pscustomobject]@{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel } }
    function global:New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable, $ExecutionTimeLimit) [pscustomobject]@{ StartWhenAvailable = [bool]$StartWhenAvailable; ExecutionTimeLimit = $ExecutionTimeLimit } }
    function global:Register-ScheduledTask {
        [CmdletBinding()]
        param([string]$TaskName, [string]$TaskPath, $Action, $Trigger, $Principal, $Settings, [string]$Description, [switch]$Force)
        $key = "$TaskPath$TaskName"
        if ($global:FakeWin.Tasks.ContainsKey($key) -and -not $Force) { throw "Task $key exists." }
        if ($Principal -and "$($Principal.UserId)" -match '\\' -and -not (Test-FakePrincipal $Principal.UserId)) {
            throw "No mapping between account names and security IDs was done: $($Principal.UserId)"
        }
        $global:FakeWin.Tasks[$key] = @{ Action = $Action; Trigger = $Trigger; Principal = $Principal; Settings = $Settings; Description = $Description }
    }
    function global:Get-ScheduledTask {
        [CmdletBinding()]
        param([string]$TaskName, [string]$TaskPath)
        if ($global:FakeWin.Tasks.ContainsKey("$TaskPath$TaskName")) { [pscustomobject]@{ TaskName = $TaskName; TaskPath = $TaskPath } }
        else { Write-Error -Message "No MSFT_ScheduledTask objects found with property 'TaskName' equal to '$TaskName'." -Category ObjectNotFound }
    }
    function global:Unregister-ScheduledTask {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process { $global:FakeWin.Tasks.Remove("$($InputObject.TaskPath)$($InputObject.TaskName)") }
    }
    function global:Get-WinEvent { [CmdletBinding()] param($FilterHashtable, $MaxEvents) throw 'No events were found that match the specified selection criteria.' }
    function global:Install-WindowsFeature {
        param([string[]]$Name)
        $global:FakeWin.Iis.Features = @($Name)
        [pscustomobject]@{ Success = $true; RestartNeeded = 'No' }
    }
    function global:Enable-WindowsOptionalFeature { param([switch]$Online, [string[]]$FeatureName, [switch]$All, [switch]$NoRestart) $global:FakeWin.Iis.Features = @($FeatureName) }

    function global:Get-Acl {
        # Owner, protection flag and access rules (SIDs) as the real cmdlet reports them for
        # GetOwner/GetAccessRules(..., [SecurityIdentifier]).
        [CmdletBinding()]
        param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath)
        $target = Get-FakeFullPath "$LiteralPath$Path"
        if (-not ([System.IO.File]::Exists($target) -or [System.IO.Directory]::Exists($target))) { throw "Cannot find path '$target' because it does not exist." }
        $entry = $global:FakeWin.Acl[$target]
        $acl = [pscustomobject]@{
            Owner                   = $(if ($global:FakeWin.Owner.ContainsKey($target)) { $global:FakeWin.Owner[$target] } else { 'S-1-5-32-544' })
            AreAccessRulesProtected = [bool]($entry -and $entry.Protected)
            Rules                   = @(Get-FakeAccessRule $target)
        }
        Add-Member -InputObject $acl -MemberType ScriptMethod -Name GetOwner -Value { param($Type) [pscustomobject]@{ Value = $this.Owner } }
        Add-Member -InputObject $acl -MemberType ScriptMethod -Name GetAccessRules -Value {
            param($IncludeExplicit, $IncludeInherited, $Type)
            @($this.Rules | Where-Object { ($IncludeExplicit -and -not $_.IsInherited) -or ($IncludeInherited -and $_.IsInherited) })
        }
        $acl
    }

    function global:Get-SmbConnection {
        [CmdletBinding()]
        param([string]$ServerName)
        @($global:FakeWin.Smb.Connections | Where-Object { -not $ServerName -or $_.ServerName -eq $ServerName })
    }
    function global:Get-SmbMapping {
        [CmdletBinding()]
        param([string]$LocalPath)
        $mapping = $global:FakeWin.Smb.Mappings[$LocalPath.ToUpperInvariant()]
        if ($mapping) { [pscustomobject]@{ LocalPath = $LocalPath; RemotePath = $mapping; Status = 'OK' } }
        else { Write-Error -Message "No MSFT_SmbMapping objects found with property 'LocalPath' equal to '$LocalPath'." -Category ObjectNotFound }
    }

    function global:sc.exe {
        $a = @($args)
        Add-FakeCall 'sc.exe' $a
        $global:LASTEXITCODE = 0
        $name = $a[1]
        $svc = $global:FakeWin.Services[$name]
        if (-not $svc) {
            '[SC] OpenService FAILED 1060:'; 'The specified service does not exist as an installed service.'
            $global:LASTEXITCODE = 1060; return
        }
        switch ($a[0]) {
            'config' {
                for ($i = 2; $i + 1 -lt $a.Count; $i += 2) {
                    if ($a[$i] -eq 'obj=') { $svc.ObjectName = $a[$i + 1] } else { $global:LASTEXITCODE = 87; return }
                }
            }
            'sidtype' { $svc.SidType = $a[2] }
            'privs' { $svc.Privileges = $a[2] }
            'failure' {
                for ($i = 2; $i + 1 -lt $a.Count; $i += 2) {
                    switch ($a[$i]) { 'reset=' { $svc.FailureReset = $a[$i + 1] } 'actions=' { $svc.FailureActions = $a[$i + 1] } default { $global:LASTEXITCODE = 87; return } }
                }
            }
            'failureflag' { $svc.FailureFlag = $a[2] }
            'delete' {
                $global:FakeWin.Services.Remove($name)
                $global:FakeWin.Registry.Remove("HKLM:\SYSTEM\CurrentControlSet\Services\$name")
            }
            default { $global:LASTEXITCODE = 87; return }
        }
        '[SC] SUCCESS'
    }

    function global:icacls.exe {
        # Supports the subset the installers use: <path> [/setowner principal] [/reset] [/inheritance:r]
        # [/grant:r principal:(flags)rights ...] [/remove[:g|:d] principal] [/T] [/L] [/C] [/Q]. With /T, /setowner and
        # /reset also apply to everything below <path>; /reset drops the explicit ACEs (the item inherits again).
        # Like the real tool, a link (junction / symbolic link) is followed - its target is changed, and /T descends
        # into linked directories - unless /L is given, which changes the link itself. FakeWin.IcaclsHook (if set)
        # runs before each call with its arguments, e.g. to let a "local user" race the installer.
        $a = @($args)
        Add-FakeCall 'icacls.exe' $a
        if ($global:FakeWin.IcaclsHook) { & $global:FakeWin.IcaclsHook $a }
        $global:LASTEXITCODE = 0
        $path = Get-FakeFullPath $a[0]
        if (-not ([System.IO.File]::Exists($path) -or [System.IO.Directory]::Exists($path))) { "${path}: The system cannot find the file specified."; $global:LASTEXITCODE = 2; return }
        if ($a -notcontains '/L') {
            $item = Get-Item -LiteralPath $path -Force
            if ($item.LinkTarget) { $path = Get-FakeFullPath ([System.IO.Path]::Combine((Split-Path -Parent $path), $item.LinkTarget)) }
        }
        $ops = New-Object System.Collections.Generic.List[object]
        $mode = $null; $recurse = $false
        for ($i = 1; $i -lt $a.Count; $i++) {
            $t = $a[$i]
            switch -Regex ($t) {
                '^/inheritance:r$' { $ops.Add(@('protect')); $mode = $null; continue }
                '^/grant:r$' { $mode = 'grant'; continue }
                '^/reset$' { $ops.Add(@('reset')); $mode = $null; continue }
                '^/(setowner|remove(:[gd])?)$' {
                    $principal = "$($a[$i + 1])"; $i++
                    if (-not (Test-FakePrincipal $principal)) {
                        "${principal}: No mapping between account names and security IDs was done."; $global:LASTEXITCODE = 1332; return
                    }
                    $ops.Add(@(($t -replace ':[gd]$', '').TrimStart('/'), $principal)); $mode = $null; continue
                }
                '^/T$' { $recurse = $true; continue }
                '^/[CQL]$' { $mode = $null; continue }
                '^/' { "Invalid parameter `"$t`""; $global:LASTEXITCODE = 87; return }
                default {
                    if ($mode -ne 'grant' -or $t -notmatch '^(?<p>[^:]+):(?<ace>(\((OI|CI|IO|NP)\))*(F|M|RX|R|W|\([A-Z]+(,[A-Z]+)*\)))$') {
                        "Invalid parameter `"$t`""; $global:LASTEXITCODE = 87; return
                    }
                    $principal = $Matches['p']; $ace = $Matches['ace']
                    if (-not (Test-FakePrincipal $principal)) {
                        "${principal}: No mapping between account names and security IDs was done."; $global:LASTEXITCODE = 1332; return
                    }
                    $ops.Add(@('grant', $principal, $ace))
                }
            }
        }
        $targets = @($path)
        if ($recurse -and [System.IO.Directory]::Exists($path)) {
            # Without /L, linked directories are entered and their content is changed at its real location.
            $follow = $a -notcontains '/L'
            $pending = New-Object System.Collections.Stack
            $pending.Push($path)
            while ($pending.Count) {
                foreach ($child in @(Get-ChildItem -LiteralPath $pending.Pop() -Force)) {
                    $real = Get-FakeFullPath $child.FullName
                    if ($follow -and $child.LinkTarget) { $real = Get-FakeFullPath $child.ResolveLinkTarget($true).FullName }
                    $targets += $real
                    if ([System.IO.Directory]::Exists($real) -and ($follow -or -not $child.LinkTarget)) { $pending.Push($real) }
                }
            }
        }
        foreach ($op in $ops) {
            if ($global:FakeWin.IcaclsIgnore -contains "/$($op[0])") { continue }
            switch ($op[0]) {
                'setowner' { foreach ($target in $targets) { $global:FakeWin.Owner[$target] = Get-FakeSid $op[1] } }
                'reset' { foreach ($target in $targets) { $global:FakeWin.Acl.Remove($target) } }
                default {
                    $entry = $global:FakeWin.Acl[$path]
                    if (-not $entry) { $entry = @{ Protected = $false; Grants = [ordered]@{} }; $global:FakeWin.Acl[$path] = $entry }
                    switch ($op[0]) {
                        'protect' { $entry.Protected = $true }
                        'grant' { $entry.Grants[$op[1]] = $op[2] }
                        'remove' {
                            $sid = Get-FakeSid $op[1]
                            foreach ($key in @($entry.Grants.Keys)) { if ((Get-FakeSid $key) -eq $sid) { $entry.Grants.Remove($key) } }
                        }
                    }
                }
            }
        }
        'Successfully processed {0} files; Failed processing 0 files' -f $targets.Count
    }

    function global:robocopy.exe {
        # <source> <destination> /MIR [/XD dirs...] [/XF files...] and output-only switches.
        $a = @($args)
        Add-FakeCall 'robocopy.exe' $a
        $src = $a[0]; $dst = $a[1]; $xd = @(); $xf = @(); $list = $null; $mirror = $false
        for ($i = 2; $i -lt $a.Count; $i++) {
            $t = $a[$i]
            if ($t.StartsWith('/')) {
                $list = $null
                switch ($t.ToUpperInvariant()) { '/MIR' { $mirror = $true } '/XD' { $list = 'XD' } '/XF' { $list = 'XF' } }
                continue
            }
            if ($list -eq 'XD') { $xd += $t } elseif ($list -eq 'XF') { $xf += $t }
        }
        if (-not (Test-Path -LiteralPath $src -PathType Container)) { "ERROR 2 (0x00000002) Accessing Source Directory $src"; $global:LASTEXITCODE = 16; return }
        $srcFull = (Resolve-Path -LiteralPath $src).ProviderPath
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        $dstFull = (Resolve-Path -LiteralPath $dst).ProviderPath
        $wanted = @{}
        $copied = 0
        foreach ($file in Get-ChildItem -LiteralPath $srcFull -Recurse -File -Force) {
            $rel = $file.FullName.Substring($srcFull.Length).TrimStart('\', '/')
            if (Test-RobocopyExcluded $rel $xd $xf) { continue }
            $wanted[$rel] = $true
            $target = Join-Path $dstFull $rel
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force
            $copied++
        }
        $extra = 0
        if ($mirror) {
            foreach ($file in @(Get-ChildItem -LiteralPath $dstFull -Recurse -File -Force)) {
                $rel = $file.FullName.Substring($dstFull.Length).TrimStart('\', '/')
                if ($wanted.ContainsKey($rel) -or (Test-RobocopyExcluded $rel $xd $xf)) { continue }
                Remove-Item -LiteralPath $file.FullName -Force
                $extra = 2
            }
        }
        $global:LASTEXITCODE = [int]($copied -gt 0) + $extra
    }

    function global:FakeControlPlaneExe {
        $a = @($args)
        $global:FakeWin.Calls.Add([pscustomobject]@{ Command = 'aegis-control-plane'; Args = $a
                Port = $env:CONTROL_PLANE_PORT; Tls = $env:AEGIS_TLS_CERT_FILE })
        switch ($a[0]) {
            'gen-ca' { $fp = New-TestCa -Dir $a[1]; "Root CA ready in $($a[1])"; "  fingerprint: $fp"; $global:LASTEXITCODE = 0 }
            'healthcheck' {
                # Like the real probe: GET http(s)://127.0.0.1:<CONTROL_PLANE_PORT>/healthz.
                $svc = $global:FakeWin.Services['AegisControlPlane']
                $listen = (Get-RegistryEnvironment 'AegisControlPlane')['AEGIS_LISTEN_ADDR']
                $ipv4Loopback = (-not $listen) -or ($listen -match '^(|0\.0\.0\.0|127\.0\.0\.1|\[::\]|::):\d+$')
                $global:LASTEXITCODE = if ($svc -and $svc.Status -eq 'Running' -and $global:FakeWin.Healthy -and $ipv4Loopback) { 0 } else { 1 }
            }
            default { $global:LASTEXITCODE = 2 }
        }
    }

    function global:FakePython {
        # python.exe double: version probe, venv creation, pip, compileall and the import checks. Leading interpreter
        # options (-I, -S, -E, ...) are recorded as Options; Args holds the rest of the command line, PipEnv the PIP_*
        # variables the process got.
        $a = @($args)
        $options = @()
        while ($a.Count -and $a[0] -cmatch '^-[BEIOPSsuv]$') { $options += $a[0]; $a = @($a | Select-Object -Skip 1) }
        $self = $global:FakeWin.InvokedExe
        $pipEnv = [ordered]@{}
        foreach ($item in @(Get-ChildItem -Path Env: | Where-Object { $_.Name -like 'PIP_*' } | Sort-Object -Property Name)) { $pipEnv[$item.Name] = $item.Value }
        $global:FakeWin.Calls.Add([pscustomobject]@{ Command = 'python'; Exe = $self; Options = $options; Args = $a; PipEnv = $pipEnv })
        $py = $global:FakeWin.Python
        $global:LASTEXITCODE = 0
        if ($a[0] -eq '-m' -and $a[1] -eq 'venv') {
            $scripts = Join-Path $a[2] 'Scripts'
            New-Item -ItemType Directory -Path $scripts -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $scripts 'python.exe') -Value 'venv python'
            Set-Content -LiteralPath (Join-Path $a[2] 'pyvenv.cfg') -Value @("home = $(Split-Path -Parent $self)", "version = $($py.Version)")
            $py.VenvsCreated++
            return
        }
        if ($a[0] -eq '-m' -and $a[1] -eq 'pip' -and $a[2] -eq 'check') {
            if ($py.PipCheck.Count) { $py.PipCheck; $global:LASTEXITCODE = 1 } else { 'No broken requirements found.' }
            return
        }
        if ($a[0] -eq '-m' -and $a[1] -eq 'pip') {
            $scripts = Split-Path -Parent $self
            # Like pip (pip/_internal/configuration.py), independent of -I and --isolated: the configuration files -
            # the global %ProgramData%\pip\pip.ini and PIP_CONFIG_FILE - count unless PIP_CONFIG_FILE is os.devnull
            # ('nul'), then the PIP_* variables. Modelled: "requirement = <file>" and PIP_REQUIREMENT add a -r file.
            $extra = @()
            if ($env:PIP_CONFIG_FILE -cne 'nul') {
                foreach ($ini in @((Join-Path $env:ProgramData 'pip\pip.ini'), $env:PIP_CONFIG_FILE)) {
                    if (-not $ini -or -not [System.IO.File]::Exists($ini)) { continue }
                    foreach ($line in [System.IO.File]::ReadAllLines($ini)) { if ($line -match '^\s*requirement\s*=\s*(?<f>\S.*?)\s*$') { $extra += @('-r', $Matches['f']) } }
                }
            }
            if ($env:PIP_REQUIREMENT) { $extra += @('-r', $env:PIP_REQUIREMENT) }
            $a = @($a) + $extra
            for ($i = 2; $i -lt $a.Count; $i++) {
                if ($a[$i] -eq '-r') {
                    # Kept for the tests: the installer may delete a requirements file it generated.
                    $py.Requirements += [pscustomobject]@{ Path = $a[$i + 1]; Lines = @(Get-Content -LiteralPath $a[$i + 1]) }
                    foreach ($line in Get-Content -LiteralPath $a[$i + 1]) {
                        if ($line -match '^\s*(?<n>[A-Za-z0-9._-]+)==(?<v>[0-9][^\s;]*)') { $py.Packages[$Matches['n'].ToLowerInvariant()] = $Matches['v'] }
                    }
                    $i++
                }
                elseif ($a[$i] -match '^(?<n>[A-Za-z0-9._-]+)==(?<v>[0-9][^\s;]*)$') {
                    $py.Packages[$Matches['n'].ToLowerInvariant()] = $Matches['v']
                    # mitmproxy's own metadata caps Brotli below the fixed release.
                    if ($Matches['n'] -eq 'mitmproxy') { $py.Packages['brotli'] = '1.1.0' }
                }
            }
            if ($py.Packages.ContainsKey('mitmproxy')) { Set-Content -LiteralPath (Join-Path $scripts 'mitmdump.exe') -Value 'mitmdump' }
            return
        }
        if ($a[0] -eq '-m' -and $a[1] -eq 'compileall') { return }
        if ($a[0] -eq '-c') {
            switch -Wildcard ($a[1]) {
                'import sys; print(sys.version_info*' { $py.Version; return }
                'import http.server*' { if ($py.Packages.ContainsKey('mitmproxy')) { $py.Packages['mitmproxy'] } else { 'ModuleNotFoundError'; $global:LASTEXITCODE = 1 }; return }
                'import yara_x' { if (-not $py.Packages.ContainsKey('yara-x')) { 'ModuleNotFoundError'; $global:LASTEXITCODE = 1 }; return }
                'import re, sys, importlib.metadata*' {
                    # Security baseline check: installed versions against requirements-security.txt (packaging.version).
                    $low = @()
                    foreach ($line in Get-Content -LiteralPath $a[2]) {
                        if ($line -notmatch '^\s*(?<n>[A-Za-z0-9._-]+)==(?<v>\S+)') { continue }
                        $name = $Matches['n']; $minimum = $Matches['v']
                        $have = $py.Packages[$name.ToLowerInvariant()]
                        if (-not $have) { continue }
                        $cmp = Compare-FakePep440 $have $minimum
                        if ($null -eq $cmp) { 'Traceback (most recent call last):'; "packaging.version.InvalidVersion: Invalid version: '$have'"; $global:LASTEXITCODE = 1; return }
                        if ($cmp -lt 0) { $low += "$name $have < $minimum" }
                    }
                    $low -join '; '
                    $global:LASTEXITCODE = [int]($low.Count -gt 0)
                    return
                }
                'import importlib.metadata*' {
                    $n = "$($a[2])".ToLowerInvariant()
                    if ($py.Packages.ContainsKey($n)) { $py.Packages[$n] } else { 'PackageNotFoundError'; $global:LASTEXITCODE = 1 }
                    return
                }
                'import sys; sys.path.insert*' {
                    if (-not (Test-Path -LiteralPath (Join-Path $a[2] 'aegis_dp/addon.py'))) { 'ModuleNotFoundError'; $global:LASTEXITCODE = 1 }
                    return
                }
            }
        }
        "unexpected python invocation: $($a -join ' ')"; $global:LASTEXITCODE = 2
    }

    function global:FakeWinSW {
        # WinSW 2.x: reads <exe base name>.xml next to the executable.
        $a = @($args)
        $self = $global:FakeWin.InvokedExe
        Add-FakeCall 'winsw' $a
        $global:LASTEXITCODE = 0
        $xmlPath = [System.IO.Path]::ChangeExtension($self, '.xml')
        switch ($a[0]) {
            'install' {
                $xml = [xml][System.IO.File]::ReadAllText($xmlPath)
                $id = $xml.service.id
                if ($global:FakeWin.Services.ContainsKey($id)) { "Service '$id' already exists."; $global:LASTEXITCODE = 1; return }
                $global:FakeWin.Services[$id] = @{ Status = 'Stopped'; PathName = "`"$self`""; StartType = $xml.service.startmode
                    ObjectName = 'LocalSystem'; Xml = $xml.OuterXml }
                $global:FakeWin.Registry["HKLM:\SYSTEM\CurrentControlSet\Services\$id"] = @{}
                "Installing service '$id'..."
            }
            'uninstall' {
                $xml = [xml][System.IO.File]::ReadAllText($xmlPath)
                $id = $xml.service.id
                $global:FakeWin.Services.Remove($id)
                $global:FakeWin.Registry.Remove("HKLM:\SYSTEM\CurrentControlSet\Services\$id")
            }
            default { $global:LASTEXITCODE = 1 }
        }
    }

    function global:FakeHttpStatus {
        param([string]$Url)
        $global:FakeWin.HttpProbes.Add($Url)
        $svc = $global:FakeWin.Services['AegisDataPlane']
        if (-not $svc -or $svc.Status -ne 'Running' -or -not $global:FakeWin.Alive) { return 0 }
        if ($Url -like '*/readyz') { if ($global:FakeWin.Ready) { return 200 } else { return 503 } }
        return 200
    }
}

function Add-FakeWindowsMock {
    # Pester mocks for cmdlets that exist on every platform; only the calls the fakes own are redirected.
    Mock Start-Sleep {
        $ms = if ($Milliseconds) { $Milliseconds } else { 1000 * $Seconds }
        $global:FakeWin.Now = $global:FakeWin.Now.AddMilliseconds($ms)
    }
    Mock Get-Date { $global:FakeWin.Now } -ParameterFilter { -not $Format -and -not $Date }
    Mock Get-ItemProperty -ParameterFilter { "$Path" -like 'HKLM:*' } {
        $key = $global:FakeWin.Registry["$Path"]
        if ($null -eq $key) { return }
        if ($Name) { if ($key.ContainsKey("$Name")) { [pscustomobject]@{ "$Name" = $key["$Name"] } } }
        else { [pscustomobject]$key }
    }
    Mock New-ItemProperty -ParameterFilter { "$Path" -like 'HKLM:*' } {
        $key = $global:FakeWin.Registry["$Path"]
        if ($null -eq $key) { throw "Cannot find path '$Path' because it does not exist." }
        $key["$Name"] = if ("$PropertyType" -eq 'MultiString') { [string[]]@($Value) } else { $Value }
        $global:FakeWin.RegistryTypes["$Path|$Name"] = "$PropertyType"
    }
    Mock Test-Path -ParameterFilter { "$LiteralPath$Path" -like 'HKLM:*' } { $global:FakeWin.Registry.ContainsKey("$LiteralPath$Path") }
    Mock New-Item -ParameterFilter { "$Path" -like 'HKLM:*' } {
        if ($global:FakeWin.Registry.ContainsKey("$Path") -and -not $Force) { throw "A key at this path already exists: $Path" }
        Add-FakeCall 'New-Item' @("$Path")
        $global:FakeWin.Registry["$Path"] = @{}
    }
    Mock Remove-Item -ParameterFilter { "$LiteralPath" -like 'HKLM:*' } {
        foreach ($k in @($global:FakeWin.Registry.Keys)) { if ($k -eq "$LiteralPath" -or $k -like "$LiteralPath\*") { $global:FakeWin.Registry.Remove($k) } }
    }
    Mock Start-Process -ParameterFilter { @($ArgumentList) -contains 'version' } {
        Add-FakeCall 'Start-Process' @($FilePath, $ArgumentList)
        if ($RedirectStandardOutput) { [System.IO.File]::WriteAllText($RedirectStandardOutput, $global:FakeWin.BinaryVersion + "`n") }
        $proc = [pscustomobject]@{ ExitCode = 0 }
        Add-Member -InputObject $proc -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) -not $global:FakeWin.VersionHangs }
        Add-Member -InputObject $proc -MemberType ScriptMethod -Name Kill -Value { $global:FakeWin.VersionKilled = $true }
        $proc
    }
}

function Remove-FakeWindows {
    foreach ($name in $script:FakeStubFunctions) { Remove-Item -LiteralPath "Function:\$name" -Force -ErrorAction SilentlyContinue }
    if (Get-Variable -Name FakeWin -Scope Global -ErrorAction SilentlyContinue) {
        for ($i = 0; $i -lt $global:FakeWin.Aliases.Count; $i++) {
            Remove-Alias -Name $global:FakeWin.Aliases[$i] -Scope Global -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "Function:\FakeExe$i" -Force -ErrorAction SilentlyContinue
        }
    }
    if (Get-Variable -Name FakeWinSavedEnv -Scope Global -ErrorAction SilentlyContinue) {
        foreach ($name in $global:FakeWinSavedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $global:FakeWinSavedEnv[$name]) }
    }
}

function Register-FakeExecutable {
    # Routes "& '<path>' ..." in the installers to a fake: an alias named after the path (aliases are
    # resolved before files) points to a wrapper that records which path was invoked.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Function)
    $wrapper = 'FakeExe{0}' -f $global:FakeWin.Aliases.Count
    $body = "`$global:FakeWin.InvokedExe = '{0}'; {1} @args" -f $Path.Replace("'", "''"), $Function
    Set-Item -LiteralPath "Function:\global:$wrapper" -Value ([scriptblock]::Create($body))
    Set-Alias -Name $Path -Value $wrapper -Scope Global -Force
    $global:FakeWin.Aliases.Add($Path)
}

function Join-Parameters([hashtable]$Base, [hashtable]$Extra) {
    # Copy of $Base with the entries of $Extra added or replaced (splatting helper).
    $result = $Base.Clone()
    foreach ($key in $Extra.Keys) { $result[$key] = $Extra[$key] }
    return $result
}

function global:Get-RegistryEnvironment([string]$ServiceName) {
    # The service's REG_MULTI_SZ Environment as an ordered name -> value map.
    $map = [ordered]@{}
    $key = $global:FakeWin.Registry["HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"]
    if ($key -and $key.ContainsKey('Environment')) {
        foreach ($line in $key['Environment']) { $pair = $line -split '=', 2; $map[$pair[0]] = $pair[1] }
    }
    return $map
}

function global:Add-FakeCall([string]$Command, [object[]]$Arguments) {
    $global:FakeWin.Calls.Add([pscustomobject]@{ Command = $Command; Args = @($Arguments) })
}

function Get-FakeCall([string]$Command) {
    @($global:FakeWin.Calls | Where-Object { $_.Command -eq $Command })
}

function global:Get-FakeFullPath([string]$Path) {
    # Without a trailing separator, except for a root ('/', 'C:\').
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.Length -gt [System.IO.Path]::GetPathRoot($full).Length) { $full = $full.TrimEnd('\', '/') }
    $full
}

function global:Test-FakePrincipal([string]$Principal) {
    # Well-known SIDs and builtin names always resolve; per-service / app-pool accounts only once they exist.
    if ($Principal -match '^\*S-1-') { return $true }
    if ($Principal -match '^NT SERVICE\\(?<svc>.+)$') { return $global:FakeWin.Services.ContainsKey($Matches['svc']) }
    if ($Principal -match '^IIS AppPool\\(?<pool>.+)$') { return $global:FakeWin.Iis.AppPools.ContainsKey($Matches['pool']) }
    return $Principal -in @('NT AUTHORITY\LocalService', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Users')
}

function global:Get-FakeSid([string]$Principal) {
    # SID string of an icacls principal; virtual accounts are hashed like Windows does (S-1-5-80: upper-case
    # service name, S-1-5-82: lower-case application pool name).
    if ($Principal -match '^\*?(?<sid>S-1-[0-9-]+)$') { return $Matches['sid'] }
    $virtual = $null
    if ($Principal -match '^NT SERVICE\\(?<n>.+)$') { $virtual = @('S-1-5-80', $Matches['n'].ToUpperInvariant()) }
    elseif ($Principal -match '^IIS AppPool\\(?<n>.+)$') { $virtual = @('S-1-5-82', $Matches['n'].ToLowerInvariant()) }
    if ($virtual) {
        $hash = [System.Security.Cryptography.SHA1]::HashData([System.Text.Encoding]::Unicode.GetBytes($virtual[1]))
        return $virtual[0] + '-' + ((0..4 | ForEach-Object { [System.BitConverter]::ToUInt32($hash, 4 * $_) }) -join '-')
    }
    $wellKnown = @{ 'NT AUTHORITY\LocalService' = 'S-1-5-19'; 'NT AUTHORITY\SYSTEM' = 'S-1-5-18'; 'BUILTIN\Administrators' = 'S-1-5-32-544'
        'BUILTIN\Users' = 'S-1-5-32-545'; 'NT AUTHORITY\Authenticated Users' = 'S-1-5-11' }
    if ($wellKnown.ContainsKey($Principal)) { return $wellKnown[$Principal] }
    return $Principal
}

function global:ConvertFrom-FakeAce([string]$Ace) {
    # '(OI)(CI)RX' or '(CI)(WD,AD)' -> inheritance flags and the FileSystemRights mask icacls would write.
    $simple = @{ F = 0x1F01FF; M = 0x1301BF; RX = 0x1200A9; R = 0x120089; W = 0x120116 }
    $specific = @{ RD = 0x1; WD = 0x2; AD = 0x4; REA = 0x8; WEA = 0x10; X = 0x20; DC = 0x40; RA = 0x80; WA = 0x100
        D = 0x10000; RC = 0x20000; WDAC = 0x40000; WO = 0x80000; S = 0x100000; GA = 0x10000000; GE = 0x20000000; GW = 0x40000000; GR = [int]::MinValue }
    $flags = @([regex]::Matches($Ace, '\((OI|CI|IO|NP)\)') | ForEach-Object { $_.Groups[1].Value })
    $rights = $Ace -replace '\((OI|CI|IO|NP)\)', ''
    $mask = 0
    if ($simple.ContainsKey($rights)) { $mask = $simple[$rights] }
    else { foreach ($token in $rights.Trim('(', ')').Split(',')) { $mask = $mask -bor $specific[$token] } }
    [pscustomobject]@{ Flags = $flags; Rights = $mask }
}

function global:Get-FakeAccessRule([string]$Path) {
    # Access rules of Path as Get-Acl reports them: its explicit ACEs, then the ACEs its ancestors pass on (up to
    # and including the nearest protected one), each with the SID of its principal.
    $isDir = [System.IO.Directory]::Exists($Path)   # not Test-Path: it is mocked, which is slow
    $current = $Path
    $depth = 0
    while ($current) {
        $entry = $global:FakeWin.Acl[$current]
        if ($entry) {
            foreach ($p in $entry.Grants.Keys) {
                $ace = ConvertFrom-FakeAce $entry.Grants[$p]
                if ($depth -gt 0) {
                    if (-not ($ace.Flags -contains $(if ($isDir) { 'CI' } else { 'OI' }))) { continue }
                    if ($depth -gt 1 -and $ace.Flags -contains 'NP') { continue }
                }
                $inheritance = @()
                if ($ace.Flags -contains 'OI') { $inheritance += 'ObjectInherit' }
                if ($ace.Flags -contains 'CI') { $inheritance += 'ContainerInherit' }
                [pscustomobject]@{
                    IdentityReference = [pscustomobject]@{ Value = Get-FakeSid $p }
                    FileSystemRights  = [System.Security.AccessControl.FileSystemRights]$ace.Rights
                    AccessControlType = 'Allow'
                    IsInherited       = ($depth -gt 0)
                    InheritanceFlags  = $(if ($inheritance.Count) { $inheritance -join ', ' } else { 'None' })
                    PropagationFlags  = $(if ($depth -eq 0 -and $ace.Flags -contains 'IO') { 'InheritOnly' } else { 'None' })
                }
            }
            if ($entry.Protected) { break }
        }
        if ($current -eq $global:FakeWin.Root) { break }
        $parent = [System.IO.Path]::GetDirectoryName($current)   # null at a root ('/', 'C:\'), where Split-Path throws
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
        $depth++
    }
}

function global:Test-RobocopyExcluded([string]$Relative, [string[]]$ExcludeDirs, [string[]]$ExcludeFiles) {
    $parts = @($Relative -split '[\\/]')
    for ($i = 0; $i -lt $parts.Count - 1; $i++) { if ($ExcludeDirs -contains $parts[$i]) { return $true } }
    foreach ($pattern in $ExcludeFiles) { if ($parts[-1] -like $pattern) { return $true } }
    return $false
}

function Get-FakeAccess {
    # Effective NTFS grants of a path: explicit ACEs plus inheritable ACEs of the ancestors up to (and
    # including) the nearest protected one. Returns @{ principal = rights }.
    param([Parameter(Mandatory = $true)][string]$Path)
    $path = Get-FakeFullPath $Path
    $isDir = [System.IO.Directory]::Exists($path)
    $result = @{}
    $current = $path
    $first = $true
    while ($current) {
        $entry = $global:FakeWin.Acl[$current]
        if ($entry) {
            foreach ($p in $entry.Grants.Keys) {
                $ace = $entry.Grants[$p]
                $inherits = if ($isDir) { $ace -match '\(CI\)' } else { $ace -match '\(OI\)' }
                if ($first -and $ace -match '\(IO\)') { continue }
                if (-not $first -and -not $inherits) { continue }
                $rights = $ace -replace '\((OI|CI|IO|NP)\)', ''
                if (-not $result.ContainsKey($p)) { $result[$p] = $rights }
            }
            if ($entry.Protected) { break }
        }
        if ($current -eq $global:FakeWin.Root) { break }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
        $first = $false
    }
    return $result
}

function Get-PrincipalList([string]$Path) {
    # Principals with effective access to Path, sorted and comma-separated (for exact comparisons).
    (@((Get-FakeAccess $Path).Keys) | Sort-Object) -join ','
}

function Join-Sorted([string[]]$Items) { (@($Items) | Sort-Object) -join ',' }

function Test-FakeWritable {
    # True if one of the given principals may create, change, delete or re-ACL files at Path.
    param([string]$Path, [string[]]$Principals = @($script:SidUsers, $script:SidAuthenticatedUsers))
    $access = Get-FakeAccess $Path
    foreach ($p in $Principals) { if ($access.ContainsKey($p) -and ((ConvertFrom-FakeAce $access[$p]).Rights -band 0x500D0156)) { return $true } }
    return $false
}

function Set-FakeOwner {
    # Owner of Path (and everything below it), e.g. a non-administrator who created a directory in advance.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Sid)
    $global:FakeWin.Owner[(Get-FakeFullPath $Path)] = $Sid
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)) { $global:FakeWin.Owner[(Get-FakeFullPath $item.FullName)] = $Sid }
}

function global:Compare-FakePep440([string]$Left, [string]$Right) {
    # -1/0/1 like packaging.version.Version for release[{a|b|rc}N][.postN][.devN]; $null for an invalid version.
    $keys = foreach ($v in @($Left, $Right)) {
        if ($v -notmatch '^(?<rel>\d+(\.\d+)*)((?<pre>a|b|rc)(?<pren>\d+))?(\.post(?<post>\d+))?(\.dev(?<dev>\d+))?$') { return $null }
        $release = @($Matches['rel'].Split('.') | ForEach-Object { [int]$_ }) + @(0, 0, 0, 0, 0, 0)
        $phase = if ($Matches['pre']) { @{ a = -3; b = -2; rc = -1 }[$Matches['pre']] } elseif ($Matches['post']) { 1 } elseif ($Matches['dev']) { -4 } else { 0 }
        , (@($release[0..5]) + @($phase))
    }
    for ($i = 0; $i -lt 7; $i++) { if ($keys[0][$i] -ne $keys[1][$i]) { return [math]::Sign($keys[0][$i] - $keys[1][$i]) } }
    return 0
}

function global:New-TestCa {
    # Creates an RSA CA in the control-plane layout and returns its SHA-256 fingerprint (AA:BB:...).
    param([Parameter(Mandatory = $true)][string]$Dir, [string]$Subject = 'CN=AegisProxy Test Root CA, O=AegisProxy')
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($Subject, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(10))
    $certPem = $cert.ExportCertificatePem()
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $Dir 'mitmproxy-ca.pem'), $rsa.ExportRSAPrivateKeyPem() + "`n" + $certPem + "`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $Dir 'mitmproxy-ca-cert.pem'), $certPem + "`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $Dir 'aegis-enterprise-ca.crt'), $certPem + "`n", $utf8)
    [System.IO.File]::WriteAllBytes((Join-Path $Dir 'aegis-enterprise-ca.der'), $cert.RawData)
    $hash = [System.Security.Cryptography.SHA256]::HashData($cert.RawData)
    return ([System.BitConverter]::ToString($hash)).Replace('-', ':')
}

function New-FakeBinary {
    # A file that passes the installers' PE ("MZ") check.
    param([Parameter(Mandatory = $true)][string]$Path, [string]$Marker = 'v1')
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, [byte[]](@(0x4D, 0x5A) + [System.Text.Encoding]::ASCII.GetBytes(" fake $Marker")))
}

function Import-ScriptFunction {
    # Defines selected helper functions of an installer in the caller's scope without running the script.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$Name)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Name -contains $n.Name }, $false)
    if (@($defs).Count -ne $Name.Count) { throw "Not all functions found in ${Path}: $($Name -join ', ')" }
    return (@($defs | ForEach-Object { $_.Extent.Text }) -join "`n")
}

function Invoke-Installer {
    # Runs an installer with all output streams captured. Returns the text and the exit code.
    param([Parameter(Mandatory = $true)][string]$Path, [hashtable]$Parameters = @{})
    $global:LASTEXITCODE = 0
    $out = & $Path @Parameters *>&1 | ForEach-Object { "$_" }
    [pscustomobject]@{ Output = ($out -join "`n"); ExitCode = $global:LASTEXITCODE }
}
