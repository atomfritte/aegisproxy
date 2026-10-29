#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
# Static checks of the Windows installers that do not need the fake system.

BeforeDiscovery {
    $script:Installers = @(Get-ChildItem -LiteralPath (Split-Path -Parent $PSScriptRoot) -Filter '*.ps1' -File |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $Root)

    function Get-Ast([string]$Path) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        [pscustomobject]@{ Ast = $ast; Errors = $errors }
    }
}

Describe '<Name>' -ForEach $Installers {
    BeforeAll { $script:Parsed = Get-Ast $Path }

    It 'parses without errors' {
        $Parsed.Errors | Should -BeNullOrEmpty
    }

    It 'is pure ASCII (Windows PowerShell 5.1 reads BOM-less files in the ANSI code page)' {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 0x7E -or ($_ -lt 0x20 -and $_ -notin 0x09, 0x0A, 0x0D) }).Count | Should -Be 0
    }

    It 'requires Windows PowerShell 5.1+ and an elevated session' {
        $Parsed.Ast.ScriptRequirements.RequiredPSVersion | Should -Be ([version]'5.1')
        $Parsed.Ast.ScriptRequirements.IsElevationRequired | Should -BeTrue
    }

    It 'supports -WhatIf/-Confirm' {
        $binding = $Parsed.Ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }
        ($binding.NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' }).Argument.Extent.Text | Should -Be '$true'
    }

    It 'never evaluates strings as code or converts plain text to secure strings' {
        $calls = $Parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        @($calls | Where-Object { $_.GetCommandName() -in @('Invoke-Expression', 'iex') }).Count | Should -Be 0
        @($calls | Where-Object { $_.GetCommandName() -eq 'ConvertTo-SecureString' }).Count | Should -Be 0
    }

    It 'passes no double quotes inside native command arguments (mangled by Windows PowerShell 5.1)' {
        $natives = $Parsed.Ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Invoke-Native', 'Invoke-NativeLive') }, $true)
        $natives.Count | Should -BeGreaterThan 0
        foreach ($call in $natives) {
            $strings = $call.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
            foreach ($s in $strings) { $s.Value | Should -Not -Match '"' -Because $call.Extent.Text }
        }
    }
}

Describe 'installation source check' {
    It 'is the same code in every installer (<Name>)' -TestCases @(
        @{ Name = 'ConvertTo-FileRight' }, @{ Name = 'Get-WritableSource' }, @{ Name = 'Assert-TrustedSource' },
        @{ Name = 'Assert-TrustedLocation' }, @{ Name = 'Get-NewParent' }
    ) {
        $scripts = @(Get-ChildItem -LiteralPath $Root -Filter 'Install-Aegis*.ps1' -File)
        $scripts.Count | Should -Be 3
        $texts = @($scripts | ForEach-Object {
                (Get-Ast $_.FullName).Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $false).Extent.Text
            })
        $texts.Count | Should -Be 3
        @($texts | Sort-Object -Unique).Count | Should -Be 1
    }

    It 'runs before the installers use their sources' {
        foreach ($case in @(
                @{ Script = 'Install-AegisControlPlane.ps1'; Before = 'Start-Process -FilePath $newBinary' },
                @{ Script = 'Install-AegisDataPlane.ps1'; Before = 'Get-FileHash -LiteralPath $WinSWExe' },
                @{ Script = 'Install-AegisConsole-IIS.ps1'; Before = "robocopy.exe' -ArgumentList @(`$DistDir" })) {
            $text = [System.IO.File]::ReadAllText((Join-Path $Root $case.Script))
            $check = $text.IndexOf('Assert-TrustedSource -Path @($PSCommandPath')
            $check | Should -BeGreaterThan 0 -Because $case.Script
            $check | Should -BeLessThan $text.IndexOf($case.Before) -Because $case.Script
        }
    }
}

Describe 'installation directory check' {
    It 'lists the directories to create, then checks the way to the installation directories before <Before> (<Script>)' -TestCases @(
        @{ Script = 'Install-AegisControlPlane.ps1'; Paths = '@($InstallDir, $DataRoot)'; Before = "ShouldProcess(`$ServiceName, 'Stop service for upgrade')" },
        @{ Script = 'Install-AegisDataPlane.ps1'; Paths = '@($InstallDir, $dataTop)'; Before = "ShouldProcess(`$ServiceName, 'Stop service for upgrade')" },
        @{ Script = 'Install-AegisConsole-IIS.ps1'; Paths = '@($PhysicalPath)'; Before = "ShouldProcess('IIS', 'Install role services')" },
        @{ Script = 'Install-AegisConsole-IIS.ps1'; Paths = '@($PhysicalPath)'; Before = 'New-Item -ItemType Directory -Path $PhysicalPath'; Last = $true }
    ) {
        $text = [System.IO.File]::ReadAllText((Join-Path $Root $Script))
        $check = if ($Last) { $text.LastIndexOf("Assert-TrustedLocation -Path $Paths") } else { $text.IndexOf("Assert-TrustedLocation -Path $Paths") }
        $check | Should -BeGreaterThan 0
        $check | Should -BeLessThan $text.IndexOf($Before)
        if ($Script -ne 'Install-AegisConsole-IIS.ps1' -or $Last) {
            $listed = $text.LastIndexOf("Get-NewParent $Paths", $check)
            $listed | Should -BeGreaterThan 0 -Because 'directories that someone creates after the check must still be listed'
            $text.Substring($listed, $check - $listed).Split("`n").Count | Should -Be 2 -Because 'the list is taken right before the check'
        }
    }

    It 'checks the directories above the Python directory before the data-plane installer runs Python' {
        $text = [System.IO.File]::ReadAllText((Join-Path $Root 'Install-AegisDataPlane.ps1'))
        $check = $text.IndexOf('Get-WritableSource -Location @($pyHome)')
        $check | Should -BeGreaterThan 0
        $check | Should -BeLessThan $text.IndexOf('Invoke-Native -FilePath $pythonBase')
    }
}

Describe 'WinSW template and data-plane installer' {
    It 'replaces exactly the placeholders the template defines' {
        $template = [System.IO.File]::ReadAllText((Join-Path $Root 'aegis-dataplane.xml'))
        $body = $template -replace '(?s)<!--.*?-->', ''
        $inTemplate = @([regex]::Matches($body, '@@[A-Z_]+@@') | ForEach-Object Value | Sort-Object -Unique)
        $script = [System.IO.File]::ReadAllText((Join-Path $Root 'Install-AegisDataPlane.ps1'))
        $inScript = @([regex]::Matches($script, "'(@@[A-Z_]+@@)'\s*=") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $inScript | Should -Be $inTemplate
    }

    It 'pins the same WinSW release hash as the CI job' {
        $ci = [System.IO.File]::ReadAllText((Join-Path $RepoRoot '.github/workflows/ci.yml'))
        $ciHash = [regex]::Match($ci, "-ne '([0-9A-F]{64})'\) \{ throw `"WinSW hash mismatch").Groups[1].Value
        $ciHash | Should -Match '^[0-9A-F]{64}$'
        $param = (Get-Command (Join-Path $Root 'Install-AegisDataPlane.ps1')).Parameters['WinSWSha256']
        $ast = (Get-Ast (Join-Path $Root 'Install-AegisDataPlane.ps1')).Ast
        $default = ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'WinSWSha256' }).DefaultValue.Value
        $param | Should -Not -BeNullOrEmpty
        $default | Should -Be $ciHash
    }
}

Describe 'IIS web.config template' {
    BeforeAll { $script:WebConfig = [System.IO.File]::ReadAllText((Join-Path $Root 'iis/web.config')) }

    It 'is well-formed XML' {
        { [xml]$WebConfig } | Should -Not -Throw
    }

    It 'contains the CSP connect-src directive the console installer extends' {
        $WebConfig | Should -Match "connect-src 'self';"
        ([xml]$WebConfig).configuration.'system.webServer'.httpProtocol.customHeaders.add |
            Where-Object name -eq 'Content-Security-Policy' | Should -Not -BeNullOrEmpty
    }
}
