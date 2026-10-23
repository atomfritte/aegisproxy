<#
.SYNOPSIS
    Static analysis and Pester tests for the Windows installers in deploy\windows.

.DESCRIPTION
    Runs on PowerShell 7 under Windows and Linux. The tests execute the unchanged installers against an
    in-memory Windows (FakeWindows.ps1): no service, firewall rule, ACL or registry value of the machine
    running the tests is touched. Pinned tool versions are installed for the current user when missing.

.PARAMETER OutputDir
    Directory for the JUnit XML report (windows-installers.junit.xml). Optional.

.EXAMPLE
    pwsh -NoProfile -File deploy/windows/tests/Invoke-InstallerTests.ps1 -OutputDir ./test-results
#>
[CmdletBinding()]
param([string]$OutputDir)

$ErrorActionPreference = 'Stop'
$PesterVersion = '5.9.1'
$AnalyzerVersion = '1.25.0'

foreach ($module in @(@{ Name = 'Pester'; Version = $PesterVersion }, @{ Name = 'PSScriptAnalyzer'; Version = $AnalyzerVersion })) {
    if (-not (Get-Module -ListAvailable -Name $module.Name | Where-Object { "$($_.Version)" -eq $module.Version })) {
        Install-Module -Name $module.Name -RequiredVersion $module.Version -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module -Name $module.Name -RequiredVersion $module.Version -Force
}

$installerDir = Split-Path -Parent $PSScriptRoot
$settings = @{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseShouldProcessForStateChangingFunctions', 'PSAvoidUsingPlainTextForPassword')
    Rules        = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } }
}
$findings = @(Get-ChildItem -LiteralPath $installerDir -Filter '*.ps1' -File | ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Settings $settings })
if ($findings.Count) { $findings | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Host }
Write-Host "PSScriptAnalyzer $AnalyzerVersion : $($findings.Count) finding(s)"

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
if ($OutputDir) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'JUnitXml'
    $config.TestResult.OutputPath = Join-Path $OutputDir 'windows-installers.junit.xml'
}
$result = Invoke-Pester -Configuration $config

if ($findings.Count -or $result.Result -ne 'Passed') { exit 1 }
