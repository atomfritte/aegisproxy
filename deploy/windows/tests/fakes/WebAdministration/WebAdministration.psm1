# Test double for the IIS WebAdministration module used by Install-AegisConsole-IIS.ps1.
# State lives in $global:FakeWin.Iis (see ..\..\FakeWindows.ps1).

function New-WebAppPool {
    param([string]$Name)
    if ($global:FakeWin.Iis.AppPools.ContainsKey($Name)) { throw "Application pool $Name already exists." }
    $global:FakeWin.Iis.AppPools[$Name] = @{ State = 'Stopped' }
    [pscustomobject]@{ Name = $Name }
}

function Start-WebAppPool {
    [CmdletBinding()]
    param([string]$Name)
    $global:FakeWin.Iis.AppPools[$Name].State = 'Started'
}

function Get-Website {
    [CmdletBinding()]
    param([string]$Name)
    if ($global:FakeWin.Iis.Sites.ContainsKey($Name)) { [pscustomobject]@{ Name = $Name } }
}

function New-Website {
    param([string]$Name, [string]$PhysicalPath, [string]$ApplicationPool, [int]$Port, [string]$HostHeader, [switch]$Ssl, [int]$SslFlags)
    if ($global:FakeWin.Iis.Sites.ContainsKey($Name)) { throw "Cannot create a file when that file already exists. (site $Name)" }
    $site = @{ physicalPath = $PhysicalPath; applicationPool = $ApplicationPool; State = 'Stopped'
        Bindings = New-Object System.Collections.Generic.List[hashtable] }
    $site.Bindings.Add(@{ Protocol = $(if ($Ssl) { 'https' } else { 'http' }); Port = $Port; HostHeader = $HostHeader; SslFlags = $SslFlags; Certificate = $null })
    $global:FakeWin.Iis.Sites[$Name] = $site
    [pscustomobject]@{ Name = $Name }
}

function Start-Website {
    param([string]$Name)
    $global:FakeWin.Iis.Sites[$Name].State = 'Started'
}

function Get-WebBinding {
    param([string]$Name, [string]$Protocol, [int]$Port, [string]$HostHeader)
    foreach ($b in $global:FakeWin.Iis.Sites[$Name].Bindings) {
        if ($b.Protocol -ne $Protocol -or $b.Port -ne $Port -or $b.HostHeader -ne $HostHeader) { continue }
        $obj = [pscustomobject]@{ protocol = $b.Protocol; bindingInformation = "*:$($b.Port):$($b.HostHeader)"; Data = $b }
        Add-Member -InputObject $obj -MemberType ScriptMethod -Name RemoveSslCertificate -Value {
            if (-not $this.Data.Certificate) { throw 'A specified logon session does not exist.' }
            $this.Data.Certificate = $null
        }
        Add-Member -InputObject $obj -MemberType ScriptMethod -Name AddSslCertificate -Value {
            param($Thumbprint, $Store)
            if ($this.Data.Certificate) { throw 'Cannot create a file when that file already exists.' }
            $this.Data.Certificate = "$Store\$Thumbprint"
        }
        $obj
    }
}

function New-WebBinding {
    param([string]$Name, [string]$Protocol, [int]$Port, [string]$HostHeader, [int]$SslFlags)
    $site = $global:FakeWin.Iis.Sites[$Name]
    foreach ($b in $site.Bindings) {
        if ($b.Protocol -eq $Protocol -and $b.Port -eq $Port -and $b.HostHeader -eq $HostHeader) { throw 'Cannot add duplicate collection entry.' }
    }
    $site.Bindings.Add(@{ Protocol = $Protocol; Port = $Port; HostHeader = $HostHeader; SslFlags = $SslFlags; Certificate = $null })
}

function Set-WebConfigurationProperty {
    param([string]$PSPath, [string]$Location, [string]$Filter, [string]$Name, $Value)
    $global:FakeWin.Iis.Config["$PSPath|$Location|$Filter|$Name"] = $Value
}

Export-ModuleMember -Function New-WebAppPool, Start-WebAppPool, Get-Website, New-Website, Start-Website, Get-WebBinding, New-WebBinding, Set-WebConfigurationProperty
