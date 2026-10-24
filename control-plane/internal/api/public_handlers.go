package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		writeError(w, http.StatusServiceUnavailable, "shutting down")
		return
	}
	if s.store == nil || s.store.GetRevision() == 0 {
		writeError(w, http.StatusServiceUnavailable, "state not loaded")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	audit := "writable"
	if !s.store.AuditStatus().Writable {
		audit = "unavailable" // reads keep working; changes are refused (aegis_audit_log_writable, posture)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "revision": s.store.GetRevision(), "storage": s.store.StorageName(), "audit_log": audit})
}

func (s *Server) handlePublicMeta(w http.ResponseWriter, r *http.Request) {
	snap := s.store.GetSnapshot()
	sso := s.store.SSOSettings(s.cfg.PublicURL)
	writeJSON(w, http.StatusOK, map[string]any{
		"product":             "AegisProxy Enterprise",
		"version":             s.version,
		"demo_mode":           s.store.DemoMode(),
		"public_url":          s.cfg.PublicURL,
		"local_login_enabled": snap.EntraConfig.AllowLocalLogin || !snap.EntraConfig.Enabled,
		"entra_enabled":       snap.EntraConfig.Enabled,
		"sso": map[string]any{"enabled": snap.EntraConfig.Enabled, "provider": sso.Provider, "label": sso.DisplayName,
			"login_url": "/api/auth/sso/login", "local_login_enabled": snap.EntraConfig.AllowLocalLogin || !snap.EntraConfig.Enabled},
	})
}

func (s *Server) allowCA(w http.ResponseWriter, r *http.Request) bool {
	if !s.caLimit.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return false
	}
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Cache-Control", "public, max-age=300")
	return true
}

func (s *Server) handlePublicCAInfo(w http.ResponseWriter, r *http.Request) {
	if !s.allowCA(w, r) {
		return
	}
	cmds := s.caInstallCommands()
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":               s.caMgr.Subject,
		"issuer":                s.caMgr.Issuer,
		"serial":                s.caMgr.SerialHex,
		"not_before":            s.caMgr.NotBefore,
		"not_after":             s.caMgr.NotAfter,
		"fingerprint":           s.caMgr.Fingerprint,
		"pem_content":           string(s.caMgr.CertPEM),
		"public_url":            s.cfg.PublicURL,
		"download_crt":          "/api/public/ca/aegis-ca.crt",
		"download_pem":          "/api/public/ca/aegis-ca.pem",
		"download_der":          "/api/public/ca/aegis-ca.der",
		"linux_script":          "/api/public/ca/install-linux.sh",
		"windows_script":        "/api/public/ca/install-windows.ps1",
		"linux_script_sha256":   cmds.LinuxSHA256,
		"windows_script_sha256": cmds.WindowsSHA256,
		"linux_command":         cmds.Linux,
		"windows_command":       cmds.Windows,
	})
}

// caInstallCommands are copy-paste commands that download a trust installer, check it against its
// SHA-256 and only then run it with root/administrator rights. Installers are never piped into a
// shell: the hash comes from the authenticated console, so a script altered in transit (plain http,
// a TLS-intercepting middlebox, a spoofed host) is refused before it runs.
type caInstallCommands struct {
	LinuxSHA256, WindowsSHA256 string
	Linux, Windows             string
}

func (s *Server) caInstallCommands() caInstallCommands {
	ls := sha256.Sum256([]byte(s.linuxInstallScript()))
	ws := sha256.Sum256([]byte(s.windowsInstallScript()))
	c := caInstallCommands{LinuxSHA256: hex.EncodeToString(ls[:]), WindowsSHA256: hex.EncodeToString(ws[:])}
	c.Linux = fmt.Sprintf(`curl -fsSLo aegis-ca-install.sh %s && echo '%s  aegis-ca-install.sh' | sha256sum -c - && sudo bash aegis-ca-install.sh`,
		shellQuoteSingle(s.cfg.PublicURL+"/api/public/ca/install-linux.sh"), c.LinuxSHA256)
	c.Windows = fmt.Sprintf(`$f = Join-Path $env:TEMP 'aegis-ca-install.ps1'; iwr -UseBasicParsing '%s' -OutFile $f; if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '%s') { throw 'aegis-ca-install.ps1: SHA-256 mismatch, not running it' }; powershell -NoProfile -ExecutionPolicy Bypass -File $f`,
		strings.ReplaceAll(s.cfg.PublicURL+"/api/public/ca/install-windows.ps1", "'", "''"), c.WindowsSHA256)
	return c
}

func (s *Server) handlePublicCACertPEM(w http.ResponseWriter, r *http.Request) {
	if !s.allowCA(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-enterprise-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.caMgr.CertPEM)
}

func (s *Server) handlePublicCACertDER(w http.ResponseWriter, r *http.Request) {
	if !s.allowCA(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-enterprise-ca.der"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.caMgr.CertDER)
}

// handlePublicLinuxInstallScript serves a trust installer pinned to the CA fingerprint. The CA URL
// is derived from AEGIS_PUBLIC_URL, never from the (attacker-controlled) Host header.
func (s *Server) handlePublicLinuxInstallScript(w http.ResponseWriter, r *http.Request) {
	if !s.allowCA(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(s.linuxInstallScript()))
}

func (s *Server) linuxInstallScript() string {
	caURL := shellQuoteSingle(s.cfg.PublicURL + "/api/public/ca/aegis-ca.crt")
	insecure := ""
	if strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "http://") {
		insecure = `
# WARNING: AEGIS_PUBLIC_URL uses plain http, so this script can be altered in transit. Run it only
# after its SHA-256 matched the value shown in the AegisProxy console.
echo "[!] WARNING: this installer was served over plain http (AEGIS_PUBLIC_URL); make sure its SHA-256 matched the console value." >&2
`
	}
	return fmt.Sprintf(`#!/usr/bin/env bash
# AegisProxy Enterprise Root CA - Automated Server Trust Installer
# The CA is pinned to its SHA-256 fingerprint. Verify the fingerprint below against the value shown
# in the AegisProxy console (TLS & CA) before running this script with root privileges.
# Usage: never pipe it into a shell. Download it, compare its SHA-256 with the value shown in the
# console (or use the verified one-liner from there), then run it:
#   curl -fsSLo aegis-ca-install.sh %[3]s/api/public/ca/install-linux.sh
#   sha256sum aegis-ca-install.sh
#   sudo bash aegis-ca-install.sh
set -euo pipefail
%[4]s
EXPECTED_FP='%[1]s'
CA_URL=%[2]s
TMP_CA="$(mktemp /tmp/aegis-ca.XXXXXX.crt)"
trap 'rm -f "$TMP_CA"' EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Please run as root (sudo)." >&2
    exit 1
fi

echo "[*] Downloading AegisProxy Enterprise Root CA (expected SHA-256: $EXPECTED_FP)..."
curl -fsSL --proto '=https,http' --max-time 30 "$CA_URL" -o "$TMP_CA"

ACTUAL_FP="$(openssl x509 -noout -fingerprint -sha256 -in "$TMP_CA" | awk -F= '{print $2}')"
if [ "$ACTUAL_FP" != "$EXPECTED_FP" ]; then
    echo "[!] SECURITY ERROR: Downloaded CA fingerprint ($ACTUAL_FP) does not match expected fingerprint ($EXPECTED_FP)!" >&2
    exit 1
fi

BUNDLE_PATH="/etc/ssl/certs/ca-certificates.crt"
if [ -d /usr/local/share/ca-certificates ]; then
    # Ubuntu / Debian / Alpine
    install -m 0644 "$TMP_CA" /usr/local/share/ca-certificates/aegis-enterprise-ca.crt
    update-ca-certificates
    BUNDLE_PATH="/etc/ssl/certs/ca-certificates.crt"
    echo "[+] Installed into Debian/Ubuntu trust store."
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
    # RHEL / Rocky / AlmaLinux / Fedora
    install -m 0644 "$TMP_CA" /etc/pki/ca-trust/source/anchors/aegis-enterprise-ca.crt
    update-ca-trust extract
    BUNDLE_PATH="/etc/pki/tls/certs/ca-bundle.crt"
    echo "[+] Installed into RHEL/Fedora trust store."
elif [ -d /etc/pki/trust/anchors ]; then
    # SLES / openSUSE
    install -m 0644 "$TMP_CA" /etc/pki/trust/anchors/aegis-enterprise-ca.crt
    update-ca-certificates
    BUNDLE_PATH="/var/lib/ca-certificates/ca-bundle.pem"
    echo "[+] Installed into SLES trust store."
else
    echo "[!] Unsupported distribution: no known CA trust store directory found." >&2
    exit 1
fi

echo "[*] Configuring Git, Python/PIP, and Node.js CA environment variables..."
cat << EOF > /etc/profile.d/aegis-proxy-ca.sh
export SSL_CERT_FILE=$BUNDLE_PATH
export REQUESTS_CA_BUNDLE=$BUNDLE_PATH
export PIP_CERT=$BUNDLE_PATH
export GIT_SSL_CAINFO=$BUNDLE_PATH
export NODE_EXTRA_CA_CERTS=$BUNDLE_PATH
EOF
chmod 0644 /etc/profile.d/aegis-proxy-ca.sh
echo "[+] Done! All SSL/TLS traffic via AegisProxy is now trusted."
`, s.caMgr.Fingerprint, caURL, s.cfg.PublicURL, insecure)
}

// windowsInstallScript is a PowerShell trust installer for Windows servers. The CA is
// pinned to its SHA-256 fingerprint. Optionally ($env:AEGIS_PROXY = "proxy.corp:8080") it configures
// the WinHTTP and machine-wide proxy so services and CLI tools route through AegisProxy.
func (s *Server) windowsInstallScript() string {
	fp := strings.ReplaceAll(s.caMgr.Fingerprint, ":", "")
	caURL := strings.ReplaceAll(s.cfg.PublicURL+"/api/public/ca/aegis-ca.der", "'", "''")
	script := fmt.Sprintf(`#Requires -RunAsAdministrator
# AegisProxy Enterprise Root CA - Windows Server Trust Installer
# Usage (elevated PowerShell): never pipe it into iex. Download it, compare its SHA-256 with the value
# shown in the AegisProxy console (TLS & CA, or use the verified one-liner from there), then run it:
#   $env:AEGIS_PROXY = "aegis-proxy.corp.example:8080"   # optional: also configure proxy settings
#   iwr -UseBasicParsing %s/api/public/ca/install-windows.ps1 -OutFile aegis-ca-install.ps1
#   Get-FileHash aegis-ca-install.ps1 -Algorithm SHA256
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\aegis-ca-install.ps1
$ErrorActionPreference = 'Stop'
$ExpectedFingerprint = '%s'
$CaUrl = '%s'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$tmp = Join-Path $env:TEMP ("aegis-ca-" + [guid]::NewGuid().ToString() + ".cer")
try {
    Write-Host "[*] Downloading AegisProxy Enterprise Root CA..."
    Invoke-WebRequest -UseBasicParsing -Uri $CaUrl -OutFile $tmp
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmp)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $actual = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '')
    if ($actual -ne $ExpectedFingerprint) {
        throw "SECURITY ERROR: CA fingerprint $actual does not match expected $ExpectedFingerprint"
    }
    Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "[+] Installed into Cert:\LocalMachine\Root ($($cert.Subject))"

    # PEM copy for runtimes with their own trust store (Node.js, Python certifi, Java keytool import). The file is
    # trusted machine-wide (NODE_EXTRA_CA_CERTS), so it lives in a directory below Program Files that only
    # SYSTEM/Administrators can change (users read it); an existing directory is taken over and checked first.
    $dir = Join-Path $env:ProgramFiles 'AegisProxy\ca-trust'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    icacls.exe $dir /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for $dir" }
    icacls.exe $dir /reset /T /C /Q | Out-Null
    icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $dir" }
    $acl = Get-Acl -LiteralPath $dir
    $admins = @('S-1-5-18', 'S-1-5-32-544')
    $writers = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
        "$($_.AccessControlType)" -eq 'Allow' -and $admins -notcontains $_.IdentityReference.Value -and ([int]$_.FileSystemRights -band 0x500D0156) })
    if ($admins -notcontains $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -or $writers.Count) {
        throw "SECURITY ERROR: $dir is not restricted to administrators (owner or write access of another account)"
    }
    $pem = "-----BEGIN CERTIFICATE-----`+"`"+`n" + [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') + "`+"`"+`n-----END CERTIFICATE-----`+"`"+`n"
    $pemPath = Join-Path $dir 'aegis-enterprise-ca.pem'
    Set-Content -LiteralPath $pemPath -Value $pem -Encoding ascii
    [Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $pemPath, 'Machine')
    if (Get-Command git -ErrorAction SilentlyContinue) { git config --system http.sslBackend schannel }
    Write-Host "[+] NODE_EXTRA_CA_CERTS=$pemPath; Git uses the Windows certificate store (schannel)."

    if ($env:AEGIS_PROXY) {
        netsh winhttp set proxy proxy-server="$($env:AEGIS_PROXY)" bypass-list="<local>" | Out-Null
        [Environment]::SetEnvironmentVariable('HTTP_PROXY', "http://$($env:AEGIS_PROXY)", 'Machine')
        [Environment]::SetEnvironmentVariable('HTTPS_PROXY', "http://$($env:AEGIS_PROXY)", 'Machine')
        [Environment]::SetEnvironmentVariable('NO_PROXY', 'localhost,127.0.0.1,.local', 'Machine')
        Write-Host "[+] WinHTTP and machine-wide proxy set to $($env:AEGIS_PROXY)"
    }
    Write-Host "[+] Done. Restart services / open a new shell to pick up the environment changes."
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
}
`, s.cfg.PublicURL, fp, caURL)
	return script
}

// handlePublicWindowsInstallScript serves windowsInstallScript (see there).
func (s *Server) handlePublicWindowsInstallScript(w http.ResponseWriter, r *http.Request) {
	if !s.allowCA(w, r) {
		return
	}
	script := s.windowsInstallScript()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="install-windows.ps1"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

func shellQuoteSingle(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

type publicCreateRequestDTO struct {
	BlockToken     string `json:"block_token"`
	TraceID        string `json:"trace_id"`
	ServerIP       string `json:"server_ip"`
	RequestedURL   string `json:"requested_url"`
	Method         string `json:"method"`
	Requester      string `json:"requester"`
	Reason         string `json:"reason"`
	RequestedScope string `json:"requested_scope"`
	Duration       string `json:"duration"`
}

func (s *Server) handlePublicPreflight(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// handlePublicCreateRequest accepts self-service access requests from the block page / CLI.
// Server identity is only trusted when the request carries a data-plane-signed block token;
// otherwise the TCP source address is used and the request is flagged as unverified.
func (s *Server) handlePublicCreateRequest(w http.ResponseWriter, r *http.Request) {
	remoteIP := s.clientIP(r)
	if !s.publicLimit.Allow(remoteIP) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "Rate limit exceeded for access requests (max 20/min per IP)")
		return
	}
	var dto publicCreateRequestDTO
	if !decodeJSON(w, r, &dto) {
		return
	}
	payload := models.AccessRequest{
		TraceID:        strings.TrimSpace(dto.TraceID),
		Requester:      strings.TrimSpace(dto.Requester),
		Reason:         strings.TrimSpace(dto.Reason),
		RequestedScope: strings.TrimSpace(dto.RequestedScope),
		Duration:       strings.TrimSpace(dto.Duration),
		SourceIP:       remoteIP,
	}
	if payload.Duration == "" {
		payload.Duration = "24h"
	}

	if tok := strings.TrimSpace(dto.BlockToken); tok != "" {
		claims, err := auth.VerifyBlockToken(s.cfg.DataPlaneKey, tok)
		if err != nil {
			s.metrics.Inc("aegis_access_requests_total", "result", "bad_token")
			writeError(w, http.StatusBadRequest, "Invalid or expired block token: "+err.Error()+". Re-run the blocked request to obtain a fresh one.")
			return
		}
		payload.ServerIP = claims.ServerIP
		payload.RequestedURL = claims.URL
		payload.Method = claims.Method
		payload.TraceID = claims.TraceID
		payload.Verified = true
	} else {
		payload.ServerIP = remoteIP
		payload.RequestedURL = strings.TrimSpace(dto.RequestedURL)
		payload.Method = strings.ToUpper(strings.TrimSpace(dto.Method))
	}
	if payload.Method == "" {
		payload.Method = "GET"
	}
	if payload.Requester == "" {
		payload.Requester = fmt.Sprintf("operator@%s", payload.ServerIP)
	}
	if len(payload.RequestedURL) > 4096 {
		writeError(w, http.StatusBadRequest, "requested_url too long")
		return
	}
	u, err := url.Parse(payload.RequestedURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "requested_url must be a valid http:// or https:// URL")
		return
	}
	payload.Host = u.Host
	payload.Path = u.EscapedPath()
	if payload.Path == "" {
		payload.Path = "/"
	}

	created, isNew, err := s.store.CreateAccessRequest(payload)
	if err != nil {
		if err == store.ErrTooManyPending {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.metrics.Inc("aegis_access_requests_total", "result", map[bool]string{true: "created", false: "duplicate"}[isNew])
	msg := "Access request submitted. InfoSec & Team Leads have been notified."
	status := http.StatusCreated
	if !isNew {
		msg = "An identical request for this server is already pending review."
		status = http.StatusOK
	}
	if !created.Verified {
		msg += " (Server identity could not be verified by the proxy — reviewers will see this request as UNVERIFIED.)"
	}
	writeJSON(w, status, map[string]any{
		"message": msg,
		"request": map[string]any{
			"id":                     created.ID,
			"status":                 created.Status,
			"verified":               created.Verified,
			"server_hostname":        created.ServerHostname,
			"suggested_host_pattern": created.SuggestedHostPattern,
			"suggested_path_pattern": created.SuggestedPathPattern,
			"created_at":             created.CreatedAt.Format(time.RFC3339),
		},
	})
}

// handlePublicRequestOptions tells the self-service portal what may be requested for the server
// that was blocked (scopes and durations of its block page template).
func (s *Server) handlePublicRequestOptions(w http.ResponseWriter, r *http.Request) {
	remoteIP := s.clientIP(r)
	if !s.publicLimit.Allow(remoteIP) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	ip, verified, verdict, target := remoteIP, false, "", ""
	if tok := strings.TrimSpace(r.URL.Query().Get("bt")); tok != "" {
		claims, err := auth.VerifyBlockToken(s.cfg.DataPlaneKey, tok)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid or expired block token. Re-run the blocked request to obtain a fresh one.")
			return
		}
		ip, verified, verdict, target = claims.ServerIP, true, claims.Verdict, claims.URL
	}
	_, hostname, groups := s.store.ResolveServer(ip, "")
	tpl := s.store.TemplateForGroups(groups)
	selfService := !models.IsSecurityVerdict(verdict) || verdict == models.VerdictPolicyBlocked
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": verified, "server_hostname": hostname, "url": target, "verdict": verdict,
		"request_form":      tpl.ShowRequestForm && selfService,
		"allowed_scopes":    tpl.AllowedScopes,
		"allowed_durations": tpl.AllowedDurations,
		"company_name":      tpl.CompanyName,
		"support":           tpl.Support,
		"default_locale":    tpl.DefaultLocale,
	})
}
