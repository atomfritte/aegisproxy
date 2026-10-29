// Root CA helpers shared by the TLS & CA page and the public block portal.
import type { CAInfo } from '../../../types';

/** "CN=AegisProxy Root,O=Corp" → { CN: 'AegisProxy Root', O: 'Corp' } (first value wins). */
export function parseDN(dn: string): Record<string, string> {
  const out: Record<string, string> = {};
  // split on commas that start a new "KEY=" attribute
  for (const part of (dn || '').split(/,(?=\s*[A-Za-z]+=)/)) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim().toUpperCase();
    if (!(k in out)) out[k] = part.slice(i + 1).trim();
  }
  return out;
}

export function commonName(dn: string): string {
  return parseDN(dn).CN || dn || '—';
}

type InstallInfo = Pick<CAInfo, 'linux_command' | 'windows_command'> | null | undefined;

/**
 * Fingerprint-pinned installers served by the control plane. A downloaded script is never piped into a
 * shell: the control plane's commands check the script against its SHA-256 before running it; without
 * them (older control plane) the steps download, show the hash for a manual comparison and run. Either
 * way the script lands in a fresh private directory and exactly the checked file runs (a fixed name in
 * a shared or the current directory could be swapped by another local user between check and run).
 */
export function installCommands(base: string, ca?: InstallInfo) {
  return {
    linux:
      ca?.linux_command ||
      `d=$(mktemp -d)
curl -fsSLo "$d/aegis-ca-install.sh" ${base}/api/public/ca/install-linux.sh
sha256sum "$d/aegis-ca-install.sh"   # compare with the console (TLS & CA)
sudo bash "$d/aegis-ca-install.sh"; rm -rf "$d"`,
    windows:
      ca?.windows_command ||
      `$d = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('aegis-ca-' + [guid]::NewGuid())); $f = Join-Path $d.FullName 'aegis-ca-install.ps1'
iwr -UseBasicParsing ${base}/api/public/ca/install-windows.ps1 -OutFile $f
Get-FileHash $f -Algorithm SHA256   # compare with the console (TLS & CA)
powershell -NoProfile -ExecutionPolicy Bypass -File $f; Remove-Item -Recurse $d.FullName`,
  };
}

export type TrustOs = 'ubuntu' | 'rhel' | 'windows' | 'docker' | 'runtime';

export const TRUST_OS: Array<{ id: TrustOs; label: string }> = [
  { id: 'ubuntu', label: 'Ubuntu / Debian' },
  { id: 'rhel', label: 'RHEL / Rocky' },
  { id: 'windows', label: 'Windows Server' },
  { id: 'docker', label: 'Docker / Kubernetes' },
  { id: 'runtime', label: 'Git, pip, Node' },
];

type SnippetInfo = (Partial<Pick<CAInfo, 'fingerprint' | 'pem_sha256' | 'linux_command' | 'windows_command'>>) | null | undefined;

/**
 * Manual trust-store import guides per platform. Every snippet checks the certificate against the CA
 * fingerprint (or the file's SHA-256) before trusting it and trusts only that one certificate; the
 * comparison values must be read from the console over https.
 */
export function trustSnippet(os: TrustOs, base: string, ca?: SnippetInfo): string {
  const fp = ca?.fingerprint || '<SHA-256 fingerprint from the console>';
  const pemSha = ca?.pem_sha256 || '<pem_sha256 from the console>';
  // openssl x509 re-encodes the first certificate only, so nothing else from the download is trusted; the
  // file lives in a fresh private directory, so the certificate that is checked is the one installed
  const verifiedPem = (dest: string, update: string) => `d=$(mktemp -d)
curl -fsSL ${base}/api/public/ca/aegis-ca.crt | openssl x509 -out "$d/aegis-ca.crt"
[ "$(openssl x509 -in "$d/aegis-ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)" = '${fp}' ] \\
  && sudo install -m 0644 "$d/aegis-ca.crt" ${dest} \\
  && sudo ${update} \\
  || echo 'CA NOT installed: fingerprint mismatch or error' >&2
rm -rf "$d"`;
  switch (os) {
    case 'ubuntu':
      return `# Ubuntu / Debian / Proxmox — system-wide CA import, only after the fingerprint matched
# (compare it with the AegisProxy console, TLS & CA, opened over https)
${verifiedPem('/usr/local/share/ca-certificates/aegis-enterprise-ca.crt', 'update-ca-certificates')}

# Or run the automated installer (fingerprint-pinned, checked against its SHA-256 before it runs;
# also configures Git, pip, Node and curl):
${installCommands(base, ca).linux}`;
    case 'rhel':
      return `# RHEL 8/9, Rocky Linux, AlmaLinux, Fedora, Oracle Linux — only after the fingerprint matched
# (compare it with the AegisProxy console, TLS & CA, opened over https)
${verifiedPem('/etc/pki/ca-trust/source/anchors/aegis-enterprise-ca.crt', 'update-ca-trust extract')}

# Or run the automated installer (fingerprint-pinned, checked against its SHA-256 before it runs):
${installCommands(base, ca).linux}`;
    case 'windows':
      return `# Windows Server 2019 / 2022 / 2025 — automated installer
# (run as Administrator; checked against its SHA-256 before it runs, pinned to the CA fingerprint,
# adds exactly that certificate to LocalMachine\\Root)
${installCommands(base, ca).windows}

# Or manually (Administrator PowerShell): download into your own temp folder, check that the file is exactly
# the certificate with the fingerprint from the AegisProxy console (opened over https), then add only that one
$f = Join-Path $env:TEMP ("aegis-ca-" + [guid]::NewGuid() + ".der")
Invoke-WebRequest -UseBasicParsing -Uri "${base}/api/public/ca/aegis-ca.der" -OutFile $f
$bytes = [IO.File]::ReadAllBytes($f); Remove-Item $f
$fp = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', ':')
if ($fp -ne '${fp}') { throw 'CA NOT installed: the download is not the certificate with this fingerprint' }
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
$store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); $store.Open('ReadWrite'); $store.Add($cert); $store.Close()

# Configure the WinHTTP proxy for Windows services
netsh winhttp set proxy proxy-server="http=<proxy-host>:8080;https=<proxy-host>:8080"`;
    case 'docker':
      return `# Docker daemon and containerd use the host trust store: import the CA as shown for
# Ubuntu / RHEL (fingerprint-checked), then restart them
sudo systemctl restart containerd docker

# Inside a Dockerfile: ADD refuses a download whose SHA-256 differs (Dockerfile syntax 1.6+, first
# line "# syntax=docker/dockerfile:1.6"; compare the value with the console opened over https)
ADD --checksum=sha256:${pemSha} ${base}/api/public/ca/aegis-ca.crt /usr/local/share/ca-certificates/aegis-ca.crt
RUN update-ca-certificates`;
    case 'runtime':
      return `# CLI tools and language runtimes (/etc/profile.d/aegis-ca.sh)
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
export GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
export AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`;
  }
}
