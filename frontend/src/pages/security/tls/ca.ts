// Root CA helpers shared by the TLS & CA page and the public block portal.

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

/** Fingerprint-pinned one-line installers served by the control plane. */
export function installCommands(base: string) {
  return {
    linux: `curl -fsSL ${base}/api/public/ca/install-linux.sh | sudo bash`,
    windows: `powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing ${base}/api/public/ca/install-windows.ps1 | iex"`,
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

/** Manual trust-store import guides per platform. */
export function trustSnippet(os: TrustOs, base: string): string {
  switch (os) {
    case 'ubuntu':
      return `# Ubuntu / Debian / Proxmox — system-wide CA import
sudo curl -fsSL ${base}/api/public/ca/aegis-ca.crt \\
  -o /usr/local/share/ca-certificates/aegis-enterprise-ca.crt
sudo update-ca-certificates

# Or run the automated installer (fingerprint-pinned; also configures Git, pip, Node and curl):
curl -fsSL ${base}/api/public/ca/install-linux.sh | sudo bash`;
    case 'rhel':
      return `# RHEL 8/9, Rocky Linux, AlmaLinux, Fedora, Oracle Linux
sudo curl -fsSL ${base}/api/public/ca/aegis-ca.crt \\
  -o /etc/pki/ca-trust/source/anchors/aegis-enterprise-ca.crt
sudo update-ca-trust extract

# Verify the trust chain
openssl verify /etc/pki/ca-trust/source/anchors/aegis-enterprise-ca.crt`;
    case 'windows':
      return `# Windows Server 2019 / 2022 / 2025 — automated installer
# (run as Administrator; pinned to the CA fingerprint, imports into LocalMachine\\Root)
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing ${base}/api/public/ca/install-windows.ps1 | iex"

# Or manually (Administrator PowerShell)
Invoke-WebRequest -UseBasicParsing -Uri "${base}/api/public/ca/aegis-ca.der" -OutFile "C:\\Windows\\Temp\\aegis-ca.der"
Import-Certificate -FilePath "C:\\Windows\\Temp\\aegis-ca.der" -CertStoreLocation Cert:\\LocalMachine\\Root

# Configure the WinHTTP proxy for Windows services
netsh winhttp set proxy proxy-server="http=<proxy-host>:8080;https=<proxy-host>:8080"`;
    case 'docker':
      return `# Docker daemon and containerd host trust
sudo mkdir -p /etc/docker/certs.d
sudo curl -fsSL ${base}/api/public/ca/aegis-ca.crt -o /etc/ssl/certs/aegis-enterprise-ca.pem
sudo systemctl restart containerd docker

# Inside a Dockerfile (multi-stage builds)
ADD ${base}/api/public/ca/aegis-ca.crt /usr/local/share/ca-certificates/aegis-ca.crt
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
