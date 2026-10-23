// Pure helpers of the public block portal (token decoding, option catalogs, server error parsing).
import type { AccessScope } from '../../types';

/** Self-service durations accepted by POST /api/public/requests. */
export type PortalDuration = '1h' | '24h' | '7d' | 'permanent';

export interface BlockTokenClaims {
  ip?: string;
  sid?: string;
  url?: string;
  m?: string;
  tid?: string;
  v?: string;
  exp?: number;
}

/**
 * Decodes (WITHOUT verifying) the claims of a block token for display.
 * Format: "v1.<base64url(json)>.<base64url(hmac)>" — the control plane verifies the signature.
 */
export function decodeBlockToken(token: string): BlockTokenClaims | null {
  if (!token.startsWith('v1.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const v = JSON.parse(new TextDecoder().decode(bytes));
    return v && typeof v === 'object' ? (v as BlockTokenClaims) : null;
  } catch {
    return null;
  }
}

/** Verdicts without self-service (data-plane: security verdicts except POLICY_BLOCKED). */
export const NO_SELF_SERVICE_VERDICTS = ['THREAT_BLOCKED', 'MALWARE_BLOCKED', 'DLP_BLOCKED', 'FILETYPE_BLOCKED', 'QUARANTINED'];

export const VERDICT_LABELS: Record<string, string> = {
  BLOCKED: 'Not on the allow list',
  POLICY_BLOCKED: 'Blocked by security policy',
  THREAT_BLOCKED: 'Threat intelligence match',
  MALWARE_BLOCKED: 'Malware detected',
  DLP_BLOCKED: 'Data loss prevention',
  FILETYPE_BLOCKED: 'File type not allowed',
  QUARANTINED: 'Server is quarantined',
};

export const SCOPES: Array<{ value: AccessScope; title: string; description: string }> = [
  {
    value: 'prefix_with_objects',
    title: 'Path prefix and linked downloads',
    description: 'The suggested path (for example github.com/org/**) plus the objects it redirects to, such as release files on a CDN.',
  },
  { value: 'exact_path', title: 'Exact URL path only', description: 'Only this path. The narrowest option and the quickest to approve.' },
  { value: 'domain', title: 'Entire domain', description: 'Every path on this host. Reviewers may narrow it before approving.' },
  {
    value: 'learning_session_15m',
    title: '15-minute learning session',
    description: 'Records this server’s traffic for 15 minutes so the team can turn everything it needs into rules.',
  },
];

export const DURATIONS: Array<{ value: PortalDuration; label: string; hint: string }> = [
  { value: '1h', label: '1 hour', hint: 'Maintenance' },
  { value: '24h', label: '24 hours', hint: 'Release window' },
  { value: '7d', label: '7 days', hint: 'Project work' },
  { value: 'permanent', label: 'Permanent', hint: 'Ongoing need' },
];

export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * Parses "scope \"domain\" is not offered for this server (allowed: [exact_path])" (and the same
 * for durations) from POST /api/public/requests.
 */
export function parseNotOffered(message: string): { field: 'scope' | 'duration'; allowed: string[] } | null {
  const m = /(scope|duration) "[^"]*" is not offered for this server \(allowed: \[([^\]]*)\]\)/.exec(message || '');
  if (!m) return null;
  return { field: m[1] as 'scope' | 'duration', allowed: m[2].split(/[\s,]+/).filter(Boolean) };
}

export interface SubmitResult {
  message: string;
  duplicate: boolean;
  request: {
    id: string;
    status: string;
    verified: boolean;
    server_hostname?: string;
    suggested_host_pattern?: string;
    suggested_path_pattern?: string;
    created_at?: string;
  };
}
