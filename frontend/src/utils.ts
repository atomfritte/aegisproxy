import { Role, User } from './types';

/** "3m ago", "in 2h", "—" for missing values. */
export function formatRelative(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t) || t <= 0) return '—';
  const diffSec = Math.round((Date.now() - t) / 1000);
  const abs = Math.abs(diffSec);
  let val: string;
  if (abs < 45) val = `${abs}s`;
  else if (abs < 3600) val = `${Math.round(abs / 60)}m`;
  else if (abs < 86400) val = `${Math.round(abs / 3600)}h`;
  else val = `${Math.round(abs / 86400)}d`;
  return diffSec >= 0 ? `${val} ago` : `in ${val}`;
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Converts an <input type="datetime-local"> value into an RFC 3339 timestamp (or undefined). */
export function localInputToISO(value: string): string | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts (plain http on an internal hostname)
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

export function canManageSystem(user: Pick<User, 'role'> | null | undefined): boolean {
  return !!user && (user.role === 'SUPER_ADMIN' || user.role === 'INFOSEC_APPROVER');
}

export function isRole(user: Pick<User, 'role'> | null | undefined, ...roles: Role[]): boolean {
  return !!user && roles.includes(user.role);
}

export const MIB = 1024 * 1024;

export function bytesToMiB(bytes: number): number {
  return Math.round((bytes / MIB) * 1000) / 1000;
}

export function miBToBytes(mib: number): number {
  return Math.round(mib * MIB);
}

/** Password policy mirrored from the control-plane: >= 12 chars and 3 of 4 character classes. */
export function passwordPolicyError(pw: string): string | null {
  if (pw.length < 12) return 'Password must be at least 12 characters long.';
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  if (classes < 3) {
    return 'Password must contain at least 3 of: lowercase, uppercase, digits, symbols.';
  }
  return null;
}
