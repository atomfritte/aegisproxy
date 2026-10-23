// YARA helpers: rule counting and data-plane compile status (heartbeat `yara_status`).
import type { DataPlaneStatus, YaraRuleSet } from '../../../types';
import type { Tone } from '../../../ui';

const RULE_RE = /^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*/gm;

/** Number of rule declarations in a source (comments are not parsed — an estimate). */
export function countRules(source: string): number {
  return (source.match(RULE_RE) ?? []).length;
}

export const yaraPath = (id?: string) => (id ? `/threats/yara/${encodeURIComponent(id)}` : '/threats/yara');

export interface EngineState {
  /** partial: some rule sets failed to compile, the others are active. */
  key: 'ok' | 'idle' | 'unavailable' | 'error' | 'partial' | 'unknown';
  label: string;
  tone: Tone;
  description: string;
  error?: string;
}

/** Parses the worker heartbeat value: ok | idle | unavailable | error:<message> | '' (older worker). */
export function yaraState(status?: string): EngineState {
  const v = (status || '').trim();
  if (v === 'ok') return { key: 'ok', label: 'Compiled', tone: 'success', description: 'The enabled rule sets are compiled and scanning downloads.' };
  if (v === 'idle') return { key: 'idle', label: 'No rules', tone: 'neutral', description: 'The engine is ready; no enabled rule set is loaded.' };
  if (v === 'unavailable')
    return { key: 'unavailable', label: 'Engine missing', tone: 'warning', description: 'This worker has no YARA engine (yara-x). Use the standard data-plane image.' };
  if (v.startsWith('error')) {
    const msg = v.replace(/^error:?\s*/, '');
    const partial = /^(\d+) of (\d+) rule sets failed:\s*/.exec(msg);
    if (partial) {
      const failed = Number(partial[1]);
      const total = Number(partial[2]);
      return {
        key: failed < total ? 'partial' : 'error',
        label: failed < total ? `${failed} of ${total} sets failed` : 'Compile error',
        tone: failed < total ? 'warning' : 'danger',
        description:
          failed < total
            ? 'Some rule sets failed to compile: they keep their previous version (or are skipped); every other set is active.'
            : 'No rule set compiled: failing sets keep their previous version or are skipped.',
        error: msg.slice(partial[0].length),
      };
    }
    return { key: 'error', label: 'Compile error', tone: 'danger', description: 'The rules failed to compile; the previous rules stay active on this worker.', error: msg };
  }
  return { key: 'unknown', label: 'Unknown', tone: 'neutral', description: 'The worker did not report a YARA status (older data-plane version).' };
}

/** ICAP heartbeat: "disabled" | "respmod=ok,reqmod=down" | … */
export function icapState(status?: string): { label: string; tone: Tone; parts: Array<{ kind: string; state: string }> } {
  const v = (status || '').trim();
  if (!v) return { label: 'Unknown', tone: 'neutral', parts: [] };
  if (v === 'disabled') return { label: 'Off', tone: 'neutral', parts: [] };
  const parts = v.split(',').map((p) => {
    const [kind, state = 'unknown'] = p.split('=');
    return { kind: kind.trim(), state: state.trim() };
  });
  const down = parts.some((p) => p.state === 'down');
  const unknown = parts.some((p) => p.state !== 'ok' && p.state !== 'down');
  return { label: down ? 'Unreachable' : unknown ? 'Connecting' : 'Connected', tone: down ? 'danger' : unknown ? 'warning' : 'success', parts };
}

/** Summary across workers: how many compiled, failed, … */
export function yaraFleet(planes: DataPlaneStatus[]) {
  const states = planes.map((p) => ({ plane: p, st: yaraState(p.yara_status) }));
  return {
    states,
    ok: states.filter((s) => s.st.key === 'ok').length,
    /** workers reporting compile problems (all or some rule sets) */
    errors: states.filter((s) => s.st.key === 'error' || s.st.key === 'partial'),
    failedAll: states.filter((s) => s.st.key === 'error').length,
    unavailable: states.filter((s) => s.st.key === 'unavailable').length,
  };
}

/** Rule sets an error message refers to ("<set name>: <message>", or the rs_<n>_<id prefix> namespace). */
export function setsInError(message: string, sets: YaraRuleSet[]): YaraRuleSet[] {
  return sets.filter((s) => (s.name && message.includes(`${s.name}:`)) || (s.id && message.includes(s.id.slice(0, 24).replace(/-/g, '_'))));
}

/** The part of a worker message about one rule set ("Broken: line 3: … (rule set skipped)"). */
export function errorForSet(message: string, set: YaraRuleSet): string {
  const part = message.split('; ').find((p) => p.startsWith(`${set.name}:`));
  return part ? part.slice(set.name.length + 1).trim() : message;
}

export const YARA_TEMPLATE = `rule Suspicious_PowerShell_Download_Cradle
{
  meta:
    description = "PowerShell download cradle in a downloaded script"
    author = "SecOps"
    severity = "high"

  strings:
    $iex = "IEX" nocase
    $dl1 = "DownloadString" nocase
    $dl2 = "DownloadFile" nocase
    $b64 = "FromBase64String" nocase

  condition:
    filesize < 2MB and $iex and any of ($dl*) and $b64
}
`;
