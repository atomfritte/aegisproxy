// Field-level diff of the before/after JSON snapshots stored on audit events.

export type FieldChange = { path: string; before?: string; after?: string; kind: 'added' | 'removed' | 'changed' | 'same' };

export function parseState(raw?: string): unknown {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Flattens nested objects to dotted paths; arrays and scalars are leaves (rendered as JSON). */
function flatten(v: unknown, prefix = '', out: Map<string, string> = new Map()): Map<string, string> {
  if (isPlainObject(v)) {
    const keys = Object.keys(v);
    if (keys.length === 0 && prefix) out.set(prefix, '{}');
    for (const k of keys) flatten(v[k], prefix ? `${prefix}.${k}` : k, out);
  } else if (prefix) {
    out.set(prefix, typeof v === 'string' ? v : JSON.stringify(v));
  }
  return out;
}

/**
 * Compares two snapshots. Returns null when either side is not a JSON object (then show raw text).
 */
export function diffStates(beforeRaw?: string, afterRaw?: string): FieldChange[] | null {
  const before = parseState(beforeRaw);
  const after = parseState(afterRaw);
  if ((before !== undefined && !isPlainObject(before)) || (after !== undefined && !isPlainObject(after))) return null;
  const b = flatten(before ?? {});
  const a = flatten(after ?? {});
  const paths = [...new Set([...b.keys(), ...a.keys()])].sort();
  return paths.map((p) => {
    const bv = b.get(p);
    const av = a.get(p);
    let kind: FieldChange['kind'] = 'same';
    if (bv === undefined) kind = 'added';
    else if (av === undefined) kind = 'removed';
    else if (bv !== av) kind = 'changed';
    return { path: p, before: bv, after: av, kind };
  });
}

export function pretty(raw?: string): string {
  const v = parseState(raw);
  if (v === undefined) return '';
  return typeof v === 'string' ? v : JSON.stringify(v, null, 2);
}

/** Item-level delta when both values are JSON arrays of scalars (e.g. companion_rules, group_ids). */
export function arrayDelta(before?: string, after?: string): Array<{ value: string; kind: 'same' | 'added' | 'removed' }> | null {
  const parse = (v?: string): unknown[] | null => {
    if (v === undefined) return [];
    try {
      const x = JSON.parse(v);
      return Array.isArray(x) && x.every((i) => i === null || typeof i !== 'object') ? x : null;
    } catch {
      return null;
    }
  };
  const b = parse(before);
  const a = parse(after);
  if (!b || !a || (before === undefined && after === undefined)) return null;
  const bs = b.map((x) => String(x));
  const as = a.map((x) => String(x));
  const out: Array<{ value: string; kind: 'same' | 'added' | 'removed' }> = [];
  for (const v of bs) out.push({ value: v, kind: as.includes(v) ? 'same' : 'removed' });
  for (const v of as) if (!bs.includes(v)) out.push({ value: v, kind: 'added' });
  return out;
}
