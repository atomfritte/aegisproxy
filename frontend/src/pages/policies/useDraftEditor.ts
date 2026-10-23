import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PolicyRule, PolicySet, PolicySetSpecInput, RuleInput } from '../../types';
import { toSpecInput, workingSpec } from '../../components/policy/policyUtils';

export interface DraftRow {
  /** Client-side key (stable across edits; new rules have rule.id === ''). */
  key: string;
  rule: RuleInput;
}

export type DraftMeta = Omit<PolicySetSpecInput, 'rules'>;

let keySeq = 0;
const newKey = () => `row-${++keySeq}`;

const RULE_FIELDS = ['name', 'description', 'action', 'host_pattern', 'path_pattern', 'methods', 'follow_redirects', 'companion_rules', 'enabled', 'expires_at'] as const;

function sameRule(a: RuleInput | PolicyRule, b: RuleInput | PolicyRule): boolean {
  return RULE_FIELDS.every((f) => JSON.stringify((a as any)[f] ?? null) === JSON.stringify((b as any)[f] ?? null));
}

/**
 * Local working copy of a policy set draft (lives in the detail page so it survives tab switches).
 * Initialized from the saved draft, or from the published content when there is no draft yet.
 */
export function useDraftEditor(set: PolicySet | undefined) {
  const sourceKey = set ? `${set.id}|${set.version}|${set.draft?.updated_at ?? 'none'}|${set.draft?.status ?? ''}` : '';
  const [meta, setMeta] = useState<DraftMeta | null>(null);
  const [rows, setRows] = useState<DraftRow[]>([]);
  const baseJson = useRef('');
  const loadedKey = useRef('');
  const force = useRef(false);

  const reset = useCallback(() => {
    if (!set) return;
    const spec = toSpecInput(workingSpec(set));
    const { rules, ...m } = spec;
    setMeta(m);
    setRows(rules.map((r) => ({ key: newKey(), rule: r })));
    baseJson.current = JSON.stringify(spec);
    loadedKey.current = sourceKey;
  }, [set, sourceKey]);

  const current: PolicySetSpecInput | null = useMemo(() => (meta ? { ...meta, rules: rows.map((r) => r.rule) } : null), [meta, rows]);
  const dirty = !!current && JSON.stringify(current) !== baseJson.current;

  // (re)initialize when the saved draft changes and there are no local edits
  useEffect(() => {
    if (!set) return;
    if (loadedKey.current === sourceKey) return;
    if (!force.current && loadedKey.current && loadedKey.current.split('|')[0] === set.id && dirty) return;
    force.current = false;
    reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceKey]);

  const published = useMemo(() => new Map((set?.rules ?? []).map((r) => [r.id, r])), [set]);

  const markOf = useCallback(
    (r: RuleInput): 'added' | 'modified' | undefined => {
      if (!r.id || !published.has(r.id)) return 'added';
      return sameRule(r, published.get(r.id)!) ? undefined : 'modified';
    },
    [published]
  );

  const removed = useMemo(() => {
    const ids = new Set(rows.map((r) => r.rule.id).filter(Boolean));
    return (set?.rules ?? []).filter((r) => !ids.has(r.id));
  }, [rows, set]);

  return {
    meta,
    setMeta: (patch: Partial<DraftMeta>) => setMeta((m) => (m ? { ...m, ...patch } : m)),
    rows,
    setRows,
    current,
    dirty,
    reset,
    markOf,
    removed,
    addRule: (rule: RuleInput) => setRows((rs) => [...rs, { key: newKey(), rule }]),
    newKey,
    /** Call after saving/discarding: the next server state replaces local edits. */
    expectReload: () => {
      force.current = true;
    },
    /** Whether the editor reflects the saved draft (false = editing starts from published). */
    hasSavedDraft: !!set?.draft,
  };
}

export type DraftEditor = ReturnType<typeof useDraftEditor>;
