import React, { useCallback } from 'react';
import { api } from '../../../api';
import { useConsole } from '../../../data/AppData';
import { navigate } from '../../../lib/router';
import type { BlockPageTemplate, ServerGroup } from '../../../types';
import { Callout, useConfirm, useToast } from '../../../ui';
import { LIMITS, toDraft, toPayload } from './model';

/** Groups that use `templateId` explicitly (group.block_page_template_id). */
export function assignedGroups(groups: ServerGroup[], templateId: string): ServerGroup[] {
  return groups.filter((g) => (g.block_page_template_id || '') === templateId);
}

/** Groups without an explicit template (they see the default template). */
export function unassignedGroups(groups: ServerGroup[]): ServerGroup[] {
  return groups.filter((g) => !g.block_page_template_id);
}

/**
 * Applies the group selection of a template: POST /api/groups with the full group object for every
 * group whose assignment changed (all other fields, incl. match_labels, are sent back unchanged).
 * Returns the number of updated groups.
 */
export async function saveAssignments(templateId: string, selected: string[], groups: ServerGroup[]): Promise<number> {
  const changed = groups.filter((g) => ((g.block_page_template_id || '') === templateId) !== selected.includes(g.id));
  for (const g of changed) {
    const want = selected.includes(g.id);
    await api.groups.upsert({ ...g, block_page_template_id: want ? templateId : '' });
  }
  return changed.length;
}

function uniqueName(base: string, taken: string[]): string {
  const lower = new Set(taken.map((t) => t.toLowerCase()));
  const clip = (s: string) => s.slice(0, LIMITS.name);
  let name = clip(base);
  for (let i = 2; lower.has(name.toLowerCase()) && i < 100; i++) name = clip(`${base} (${i})`);
  return name;
}

/** Duplicate / set default / delete with toasts, confirmations and a state refresh. */
export function useTemplateActions() {
  const { state, refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const templates = state?.block_pages ?? [];
  const groups = state?.groups ?? [];

  const duplicate = useCallback(
    async (t: BlockPageTemplate) => {
      try {
        const copy = await api.blockPages.create({
          ...toPayload(toDraft(t)),
          name: uniqueName(`Copy of ${t.name}`, templates.map((x) => x.name)),
          is_default: false,
        });
        await refresh();
        toast.success(`Duplicated as “${copy.name}”`);
        navigate(`/block-pages/${encodeURIComponent(copy.id)}`);
      } catch (err) {
        toast.error(err, { title: 'Could not duplicate the template' });
      }
    },
    [templates, refresh, toast]
  );

  const makeDefault = useCallback(
    async (t: BlockPageTemplate) => {
      const ok = await confirm({
        title: `Make “${t.name}” the default?`,
        description: 'Servers in groups without an assigned template will see this block page from their next request on.',
        confirmLabel: 'Make default',
        onConfirm: () => api.blockPages.update(t.id, { ...toPayload(toDraft(t)), is_default: true }),
      });
      if (ok) {
        await refresh();
        toast.success(`“${t.name}” is now the default template`);
      }
    },
    [confirm, refresh, toast]
  );

  const remove = useCallback(
    async (t: BlockPageTemplate, opts: { onDeleted?: () => void } = {}) => {
      const used = assignedGroups(groups, t.id);
      const ok = await confirm({
        title: `Delete “${t.name}”?`,
        description: 'The template is removed permanently. Servers keep working with their group’s or the default template.',
        tone: 'danger',
        confirmLabel: 'Delete template',
        typeToConfirm: t.name,
        body:
          used.length > 0 ? (
            <Callout tone="warning" title={`Assigned to ${used.length} ${used.length === 1 ? 'group' : 'groups'}`}>
              <span className="mb-1.5 block">The server refuses to delete assigned templates. Assign these groups to another template first:</span>
              {/* plain chips: confirm dialogs render outside the data provider (no lookup hooks) */}
              <span className="flex flex-wrap gap-1">
                {used.map((g) => (
                  <span key={g.id} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[12px] text-fg">
                    <span className="h-2 w-2 rounded-full" style={{ background: g.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
                    {g.name}
                  </span>
                ))}
              </span>
            </Callout>
          ) : undefined,
        onConfirm: () => api.blockPages.remove(t.id),
      });
      if (ok) {
        await refresh();
        toast.success(`Deleted “${t.name}”`);
        opts.onDeleted?.();
      }
    },
    [groups, confirm, refresh, toast]
  );

  return { duplicate, makeDefault, remove };
}
