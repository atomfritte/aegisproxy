import React, { useMemo } from 'react';
import { Copy, ExternalLink, FileWarning, Languages, MoreHorizontal, Pencil, Plus, Star, Trash2, Users } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { useDocumentTitle } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { BlockPageTemplate } from '../../types';
import { Badge, ButtonLink, Callout, Card, EmptyState, IconButton, Menu, PageHeader, RelativeTime, Tooltip, useToast } from '../../ui';
import { ChipList, GroupChip, UserName } from '../../components/common/EntityChips';
import { assignedGroups, unassignedGroups, useTemplateActions } from './blockpages/actions';
import { toDraft, type Locale } from './blockpages/model';
import { openSavedPreview } from './blockpages/openPreview';
import { ScaledFrame } from './blockpages/ScaledFrame';
import { usePreview } from './blockpages/usePreview';

const editPath = (id: string) => `/block-pages/${encodeURIComponent(id)}`;

const Thumbnail: React.FC<{ t: BlockPageTemplate }> = ({ t }) => {
  const draft = useMemo(() => toDraft(t), [t]);
  const p = usePreview(draft, (t.default_locale as Locale) || 'en', 'request');
  return (
    <div className="relative h-[188px] overflow-hidden bg-surface-3">
      {p.html ? (
        <ScaledFrame html={p.html} title={`Preview of ${t.name}`} logicalWidth={960} height={188} thumbnail />
      ) : (
        <div className="flex h-full items-center justify-center text-[12px] text-fg-subtle">{p.error ? 'Preview unavailable' : 'Rendering…'}</div>
      )}
    </div>
  );
};

const TemplateCard: React.FC<{ t: BlockPageTemplate; canManage: boolean }> = ({ t, canManage }) => {
  const state = useConsoleState();
  const { duplicate, makeDefault, remove } = useTemplateActions();
  const toast = useToast();
  const groups = state.groups ?? [];
  const explicit = assignedGroups(groups, t.id);
  const implicit = t.is_default ? unassignedGroups(groups) : [];
  const scopes = (t.allowed_scopes ?? []).length;

  return (
    <Card as="article" className="group flex flex-col overflow-hidden" aria-labelledby={`bp-${t.id}`}>
      <Link to={editPath(t.id)} tabIndex={-1} aria-hidden className="relative block border-b border-border">
        <Thumbnail t={t} />
        <span className="absolute inset-0 flex items-center justify-center bg-fg/0 opacity-0 transition-all group-hover:bg-fg/10 group-hover:opacity-100">
          <span className="rounded-md border border-border bg-surface px-2.5 py-1 text-[12.5px] font-medium text-fg shadow-pop">{canManage ? 'Edit template' : 'View template'}</span>
        </span>
      </Link>
      <div className="flex flex-1 flex-col gap-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Link id={`bp-${t.id}`} to={editPath(t.id)} className="truncate text-[14px] font-semibold text-fg hover:text-accent hover:underline">
                {t.name}
              </Link>
              {t.is_default && (
                <Badge tone="accent" icon={Star}>
                  Default
                </Badge>
              )}
            </div>
            <div className="mt-1 flex items-center gap-2 text-[12px] text-fg-muted">
              <span className="flex shrink-0 gap-1" aria-hidden>
                <span className="h-3 w-3 rounded-full border border-fg/10" style={{ background: t.primary_color }} />
                <span className="h-3 w-3 rounded-full border border-fg/10" style={{ background: t.accent_color }} />
              </span>
              <span className="truncate">{t.company_name || 'No company name'}</span>
            </div>
          </div>
          <Menu
            items={[
              { id: 'edit', label: canManage ? 'Edit' : 'View', icon: Pencil, to: editPath(t.id) },
              {
                id: 'open',
                label: 'Open full page',
                icon: ExternalLink,
                onSelect: () => openSavedPreview(t.id, { locale: t.default_locale, variant: 'request' }).catch((err) => toast.error(err, { title: 'Could not open the preview' })),
              },
              { id: 'dup', label: 'Duplicate', icon: Copy, onSelect: () => duplicate(t), hidden: !canManage, separator: true },
              {
                id: 'default',
                label: 'Make default',
                icon: Star,
                onSelect: () => makeDefault(t),
                hidden: !canManage || t.is_default,
                description: 'Used by servers in groups without a template',
              },
              {
                id: 'delete',
                label: 'Delete…',
                icon: Trash2,
                danger: true,
                hidden: !canManage,
                disabled: t.is_default,
                description: t.is_default ? 'Make another template the default first' : undefined,
                onSelect: () => remove(t),
                separator: true,
              },
            ]}
            trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${t.name}`} size="sm" noTooltip />}
          />
        </div>

        <div className="flex flex-wrap gap-1.5">
          <Badge tone="neutral" icon={Languages}>
            {t.default_locale === 'de' ? 'Deutsch' : 'English'} default
          </Badge>
          <Badge tone="neutral">{t.theme === 'auto' ? 'Auto theme' : t.theme === 'dark' ? 'Dark theme' : 'Light theme'}</Badge>
          {t.show_request_form ? (
            <Tooltip content={`${scopes} ${scopes === 1 ? 'scope' : 'scopes'}: ${(t.allowed_durations ?? []).join(', ')}`}>
              <Badge tone="success">Self-service on</Badge>
            </Tooltip>
          ) : (
            <Badge tone="neutral">No request form</Badge>
          )}
        </div>

        <div className="mt-auto min-w-0">
          <div className="mb-1 flex items-center gap-1.5 text-[11.5px] font-medium text-fg-subtle">
            <Users className="h-3 w-3" aria-hidden />
            {t.is_default ? 'Used by' : 'Assigned to'}
          </div>
          {explicit.length > 0 ? (
            <ChipList max={3}>
              {explicit.map((g) => (
                <GroupChip key={g.id} id={g.id} />
              ))}
            </ChipList>
          ) : t.is_default ? (
            <span className="text-[12.5px] text-fg-muted">
              {implicit.length === groups.length ? 'All groups' : `${implicit.length} of ${groups.length} groups`} (no template assigned)
            </span>
          ) : (
            <span className="text-[12.5px] text-fg-subtle">Not assigned — no server sees this page yet</span>
          )}
        </div>
      </div>
      <footer className="flex items-center gap-1.5 border-t border-border bg-surface-2 px-4 py-2 text-[12px] text-fg-subtle">
        {t.updated_at ? (
          <>
            Updated <RelativeTime value={t.updated_at} />
            {t.updated_by && (
              <>
                by <UserName username={t.updated_by} avatar={false} />
              </>
            )}
          </>
        ) : (
          'Not edited in the console yet'
        )}
      </footer>
    </Card>
  );
};

/** Block page templates: cards with live thumbnails, default + group assignments. */
export const BlockPagesPage: React.FC = () => {
  useDocumentTitle('Block pages');
  const state = useConsoleState();
  const perms = usePermissions();
  const canManage = perms.canManageSystem;
  const templates = useMemo(
    () => [...(state.block_pages ?? [])].sort((a, b) => Number(b.is_default) - Number(a.is_default) || a.name.localeCompare(b.name)),
    [state.block_pages]
  );
  const def = templates.find((t) => t.is_default);
  const assignedCount = (state.groups ?? []).filter((g) => g.block_page_template_id).length;

  return (
    <>
      <PageHeader
        title="Block pages"
        description="What servers see in the browser and in the terminal when a request is blocked. Assign templates to server groups; every other server uses the default."
        meta={
          <>
            <Badge tone="neutral">{templates.length} {templates.length === 1 ? 'template' : 'templates'}</Badge>
            <Badge tone="neutral">
              {assignedCount} of {(state.groups ?? []).length} groups with their own template
            </Badge>
          </>
        }
        actions={
          canManage && (
            <ButtonLink to="/block-pages/new" variant="primary" icon={Plus}>
              New template
            </ButtonLink>
          )
        }
      />

      {!canManage && (
        <Callout tone="neutral" className="mb-5">
          You can view templates and previews. Only InfoSec Approvers and Super Admins can change them.
        </Callout>
      )}

      {templates.length === 0 ? (
        <Card>
          <EmptyState
            icon={FileWarning}
            title="No block page templates"
            description="Blocked requests use the built-in page until you create a template."
            action={
              canManage && (
                <ButtonLink to="/block-pages/new" variant="primary" icon={Plus}>
                  Create the first template
                </ButtonLink>
              )
            }
          />
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {templates.map((t) => (
            <TemplateCard key={t.id} t={t} canManage={canManage} />
          ))}
          {canManage && (
            <Link
              to="/block-pages/new"
              className={cn(
                'flex min-h-[200px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border-strong p-6 text-center transition-colors',
                'hover:border-accent hover:bg-accent-soft/50'
              )}
            >
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-accent-soft text-accent">
                <Plus className="h-5 w-5" aria-hidden />
              </span>
              <span className="text-[13.5px] font-medium text-fg">New template</span>
              <span className="max-w-[260px] text-[12.5px] text-fg-muted">
                For example a stricter page for PCI or production groups{def ? `, based on the defaults of “${def.name}”` : ''}.
              </span>
            </Link>
          )}
        </div>
      )}

      <p className="mt-6 text-[12.5px] leading-5 text-fg-subtle">
        How a template is chosen: the first group of a server that has a template assigned wins; otherwise the default applies. Threat-protection and
        quarantine blocks always use the threat variant without a request form.
      </p>
    </>
  );
};
