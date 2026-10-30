import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Copy,
  Eye,
  HelpCircle,
  Languages,
  LayoutList,
  MoreHorizontal,
  Palette,
  PencilLine,
  RotateCcw,
  Save,
  SquareTerminal,
  Star,
  TextCursorInput,
  Trash2,
  UserCheck,
  Users,
} from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState, usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { pluralize } from '../../lib/format';
import { useDocumentTitle, useHotkey, useIsMobile } from '../../lib/hooks';
import { navigate, useNavigationBlocker, useParams } from '../../lib/router';
import type { BlockPageTemplate } from '../../types';
import {
  Badge,
  Button,
  Callout,
  Field,
  IconButton,
  Input,
  Menu,
  MultiSelect,
  PageHeader,
  RelativeTime,
  SegmentedControl,
  Switch,
  Textarea,
  useConfirm,
  useToast,
} from '../../ui';
import { GroupChip } from '../../components/common/EntityChips';
import { NotFoundPage } from '../system/NotFoundPage';
import { assignedGroups, saveAssignments, useTemplateActions } from './blockpages/actions';
import { ChoiceGroup, ColorField, Counter, FormSection, LinksEditor, LogoField, useTextTargets, VariableToolbar } from './blockpages/fields';
import {
  BUILTIN,
  DURATIONS,
  LIMITS,
  SCOPES,
  draftKey,
  newTemplate,
  toDraft,
  toPayload,
  validateDraft,
  type DraftErrors,
  type Locale,
  type TemplateDraft,
} from './blockpages/model';
import { PreviewPane, type PreviewView } from './blockpages/PreviewPane';
import { usePreview } from './blockpages/usePreview';

const SECTIONS = [
  { id: 'branding', label: 'Branding' },
  { id: 'texts', label: 'Texts' },
  { id: 'help', label: 'Help' },
  { id: 'self-service', label: 'Self-service' },
  { id: 'sections', label: 'Sections' },
  { id: 'terminal', label: 'Terminal' },
  { id: 'language', label: 'Language' },
  { id: 'assignment', label: 'Assignment' },
];

const PRIMARY_PRESETS = ['#2563EB', '#0F766E', '#7C3AED', '#BE185D', '#334155', '#C2410C'];
const ACCENT_PRESETS = ['#DC2626', '#EA580C', '#D97706', '#B91C1C', '#9333EA', '#0891B2'];

/** Errors shown before the first save attempt (format problems, not "required"). */
function liveErrors(e: DraftErrors): DraftErrors {
  const out: DraftErrors = {};
  for (const [k, v] of Object.entries(e)) {
    if (k === 'name' && v?.startsWith('Give')) continue;
    if (/^links\.\d+\.label$/.test(k) && v === 'Label required.') continue;
    out[k] = v;
  }
  return out;
}

/** Route /block-pages/:id (id "new" creates a template). */
export const BlockPageEditorPage: React.FC = () => {
  const { id = '' } = useParams<{ id: string }>();
  const state = useConsoleState();
  const isNew = id === 'new';
  const tpl = isNew ? undefined : (state.block_pages ?? []).find((t) => t.id === id);
  if (!isNew && !tpl) {
    return (
      <NotFoundPage
        title="Template not found"
        description="This block page template does not exist (anymore). It may have been deleted."
        backTo="/block-pages"
        backLabel="Back to block pages"
      />
    );
  }
  return <Editor key={id} template={tpl} />;
};

const Editor: React.FC<{ template?: BlockPageTemplate }> = ({ template }) => {
  const state = useConsoleState();
  const { refresh } = useConsole();
  const perms = usePermissions();
  const toast = useToast();
  const confirm = useConfirm();
  const isMobile = useIsMobile();
  const actions = useTemplateActions();
  const readOnly = !perms.canManageSystem;
  const isNew = !template;
  const groups = state.groups ?? [];
  const defaultTpl = (state.block_pages ?? []).find((t) => t.is_default);

  const initial = useMemo(() => (template ? toDraft(template) : newTemplate(defaultTpl?.company_name || '')), [template?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const [baseline, setBaseline] = useState<TemplateDraft>(initial);
  const [draft, setDraft] = useState<TemplateDraft>(initial);
  const baseGroups = useMemo(() => (template ? assignedGroups(groups, template.id).map((g) => g.id).sort((a, b) => String(a).localeCompare(String(b))) : []), [groups, template]);
  const [selGroups, setSelGroups] = useState<string[]>(baseGroups);
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [mobileTab, setMobileTab] = useState<'edit' | 'preview'>('edit');
  const [view, setView] = useState<PreviewView>({ mode: 'browser', variant: 'request', locale: (initial.default_locale as Locale) || 'en', device: isMobile ? 'phone' : 'desktop' });

  const groupsDirty = JSON.stringify([...selGroups].sort((a, b) => String(a).localeCompare(String(b)))) !== JSON.stringify(baseGroups);
  const dirty = draftKey(draft) !== draftKey(baseline) || groupsDirty;
  const allErrors = useMemo(() => validateDraft(draft), [draft]);
  const errors = attempted ? allErrors : liveErrors(allErrors);

  useDocumentTitle(isNew ? 'New block page' : template?.name || 'Block page');
  useNavigationBlocker(dirty && !saving, 'Discard unsaved changes to this block page?');

  // Adopt changes made elsewhere (another admin, a refresh) while nothing is being edited here.
  const serverKey = template ? `${template.updated_at}|${baseGroups.join(',')}` : '';
  const lastServerKey = useRef(serverKey);
  useEffect(() => {
    if (serverKey === lastServerKey.current) return;
    lastServerKey.current = serverKey;
    if (!dirty && template) {
      const d = toDraft(template);
      setBaseline(d);
      setDraft(d);
      setSelGroups(baseGroups);
    }
  }, [serverKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const preview = usePreview(draft, view.locale, view.variant);

  const set = <K extends keyof TemplateDraft>(k: K, v: TemplateDraft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const setSupport = (k: keyof TemplateDraft['support'], v: string) => setDraft((d) => ({ ...d, support: { ...d.support, [k]: v } }));

  const textLabels: Record<string, string> = { title: 'Title', message: 'Message', threat_message: 'Threat message', footer_text: 'Footer' };
  const texts = useTextTargets(
    ['message', 'title', 'threat_message', 'footer_text'],
    (f) => String(draft[f as keyof TemplateDraft] ?? ''),
    (f, v) => set(f as 'message', v)
  );
  const cliLabels: Record<string, string> = { cli_header: 'Header', cli_footer: 'Footer' };
  const cliTexts = useTextTargets(['cli_header', 'cli_footer'], (f) => String(draft[f as keyof TemplateDraft] ?? ''), (f, v) => set(f as 'cli_header', v));

  // Follow the field being edited in the preview (threat message → threat variant, CLI → terminal).
  const focusPreview = (patch: Partial<PreviewView>) => setView((v) => ({ ...v, ...patch }));

  const save = async () => {
    if (readOnly || saving) return;
    setAttempted(true);
    const keys = Object.keys(allErrors);
    if (keys.length > 0) {
      toast.error(`${pluralize(keys.length, 'field needs', 'fields need')} attention: ${Object.values(allErrors)[0]}`, { title: 'Template not saved' });
      const first = keys[0].split('.')[0];
      const section =
        first === 'name' || first === 'company_name' || first.endsWith('color')
          ? 'branding'
          : first === 'support' || first === 'links'
            ? 'help'
            : first.startsWith('allowed')
              ? 'self-service'
              : first.startsWith('cli')
                ? 'terminal'
                : 'texts';
      setMobileTab('edit');
      window.setTimeout(() => document.getElementById(section)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
      return;
    }
    setSaving(true);
    try {
      const payload = toPayload(draft);
      const saved = template ? await api.blockPages.update(template.id, payload) : await api.blockPages.create(payload);
      let changed = 0;
      let assignError: unknown = null;
      try {
        changed = await saveAssignments(saved.id, selGroups, groups);
      } catch (err) {
        assignError = err;
      }
      await refresh();
      const d = toDraft(saved);
      setBaseline(d);
      setDraft(d);
      setAttempted(false);
      if (assignError) toast.error(assignError, { title: `“${saved.name}” saved, but the group assignment failed` });
      else
        toast.success(isNew ? `Created “${saved.name}”` : `Saved “${saved.name}”`, {
          description: changed > 0 ? `${pluralize(changed, 'group assignment')} updated. Workers pick up the change within seconds.` : 'Workers pick up the change within seconds.',
        });
      if (isNew) navigate(`/block-pages/${encodeURIComponent(saved.id)}`, { replace: true });
    } catch (err) {
      toast.error(err, { title: 'Template not saved' });
    } finally {
      setSaving(false);
    }
  };

  const discard = async () => {
    const ok = await confirm({ title: 'Discard unsaved changes?', description: 'The form returns to the last saved version.', confirmLabel: 'Discard changes', tone: 'danger' });
    if (ok) {
      setDraft(baseline);
      setSelGroups(baseGroups);
      setAttempted(false);
    }
  };

  useHotkey('mod+s', (e) => {
    e.preventDefault();
    if (dirty) save();
  }, { enabled: !readOnly, allowInInputs: true });

  const groupOptions = groups.map((g) => {
    const other = g.block_page_template_id && g.block_page_template_id !== template?.id ? (state.block_pages ?? []).find((t) => t.id === g.block_page_template_id) : undefined;
    return {
      value: g.id,
      label: g.name,
      color: g.color,
      description: other ? `Currently uses “${other.name}”` : g.block_page_template_id ? undefined : 'Currently uses the default',
    };
  });
  const reassigned = selGroups.filter((gid) => {
    const g = groups.find((x) => x.id === gid);
    return g?.block_page_template_id && g.block_page_template_id !== template?.id;
  });
  const serversAffected = state.servers.filter((s) => (s.effective_group_ids ?? s.group_ids ?? []).some((g) => selGroups.includes(g))).length;
  const builtin = BUILTIN[(draft.default_locale as Locale) || 'en'] ?? BUILTIN.en;

  const title = isNew ? (draft.name.trim() ? draft.name : 'New block page') : template!.name;

  const headerActions = readOnly ? null : (
    <>
      {dirty && (
        <Button icon={RotateCcw} onClick={discard} disabled={saving}>
          Discard
        </Button>
      )}
      <Button variant="primary" icon={Save} onClick={save} loading={saving} disabled={!dirty && !isNew}>
        {isNew ? 'Create template' : 'Save'}
      </Button>
      {template && (
        <Menu
          items={[
            { id: 'dup', label: 'Duplicate', icon: Copy, onSelect: () => actions.duplicate(template), disabled: dirty, description: dirty ? 'Save or discard your changes first' : undefined },
            { id: 'default', label: 'Make default', icon: Star, hidden: template.is_default, onSelect: () => actions.makeDefault(template), disabled: dirty, description: dirty ? 'Save or discard your changes first' : undefined },
            {
              id: 'delete',
              label: 'Delete…',
              icon: Trash2,
              danger: true,
              separator: true,
              disabled: template.is_default,
              description: template.is_default ? 'The default template cannot be deleted' : undefined,
              onSelect: () => actions.remove(template, { onDeleted: () => navigate('/block-pages', { replace: true }) }),
            },
          ]}
          trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label="More actions" variant="secondary" noTooltip />}
        />
      )}
    </>
  );

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Block pages', to: '/block-pages' }, { label: isNew ? 'New template' : template!.name }]}
        title={title}
        meta={
          <>
            {draft.is_default && (
              <Badge tone="accent" icon={Star}>
                Default
              </Badge>
            )}
            {dirty && !readOnly && (
              <Badge tone="warning" dot>
                Unsaved changes
              </Badge>
            )}
            {readOnly && <Badge tone="neutral">Read-only</Badge>}
            {template?.updated_at && (
              <span className="text-[12.5px] text-fg-subtle">
                Saved <RelativeTime value={template.updated_at} />
                {template.updated_by ? ` by ${template.updated_by}` : ''}
              </span>
            )}
          </>
        }
        actions={headerActions}
      />

      {readOnly && (
        <Callout tone="neutral" className="mb-5">
          You can explore the template and its preview. Only InfoSec Approvers and Super Admins can change block pages.
        </Callout>
      )}

      <div className="sticky top-14 z-20 -mx-4 mb-4 border-b border-border bg-bg/95 px-4 py-2 backdrop-blur-sm lg:hidden">
        <SegmentedControl
          aria-label="Editor or preview"
          value={mobileTab}
          onChange={setMobileTab}
          className="w-full [&>button]:flex-1 [&>button]:justify-center"
          options={[
            { value: 'edit', label: 'Edit', icon: PencilLine },
            { value: 'preview', label: 'Preview', icon: Eye },
          ]}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] 2xl:grid-cols-[minmax(0,600px)_minmax(0,1fr)]">
        {/* ---------------------------------------------------------------- form */}
        <div className={cn('min-w-0', mobileTab === 'preview' && 'hidden lg:block')}>
          <nav aria-label="Form sections" className="sticky top-14 z-10 -mx-1 mb-4 hidden bg-bg/95 px-1 py-2 backdrop-blur-sm lg:block">
            <div className="flex flex-wrap gap-1">
              {SECTIONS.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => document.getElementById(s.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
                  className="rounded-full border border-border bg-surface px-2.5 py-1 text-[12px] font-medium text-fg-muted transition-colors hover:border-border-strong hover:text-fg"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </nav>

          <fieldset disabled={readOnly} className="min-w-0 space-y-5">
            <FormSection id="branding" title="Branding" icon={Palette} description="Name, logo and colors of the page.">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Template name" required error={errors.name} hint={!errors.name ? 'Shown in the console only.' : undefined}>
                  <Input value={draft.name} maxLength={LIMITS.name + 20} onChange={(e) => set('name', e.target.value)} placeholder="e.g. PCI zone" autoFocus={isNew} />
                </Field>
                <Field label="Company name" error={errors.company_name} hint="Header of the page and the {company} variable.">
                  <Input value={draft.company_name} onChange={(e) => set('company_name', e.target.value)} placeholder="Enterprise Corp" />
                </Field>
              </div>
              <LogoField value={draft.logo_data_url || ''} onChange={(v) => set('logo_data_url', v)} disabled={readOnly} />
              <div className="grid gap-4 sm:grid-cols-2">
                <ColorField label="Primary color" hint="Buttons, links and the header accent." value={draft.primary_color} onChange={(v) => set('primary_color', v)} error={errors.primary_color} disabled={readOnly} presets={PRIMARY_PRESETS} />
                <ColorField label="Accent color" hint="The blocked badge and warnings." value={draft.accent_color} onChange={(v) => set('accent_color', v)} error={errors.accent_color} disabled={readOnly} presets={ACCENT_PRESETS} />
              </div>
              <Field label="Theme" hint={draft.theme === 'auto' ? 'Follows the light or dark preference of the visitor’s browser.' : `Always ${draft.theme}.`}>
                {() => (
                  <SegmentedControl
                    aria-label="Theme"
                    value={draft.theme}
                    onChange={(v) => set('theme', v)}
                    options={[
                      { value: 'auto', label: 'Auto', disabled: readOnly },
                      { value: 'light', label: 'Light', disabled: readOnly },
                      { value: 'dark', label: 'Dark', disabled: readOnly },
                    ]}
                  />
                )}
              </Field>
              <div className="rounded-md border border-border bg-surface-2 px-3 py-2.5">
                <Switch
                  checked={draft.is_default}
                  onChange={(v) => set('is_default', v)}
                  disabled={readOnly || baseline.is_default}
                  label="Default template"
                  description={
                    baseline.is_default
                      ? 'Servers in groups without a template see this page. To change the default, make another template the default.'
                      : 'Use this page for every server whose groups have no template assigned.'
                  }
                />
              </div>
            </FormSection>

            <FormSection id="texts" title="Texts" icon={TextCursorInput} description="Blank lines create paragraphs. Empty fields use the built-in English or German text (shown as placeholder).">
              {!readOnly && <VariableToolbar targets={texts} labels={textLabels} />}
              <Field label="Title" labelAside={<Counter value={draft.title} max={LIMITS.title} />} error={errors.title}>
                <Input
                  {...texts.bind('title')}
                  value={draft.title}
                  onChange={(e) => set('title', e.target.value)}
                  onFocus={() => {
                    texts.bind('title').onFocus();
                    focusPreview({ mode: 'browser', variant: 'request' });
                  }}
                  placeholder={builtin.title}
                />
              </Field>
              <Field label="Message" labelAside={<Counter value={draft.message} max={LIMITS.message} />} error={errors.message} hint="Shown for policy blocks (no rule allows the destination).">
                <Textarea
                  {...texts.bind('message')}
                  rows={4}
                  value={draft.message}
                  onChange={(e) => set('message', e.target.value)}
                  onFocus={() => {
                    texts.bind('message').onFocus();
                    focusPreview({ mode: 'browser', variant: 'request' });
                  }}
                  placeholder={builtin.message}
                />
              </Field>
              <Field label="Threat message" labelAside={<Counter value={draft.threat_message} max={LIMITS.threat_message} />} error={errors.threat_message} hint="Shown when threat protection or quarantine blocked the request. There is no request form on this variant.">
                <Textarea
                  {...texts.bind('threat_message')}
                  rows={4}
                  value={draft.threat_message}
                  onChange={(e) => set('threat_message', e.target.value)}
                  onFocus={() => {
                    texts.bind('threat_message').onFocus();
                    focusPreview({ mode: 'browser', variant: 'threat' });
                  }}
                  placeholder={builtin.threat_message}
                />
              </Field>
              <Field label="Footer" labelAside={<Counter value={draft.footer_text} max={LIMITS.footer_text} />} error={errors.footer_text}>
                <Textarea
                  {...texts.bind('footer_text')}
                  rows={2}
                  value={draft.footer_text}
                  onChange={(e) => set('footer_text', e.target.value)}
                  onFocus={() => {
                    texts.bind('footer_text').onFocus();
                    focusPreview({ mode: 'browser' });
                  }}
                  placeholder="e.g. {company} Information Security · Outbound access is logged and reviewed."
                />
              </Field>
            </FormSection>

            <FormSection id="help" title="Help" icon={HelpCircle} description="Where people get help. Leave everything empty to hide the help section.">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Heading" hint="Defaults to “Need help?”.">
                  <Input value={draft.support.label} onChange={(e) => setSupport('label', e.target.value)} placeholder="IT Service Desk" />
                </Field>
                <Field label="E-mail" error={errors['support.email']}>
                  <Input type="email" value={draft.support.email} onChange={(e) => setSupport('email', e.target.value)} placeholder="servicedesk@corp.example" />
                </Field>
                <Field label="Phone" error={errors['support.phone']}>
                  <Input type="tel" value={draft.support.phone} onChange={(e) => setSupport('phone', e.target.value)} placeholder="+49 30 1234 5678" />
                </Field>
                <Field label="Support URL" error={errors['support.url']}>
                  <Input type="url" mono value={draft.support.url} onChange={(e) => setSupport('url', e.target.value)} placeholder="https://servicedesk.corp.example" />
                </Field>
              </div>
              <LinksEditor value={draft.links ?? []} onChange={(v) => set('links', v)} errors={errors} disabled={readOnly} />
            </FormSection>

            <FormSection id="self-service" title="Self-service" icon={UserCheck} description="Let people request access directly from the block page.">
              <Switch
                checked={draft.show_request_form}
                onChange={(v) => {
                  set('show_request_form', v);
                  focusPreview({ mode: 'browser', variant: 'request' });
                }}
                disabled={readOnly}
                label="Show the request form"
                description="Requests go to the access request queue with the server identity attested by the proxy. Threat blocks never offer the form."
              />
              <ChoiceGroup
                label="Scopes people can request"
                hint="Also enforced by the request API for every server that uses this template (portal and terminal)."
                options={SCOPES}
                value={draft.allowed_scopes ?? []}
                onChange={(v) => set('allowed_scopes', v)}
                error={errors.allowed_scopes}
                disabled={readOnly}
              />
              <ChoiceGroup
                label="Durations people can request"
                hint={`Reviewers decide what they grant; Team Leads can grant at most ${state.governance?.max_temporary_access_days ?? 30} days.`}
                options={DURATIONS}
                value={draft.allowed_durations ?? []}
                onChange={(v) => set('allowed_durations', v)}
                error={errors.allowed_durations}
                disabled={readOnly}
                columns={2}
              />
            </FormSection>

            <FormSection id="sections" title="Sections" icon={LayoutList} description="Optional blocks on the page.">
              <div className="divide-y divide-border rounded-md border border-border">
                <div className="px-3 py-3">
                  <Switch
                    checked={draft.show_technical_details}
                    onChange={(v) => set('show_technical_details', v)}
                    disabled={readOnly}
                    label="Technical details"
                    description="Server, groups, blocked URL and trace ID — what support needs to help."
                  />
                </div>
                <div className="px-3 py-3">
                  <Switch
                    checked={draft.show_suggested_rule}
                    onChange={(v) => set('show_suggested_rule', v)}
                    disabled={readOnly || !draft.show_technical_details}
                    label="Suggested rule"
                    description={draft.show_technical_details ? 'The pattern a reviewer would allow, e.g. downloads.example.org/tools/**. Policy blocks only.' : 'Part of the technical details — turn them on first.'}
                  />
                </div>
                <div className="px-3 py-3">
                  <Switch
                    checked={draft.show_ca_section}
                    onChange={(v) => set('show_ca_section', v)}
                    disabled={readOnly}
                    label="Root CA installation"
                    description="Download links and one-line installers for the enterprise root CA, so TLS inspection does not break tools."
                  />
                </div>
              </div>
            </FormSection>

            <FormSection id="terminal" title="Terminal (CLI)" icon={SquareTerminal} description="Text printed to curl, apt, pip and other command-line clients, before and after the standard block message.">
              {!readOnly && <VariableToolbar targets={cliTexts} labels={cliLabels} />}
              <Field label="Header" labelAside={<Counter value={draft.cli_header} max={LIMITS.cli_header} />} error={errors.cli_header}>
                <Textarea
                  {...cliTexts.bind('cli_header')}
                  mono
                  rows={3}
                  value={draft.cli_header}
                  onChange={(e) => set('cli_header', e.target.value)}
                  onFocus={() => {
                    cliTexts.bind('cli_header').onFocus();
                    focusPreview({ mode: 'terminal' });
                  }}
                  placeholder="e.g. {company} egress gateway — outbound access from {hostname} is restricted."
                />
              </Field>
              <Field label="Footer" labelAside={<Counter value={draft.cli_footer} max={LIMITS.cli_footer} />} error={errors.cli_footer}>
                <Textarea
                  {...cliTexts.bind('cli_footer')}
                  mono
                  rows={3}
                  value={draft.cli_footer}
                  onChange={(e) => set('cli_footer', e.target.value)}
                  onFocus={() => {
                    cliTexts.bind('cli_footer').onFocus();
                    focusPreview({ mode: 'terminal' });
                  }}
                  placeholder="e.g. Questions? servicedesk@corp.example · quote trace ID {trace_id}"
                />
              </Field>
            </FormSection>

            <FormSection id="language" title="Language" icon={Languages} description="The browser’s language picks English or German when available.">
              <Field label="Default language" hint="Used when the browser prefers neither English nor German, and for terminal clients.">
                {() => (
                  <SegmentedControl
                    aria-label="Default language"
                    value={(draft.default_locale as Locale) || 'en'}
                    onChange={(v) => {
                      set('default_locale', v);
                      focusPreview({ locale: v });
                    }}
                    options={[
                      { value: 'en', label: 'English', disabled: readOnly },
                      { value: 'de', label: 'Deutsch', disabled: readOnly },
                    ]}
                  />
                )}
              </Field>
              <p className="text-[12.5px] leading-5 text-fg-muted">
                Your texts are shown in every language as written. Built-in texts (used for empty fields, labels and the form) are translated automatically.
              </p>
            </FormSection>

            <FormSection id="assignment" title="Assignment" icon={Users} description="Server groups that show this page. A server uses the template of its first group that has one.">
              {readOnly ? (
                selGroups.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {selGroups.map((g) => (
                      <GroupChip key={g} id={g} />
                    ))}
                  </div>
                ) : (
                  <p className="text-[13px] text-fg-muted">{draft.is_default ? 'Used by every group without a template.' : 'Not assigned to any group.'}</p>
                )
              ) : (
                <Field label="Groups" hint={draft.is_default ? 'As the default, this page is also used by every group without a template.' : 'Removing a group makes it fall back to the default template.'}>
                  <MultiSelect value={selGroups} onChange={setSelGroups} options={groupOptions} placeholder="No groups assigned" searchPlaceholder="Search groups…" />
                </Field>
              )}
              {reassigned.length > 0 && (
                <Callout tone="warning" title="Moves groups from another template">
                  {reassigned.map((g) => groups.find((x) => x.id === g)?.name || g).join(', ')} will use this template after saving.
                </Callout>
              )}
              {selGroups.length > 0 && (
                <p className="text-[12.5px] text-fg-muted">
                  {pluralize(serversAffected, 'registered server')} in {pluralize(selGroups.length, 'group')} will see this page.
                </p>
              )}
            </FormSection>
          </fieldset>

          {!readOnly && dirty && (
            <div className="sticky bottom-3 z-20 mt-5 flex flex-wrap items-center gap-3 rounded-lg border border-border-strong bg-surface px-4 py-2.5 shadow-pop animate-toast-in">
              <span className="text-[13px] font-medium text-fg">Unsaved changes</span>
              <span className="hidden text-[12px] text-fg-subtle sm:inline">Ctrl S to save</span>
              <div className="ml-auto flex gap-2">
                <Button size="sm" variant="ghost" onClick={discard} disabled={saving}>
                  Discard
                </Button>
                <Button size="sm" variant="primary" icon={Save} onClick={save} loading={saving}>
                  {isNew ? 'Create template' : 'Save'}
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* ------------------------------------------------------------- preview */}
        <div className={cn('min-w-0', mobileTab === 'edit' && 'hidden lg:block')}>
          <div className="h-[calc(100dvh-180px)] min-h-[560px] lg:sticky lg:top-[72px] lg:h-[calc(100vh-96px)]">
            <PreviewPane className="h-full" preview={preview} view={view} onViewChange={setView} savedId={template?.id} dirty={dirty} />
          </div>
        </div>
      </div>
    </>
  );
};
