import React, { useEffect, useMemo, useState } from 'react';
import { Eye, Radar, Unlock } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import type { LearningSession } from '../../types';
import { Button, Callout, Combobox, Drawer, Field, Input, RadioCards, Select, Textarea } from '../../ui';
import { canStartOn, DURATIONS, MODE_META } from './sessionUtils';

/** Start a learning session on a reference server. */
export const StartSessionDrawer: React.FC<{ open: boolean; onClose: () => void; onStarted: (s: LearningSession) => void; serverId?: string }> = ({ open, onClose, onStarted, serverId }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  const { groupName } = useLookups();
  const { run, pending } = useAction();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [server, setServer] = useState('');
  const [minutes, setMinutes] = useState(15);
  const [mode, setMode] = useState<LearningSession['mode']>('record_and_allow');
  const [tried, setTried] = useState(false);

  useEffect(() => {
    if (open) {
      setName('');
      setDescription('');
      setServer(serverId ?? '');
      setMinutes(15);
      setMode('record_and_allow');
      setTried(false);
    }
  }, [open, serverId]);

  const srv = state.servers.find((s) => s.id === server);
  const strict = !!srv && (srv.group_ids ?? []).some((g) => state.groups.find((x) => x.id === g)?.strict_isolation);
  useEffect(() => {
    if (strict && mode === 'record_and_allow') setMode('record_only');
  }, [strict, mode]);

  const options = useMemo(
    () =>
      [...state.servers]
        .sort((a, b) => Number(canStartOn(perms, b)) - Number(canStartOn(perms, a)) || a.hostname.localeCompare(b.hostname))
        .map((s) => ({
          value: s.id,
          label: s.hostname,
          description: canStartOn(perms, s) ? `${s.ip || s.id} · ${(s.group_ids ?? []).map(groupName).join(', ') || 'no static group'}` : 'Outside your groups',
          disabled: !canStartOn(perms, s),
        })),
    [state.servers, perms, groupName]
  );

  const errors = { name: !name.trim() ? 'Give the session a name.' : null, server: !server ? 'Choose the reference server.' : null };
  const submit = async () => {
    setTried(true);
    if (errors.name || errors.server) return;
    const s = await run(() => api.sessions.start({ name: name.trim(), description: description.trim(), server_id: server, duration_minutes: minutes, mode }), {
      key: 'start',
      success: (x) => `Recording ${x.server_hostname} for ${minutes} minutes`,
      errorTitle: 'The session was not started',
    });
    if (s) {
      onStarted(s);
      onClose();
    }
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'start'}
      width="md"
      title="Start a learning session"
      description="Run the workload on a reference server while the proxy records its traffic. The recorded requests are compiled into rule candidates."
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'start'}>
            Cancel
          </Button>
          <Button variant="primary" icon={Radar} onClick={submit} loading={pending === 'start'}>
            Start recording
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Name" required error={tried ? errors.name : null}>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Build agent: Terraform + provider downloads" data-autofocus />
        </Field>
        <Field label="Reference server" required error={tried ? errors.server : null} hint="Team Leads can record servers of their own groups.">
          {({ id }) => <Combobox id={id} value={server} onChange={setServer} options={options} placeholder="Choose a server" searchPlaceholder="Search servers…" />}
        </Field>
        <Field label="Duration">
          <Select value={String(minutes)} onChange={(e) => setMinutes(Number(e.target.value))} options={DURATIONS.map((m) => ({ value: String(m), label: m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? 's' : ''}` }))} />
        </Field>
        <Field label="Mode">
          {() => (
            <RadioCards<LearningSession['mode']>
              aria-label="Mode"
              value={mode}
              onChange={setMode}
              options={[
                {
                  value: 'record_and_allow',
                  title: MODE_META.record_and_allow.label,
                  description: MODE_META.record_and_allow.description,
                  icon: Unlock,
                  disabled: strict,
                  disabledReason: 'Not permitted for strict-isolation (zero-internet) groups.',
                },
                { value: 'record_only', title: MODE_META.record_only.label, description: MODE_META.record_only.description, icon: Eye },
              ]}
            />
          )}
        </Field>
        <Field label="Description" optional>
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="What will run during the session, ticket number" />
        </Field>
        {mode === 'record_and_allow' && (
          <Callout tone="warning" title="The server can reach the internet while recording">
            Keep the session short and run only the intended workload. Stop it as soon as the workload is done.
          </Callout>
        )}
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};
