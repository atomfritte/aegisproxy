import React, { useEffect, useState } from 'react';
import { Boxes, Tag } from 'lucide-react';
import { api, errorMessage } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { pluralize } from '../../lib/format';
import type { Server } from '../../types';
import { Button, Field, Input, Modal, MultiSelect, useToast } from '../../ui';
import { validateLabelKey } from './fleetUtils';

/** Full record for POST /api/servers (the API replaces the whole server). */
export function serverBody(s: Server, patch: Partial<Server>): Partial<Server> & { id: string; hostname: string } {
  const { effective_group_ids: _eff, ...rest } = s;
  return { ...rest, ...patch, id: s.id, hostname: s.hostname };
}

/** Applies `fn` to every server sequentially; returns failures as "hostname: message". */
export async function forEachServer(servers: Server[], fn: (s: Server) => Promise<unknown>): Promise<string[]> {
  const failures: string[] = [];
  for (const s of servers) {
    try {
      await fn(s);
    } catch (err) {
      failures.push(`${s.hostname}: ${errorMessage(err)}`);
    }
  }
  return failures;
}

function useBulkRunner() {
  const { refresh } = useConsole();
  const toast = useToast();
  return async (servers: Server[], fn: (s: Server) => Promise<unknown>, verb: string) => {
    const failures = await forEachServer(servers, fn);
    await refresh();
    const ok = servers.length - failures.length;
    if (failures.length === 0) toast.success(`${verb} ${pluralize(ok, 'server')}`);
    else
      toast.error(failures.slice(0, 3).join('; ') + (failures.length > 3 ? `; +${failures.length - 3} more` : ''), {
        title: `${verb} ${ok} of ${servers.length} servers`,
      });
    return failures.length === 0;
  };
}

/** Bulk "set label" (merged into each server's labels). */
export const BulkLabelDialog: React.FC<{ open: boolean; onClose: () => void; servers: Server[]; onDone: () => void }> = ({ open, onClose, servers, onDone }) => {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const runBulk = useBulkRunner();
  useEffect(() => {
    if (open) {
      setKey('');
      setValue('');
    }
  }, [open]);
  const keyErr = key.trim() ? validateLabelKey(key.trim().toLowerCase()) : null;
  const can = !!key.trim() && !keyErr && !busy;
  const submit = async () => {
    if (!can) return;
    setBusy(true);
    const k = key.trim().toLowerCase();
    const ok = await runBulk(servers, (s) => api.servers.upsert(serverBody(s, { labels: { ...(s.labels ?? {}), [k]: value.trim() } })), 'Labeled');
    setBusy(false);
    if (ok) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="sm"
      title={`Set a label on ${pluralize(servers.length, 'server')}`}
      description="Adds the label or overwrites its value. Dynamic group memberships update immediately."
      icon={
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent">
          <Tag className="h-4 w-4" />
        </span>
      }
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={!can} loading={busy}>
            Set label
          </Button>
        </>
      }
    >
      <form
        className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Key" error={keyErr}>
          <Input value={key} onChange={(e) => setKey(e.target.value)} mono placeholder="compliance" data-autofocus />
        </Field>
        <span className="mt-8 text-fg-subtle">=</span>
        <Field label="Value">
          <Input value={value} onChange={(e) => setValue(e.target.value)} mono placeholder="pci" />
        </Field>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
};

/** Bulk "add to static groups". */
export const BulkGroupDialog: React.FC<{ open: boolean; onClose: () => void; servers: Server[]; onDone: () => void }> = ({ open, onClose, servers, onDone }) => {
  const state = useConsoleState();
  const [groups, setGroups] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const runBulk = useBulkRunner();
  useEffect(() => {
    if (open) setGroups([]);
  }, [open]);
  const submit = async () => {
    if (groups.length === 0) return;
    setBusy(true);
    const ok = await runBulk(
      servers,
      (s) => api.servers.upsert(serverBody(s, { group_ids: [...new Set([...(s.group_ids ?? []), ...groups])] })),
      'Updated'
    );
    setBusy(false);
    if (ok) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="sm"
      title={`Add ${pluralize(servers.length, 'server')} to groups`}
      description="Adds static memberships; existing memberships are kept."
      icon={
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent">
          <Boxes className="h-4 w-4" />
        </span>
      }
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={groups.length === 0 || busy} loading={busy}>
            Add to groups
          </Button>
        </>
      }
    >
      <Field label="Groups">
        <MultiSelect value={groups} onChange={setGroups} options={state.groups.map((g) => ({ value: g.id, label: g.name, description: g.id, color: g.color }))} placeholder="Choose groups" />
      </Field>
    </Modal>
  );
};
