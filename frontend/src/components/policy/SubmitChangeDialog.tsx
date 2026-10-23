import React, { useEffect, useState } from 'react';
import { GitPullRequestArrow } from 'lucide-react';
import type { PolicyDiff } from '../../types';
import { Button, Field, Input, Modal, Textarea } from '../../ui';

function summarize(diff: PolicyDiff | null | undefined): string {
  if (!diff) return '';
  const parts: string[] = [];
  if (diff.added) parts.push(`+${diff.added} rule${diff.added === 1 ? '' : 's'}`);
  if (diff.removed) parts.push(`-${diff.removed} rule${diff.removed === 1 ? '' : 's'}`);
  if (diff.modified) parts.push(`${diff.modified} changed`);
  if ((diff.metadata ?? []).length) parts.push('settings');
  return parts.join(', ');
}

/** Title + description for POST /policy-sets/{id}/submit. */
export const SubmitChangeDialog: React.FC<{
  open: boolean;
  onClose: () => void;
  setName: string;
  diff?: PolicyDiff | null;
  onSubmit: (title: string, description: string) => Promise<boolean>;
}> = ({ open, onClose, setName, diff, onSubmit }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) {
      const s = summarize(diff);
      setTitle(s ? `${setName}: ${s}` : setName);
      setDescription('');
    }
  }, [open, diff, setName]);
  const submit = async () => {
    setBusy(true);
    const ok = await onSubmit(title.trim(), description.trim());
    setBusy(false);
    if (ok) onClose();
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      title="Submit for review"
      description="Four-eyes review is required. The draft is locked until a second approver decides; the request includes the diff and an impact simulation."
      icon={
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent">
          <GitPullRequestArrow className="h-4 w-4" />
        </span>
      }
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={!title.trim()}>
            Submit for review
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Title" required>
          <Input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} data-autofocus />
        </Field>
        <Field label="Description" optional hint="Why the change is needed, ticket numbers, who asked for it.">
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} maxLength={4000} />
        </Field>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
};
