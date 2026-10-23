import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { passwordPolicyError } from '../utils';
import { Button, Callout, Field, Input, Modal, useToast } from '../ui';

/** Change the signed-in user's password (local accounts). */
export const ChangePasswordDialog: React.FC<{ open: boolean; onClose: () => void; authProvider?: string }> = ({ open, onClose, authProvider }) => {
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (open) {
      setCurrent('');
      setNext('');
      setConfirm('');
      setTouched(false);
    }
  }, [open]);

  const policyErr = next ? passwordPolicyError(next) : null;
  const mismatch = confirm && next !== confirm ? 'The passwords do not match.' : null;
  const can = current && next && confirm && !policyErr && !mismatch && !busy;
  const external = authProvider && authProvider !== 'local';

  const submit = async () => {
    setTouched(true);
    if (!can) return;
    setBusy(true);
    try {
      await api.auth.changePassword(current, next);
      toast.success('Password changed', { description: 'Other sessions of your account were signed out.' });
      onClose();
    } catch (err) {
      toast.error(err, { title: 'Password not changed' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      title="Change password"
      description="Use at least 12 characters with three of: lowercase, uppercase, digits, symbols."
      size="sm"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={!!external}>
            Change password
          </Button>
        </>
      }
    >
      {external ? (
        <Callout tone="info">Your account signs in through {authProvider}. Change the password with your identity provider.</Callout>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <Field label="Current password" required>
            <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} data-autofocus />
          </Field>
          <Field label="New password" required error={touched || next.length >= 12 ? policyErr : null}>
            <Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          </Field>
          <Field label="Confirm new password" required error={mismatch}>
            <Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </Field>
          <button type="submit" hidden />
        </form>
      )}
    </Modal>
  );
};
