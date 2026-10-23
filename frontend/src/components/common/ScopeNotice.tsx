import React from 'react';
import { Eye } from 'lucide-react';
import { usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { Callout } from '../../ui';

/**
 * Team Leads receive only the records of their groups (need-to-know): requests, flows, learning
 * sessions, security events and audit events. Shown on pages whose lists would otherwise look complete.
 */
export const TeamLeadScopeNotice: React.FC<{ what: string; className?: string }> = ({ what, className }) => {
  const perms = usePermissions();
  const { groupName } = useLookups();
  if (!perms.isTeamLead) return null;
  const groups = (perms.user?.allowed_groups ?? []).filter((g) => g !== '*');
  if ((perms.user?.allowed_groups ?? []).includes('*')) return null;
  return (
    <Callout tone="neutral" icon={Eye} className={className}>
      You see {what} of your groups only{groups.length ? ` (${groups.map(groupName).join(', ')})` : ''}. InfoSec sees the whole fleet.
    </Callout>
  );
};
