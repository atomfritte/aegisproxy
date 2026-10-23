import React, { useState } from 'react';
import { Inbox, Layers } from 'lucide-react';
import type { PolicyRule, PolicySet } from '../../../types';
import { ButtonLink, Callout, EmptyState } from '../../../ui';
import { RuleDetailDrawer } from '../../../components/policy/RuleDetailDrawer';
import { RulesTable } from '../../../components/policy/RulesTable';

/** Published (enforced) rules of a set. */
export const RulesTab: React.FC<{ set: PolicySet; canManage: boolean }> = ({ set, canManage }) => {
  const [open, setOpen] = useState<PolicyRule | null>(null);
  const rules = set.rules ?? [];
  return (
    <div className="space-y-4">
      {set.kind === 'approvals' && (
        <Callout tone="info" icon={Inbox} title="Managed by the access request workflow">
          Every approved access request for this group adds a rule here and publishes it immediately. To remove access, revoke the request on its page; to extend it, use Extend on the request.
        </Callout>
      )}
      {set.version === 0 ? (
        <EmptyState
          icon={Layers}
          title="Not published yet"
          description="This set has no enforced rules. Review the draft and publish it."
          action={canManage && <ButtonLink to={`/policies/${encodeURIComponent(set.id)}/draft`} variant="primary">Open draft</ButtonLink>}
        />
      ) : (
        <RulesTable
          rows={rules.map((r) => ({ key: r.id, rule: r }))}
          onOpen={(row) => setOpen(row.rule as PolicyRule)}
          empty={<EmptyState title="The published version has no rules" size="sm" />}
        />
      )}
      <RuleDetailDrawer rule={open} onClose={() => setOpen(null)} />
    </div>
  );
};
