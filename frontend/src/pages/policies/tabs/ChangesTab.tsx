import React from 'react';
import { GitCompare } from 'lucide-react';
import type { PolicyDiff, PolicySet } from '../../../types';
import { ButtonLink, Callout, EmptyState } from '../../../ui';
import { PolicyDiffView } from '../../../components/policy/PolicyDiffView';

/** Saved draft vs published version (draft_diff from GET /policy-sets/{id}). */
export const ChangesTab: React.FC<{ set: PolicySet; diff: PolicyDiff | null; canManage: boolean; unsaved: boolean }> = ({ set, diff, canManage, unsaved }) => {
  if (!set.draft) {
    return (
      <EmptyState
        icon={GitCompare}
        title="No pending changes"
        description="There is no draft, so the set is exactly what is enforced. Edits you save in the draft show up here."
        action={canManage && set.kind !== 'approvals' && <ButtonLink to={`/policies/${encodeURIComponent(set.id)}/draft`}>Edit draft</ButtonLink>}
      />
    );
  }
  return (
    <div className="space-y-4">
      {unsaved && <Callout tone="warning">You have unsaved edits in the draft tab. This comparison shows the saved draft.</Callout>}
      <p className="text-[13px] text-fg-muted">
        Saved draft compared with the published version {set.version ? `v${set.version}` : '(nothing published yet)'}.
      </p>
      <PolicyDiffView diff={diff} from={set} to={set.draft.spec} emptyTitle="The draft matches the published version" />
    </div>
  );
};
