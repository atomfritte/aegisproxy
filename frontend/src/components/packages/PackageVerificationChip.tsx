import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { BadgeCheck, FileSignature, ShieldQuestion, ShieldX } from 'lucide-react';
import { Badge, Tooltip } from '../../ui';
import { VERIFICATION_META } from './packageUtils';
import type { PackageVerification } from '../../types';

const ICON: Record<string, LucideIcon> = {
  verified: BadgeCheck,
  unsigned: FileSignature,
  failed: ShieldX,
  unchecked: ShieldQuestion,
};

/** Signature / provenance verification outcome as a chip, with the verified identity in a tooltip. */
export const PackageVerificationChip: React.FC<{ label: string; verification?: PackageVerification | null; className?: string }> = ({ label, verification, className }) => {
  const status = verification?.status ?? 'unchecked';
  const m = VERIFICATION_META[status] ?? VERIFICATION_META.unchecked;
  const Icon = ICON[status] ?? ShieldQuestion;
  const identity = verification?.identity || verification?.source_repo || verification?.key_id;
  const tip = (
    <span className="block max-w-[300px]">
      <span className="font-medium">
        {label}: {m.label}
      </span>
      {verification?.kind && <span className="mt-0.5 block text-fg-muted">{verification.kind}</span>}
      {identity && <span className="mt-0.5 block break-all font-mono text-[11.5px]">{identity}</span>}
      {verification?.detail && <span className="mt-0.5 block text-fg-muted">{verification.detail}</span>}
    </span>
  );
  return (
    <Tooltip content={tip}>
      <Badge tone={m.tone} icon={Icon} className={className}>
        {label}: {m.label}
      </Badge>
    </Tooltip>
  );
};
