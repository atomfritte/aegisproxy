import React from 'react';
import { Compass } from 'lucide-react';
import { useDocumentTitle } from '../../lib/hooks';
import { useLocation } from '../../lib/router';
import { ButtonLink, EmptyState } from '../../ui';

/** 404 for unknown console paths. */
export const NotFoundPage: React.FC<{ title?: string; description?: React.ReactNode; backTo?: string; backLabel?: string }> = ({
  title = 'Page not found',
  description,
  backTo = '/',
  backLabel = 'Go to overview',
}) => {
  useDocumentTitle(title);
  const { pathname } = useLocation();
  return (
    <EmptyState
      icon={Compass}
      title={title}
      description={description ?? <>Nothing lives at <span className="font-mono text-[12.5px]">{pathname}</span>. Check the address or use the search (Ctrl K).</>}
      action={
        <ButtonLink to={backTo} variant="primary">
          {backLabel}
        </ButtonLink>
      }
      className="py-24"
    />
  );
};
