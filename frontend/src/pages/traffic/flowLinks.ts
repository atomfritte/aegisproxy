import type { TrafficFlow } from '../../types';

/** Builds the "new policy set" URL prefilled with a rule derived from a recorded flow. */
export function newSetFromFlowUrl(flow: Pick<TrafficFlow, 'host' | 'path' | 'group_ids' | 'server_id'>): string {
  const first = (flow.path || '/').split('/').filter(Boolean)[0];
  const params = new URLSearchParams({
    host: flow.host,
    path: first ? `/${first}/**` : '/**',
    name: `${flow.host}${first ? `/${first}` : ''}`,
  });
  for (const g of flow.group_ids ?? []) params.append('group', g);
  if (flow.server_id) params.append('server', flow.server_id);
  return `/policies/new?${params.toString()}`;
}
