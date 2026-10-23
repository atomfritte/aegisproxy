import { useMemo } from 'react';
import type { PolicySet, Server, ServerGroup, User } from '../types';
import { useConsole } from './AppData';

export interface Lookups {
  groups: ServerGroup[];
  servers: Server[];
  users: User[];
  groupById: Map<string, ServerGroup>;
  serverById: Map<string, Server>;
  userByName: Map<string, User>;
  setById: Map<string, PolicySet>;
  groupName: (id: string) => string;
  serverName: (id: string) => string;
  /** Display name for a username (falls back to the username). */
  userName: (username: string) => string;
}

/** Id → entity maps built from /api/state (memoized). */
export function useLookups(): Lookups {
  const { state } = useConsole();
  return useMemo(() => {
    const groups = state?.groups ?? [];
    const servers = state?.servers ?? [];
    const users = state?.users ?? [];
    const groupById = new Map(groups.map((g) => [g.id, g]));
    const serverById = new Map(servers.map((s) => [s.id, s]));
    const userByName = new Map(users.map((u) => [u.username.toLowerCase(), u]));
    const setById = new Map((state?.policy_sets ?? []).map((s) => [s.id, s]));
    return {
      groups,
      servers,
      users,
      groupById,
      serverById,
      userByName,
      setById,
      groupName: (id) => (id === '*' ? 'All groups' : groupById.get(id)?.name ?? id),
      serverName: (id) => (id === '*' ? 'All servers' : serverById.get(id)?.hostname ?? id),
      userName: (u) => userByName.get((u || '').toLowerCase())?.display_name || u,
    };
  }, [state]);
}
