import { useCallback, useEffect, useMemo, useRef } from 'react';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import type { SecurityEvent } from '../../../types';

/** Normalized threat-protection slice of /api/state plus role helpers. */
export function useThreatData() {
  const state = useConsoleState();
  const perms = usePermissions();
  const sec = state.security;
  return useMemo(() => {
    const events = [...(sec?.events ?? [])].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const ti = sec?.threat_intel;
    const planes = state.data_planes ?? [];
    return {
      policy: sec?.policy ?? null,
      feeds: sec?.feeds ?? [],
      indicators: sec?.indicators ?? [],
      exceptions: sec?.exceptions ?? [],
      events,
      openEvents: events.filter((e) => !e.acknowledged),
      ti,
      tiEntries: ti ? ti.domains + ti.urls + ti.ips + ti.cidrs + ti.hashes : 0,
      dlpDetectors: sec?.dlp_detectors ?? [],
      fileTypes: sec?.file_types ?? [],
      planes,
      stats: state.stats,
      canManage: perms.canManageSystem,
      /** InfoSec / Super Admin: every event; Team Leads: events of their groups. */
      canAck: (e: SecurityEvent) => !e.acknowledged && perms.canApproveFor(e.group_ids ?? []),
    };
  }, [sec, state.data_planes, state.stats, perms]);
}

/** Refreshes the console state once more after a delay (feed downloads run in the background). */
export function useDelayedRefresh(ms = 5000) {
  const { refresh } = useConsole();
  const t = useRef<number>();
  useEffect(() => () => window.clearTimeout(t.current), []);
  return useCallback(() => {
    window.clearTimeout(t.current);
    t.current = window.setTimeout(() => void refresh(), ms);
  }, [refresh, ms]);
}
