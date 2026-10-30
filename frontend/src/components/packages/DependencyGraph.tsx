import React, { useEffect, useMemo, useState } from 'react';
import { ChevronRight, FileWarning, Repeat2, ShieldAlert, TerminalSquare } from 'lucide-react';
import { cn } from '../../lib/cn';
import { RelativeTime } from '../../ui/Time';
import { Badge, Callout, SegmentedControl } from '../../ui';
import type { PackageNode } from '../../types';
import { EcosystemBadge, KindBadge } from './EcosystemBadge';
import { AdvisorySummary, NodeStateChip, RiskBadge } from './RiskBadge';
import {
  activeAdvisoryTotal,
  ageHours,
  hasMalware,
  humanHours,
  isHotRisk,
  nameVersion,
  nodeStateMeta,
  riskRank,
  syscallTotal,
} from './packageUtils';

// --- graph model ------------------------------------------------------------

function nodeHotRank(n?: PackageNode | null): number {
  if (!n) return 0;
  let r = riskRank(n.assessment?.risk);
  if (hasMalware(n.assessment)) r = Math.max(r, 5);
  if (n.state === 'blocked') r = Math.max(r, 4);
  return r;
}

interface GraphModel {
  byKey: Map<string, PackageNode>;
  roots: PackageNode[];
  childrenOf: Map<string, string[]>;
  subtreeRank: Map<string, number>;
}

function buildGraph(nodes: PackageNode[], rootKey?: string): GraphModel {
  const byKey = new Map<string, PackageNode>();
  for (const n of nodes) byKey.set(n.key, n);
  const childrenOf = new Map<string, string[]>();
  const hasParent = new Set<string>();
  for (const n of nodes) {
    for (const e of n.required_by ?? []) {
      if (!e.parent) continue; // root edge
      hasParent.add(n.key);
      const arr = childrenOf.get(e.parent) ?? [];
      if (!arr.includes(n.key)) arr.push(n.key);
      childrenOf.set(e.parent, arr);
    }
  }
  let roots = nodes.filter((n) => n.root);
  if (roots.length === 0 && rootKey && byKey.has(rootKey)) roots = [byKey.get(rootKey)!];
  if (roots.length === 0) roots = nodes.filter((n) => !hasParent.has(n.key));
  if (roots.length === 0 && nodes.length > 0) roots = [nodes[0]];

  // Subtree max risk rank (own + descendants), cycle-guarded.
  const subtreeRank = new Map<string, number>();
  const compute = (key: string, stack: Set<string>): number => {
    if (subtreeRank.has(key)) return subtreeRank.get(key)!;
    const n = byKey.get(key);
    let r = nodeHotRank(n);
    if (!stack.has(key)) {
      stack.add(key);
      for (const c of childrenOf.get(key) ?? []) r = Math.max(r, compute(c, stack));
      stack.delete(key);
      subtreeRank.set(key, r);
    }
    return r;
  };
  for (const n of nodes) compute(n.key, new Set());
  return { byKey, roots, childrenOf, subtreeRank };
}

/** Auto-expand the roots and every path that leads to a high-risk node. */
function autoExpanded(g: GraphModel): Set<string> {
  const open = new Set<string>();
  const walk = (node: PackageNode, path: string, ancestors: Set<string>) => {
    const pathKey = path ? `${path}>${node.key}` : node.key;
    const kids = (g.childrenOf.get(node.key) ?? []).map((k) => g.byKey.get(k)).filter(Boolean) as PackageNode[];
    const hotChild = kids.some((k) => (g.subtreeRank.get(k.key) ?? 0) >= 4);
    if (hotChild) open.add(pathKey);
    if (ancestors.has(node.key)) return;
    const next = new Set(ancestors).add(node.key);
    for (const k of kids) walk(k, pathKey, next);
  };
  for (const r of g.roots) {
    open.add(r.key);
    walk(r, '', new Set());
  }
  return open;
}

function sortChildren(g: GraphModel, keys: string[]): PackageNode[] {
  return keys
    .map((k) => g.byKey.get(k))
    .filter((n): n is PackageNode => !!n)
    .sort((a, b) => nodeHotRank(b) - nodeHotRank(a) || a.name.localeCompare(b.name));
}

/** Best-effort path root → node, following the first parent edge (cycle-guarded). */
function pathToRoot(byKey: Map<string, PackageNode>, node: PackageNode): string[] {
  const names: string[] = [];
  let cur: PackageNode | undefined = node;
  const seen = new Set<string>();
  while (cur && !seen.has(cur.key)) {
    seen.add(cur.key);
    names.unshift(nameVersion(cur.name, cur.version, cur.display_name));
    const parentKey: string | undefined = (cur.required_by ?? []).find((e) => e.parent)?.parent;
    cur = parentKey ? byKey.get(parentKey) : undefined;
  }
  return names;
}

// --- node summary (reused in the request list) ------------------------------

/** One-line assessment summary: advisories, signature, sandbox reach, install scripts. */
export const NodeSummary: React.FC<{ node: PackageNode; className?: string }> = ({ node, className }) => {
  const a = node.assessment;
  const sandbox = a?.sandbox;
  const hostCount = (sandbox?.hosts ?? sandbox?.urls ?? []).length;
  const syscalls = syscallTotal(sandbox?.syscall_counts);
  const parts: React.ReactNode[] = [];
  if (a?.signature?.status === 'verified' || a?.provenance?.status === 'verified') parts.push(<span key="sig" className="text-success">signed</span>);
  else if (a?.signature?.status === 'failed') parts.push(<span key="sig" className="text-danger">signature failed</span>);
  else parts.push(<span key="sig">unsigned</span>);
  if (hostCount > 0) parts.push(<span key="net">contacts {hostCount} {hostCount === 1 ? 'host' : 'hosts'}</span>);
  if (syscalls > 0) parts.push(<span key="sys">{syscalls.toLocaleString('en-US')} syscalls</span>);
  if (a?.has_install_scripts) parts.push(<span key="scr" className="inline-flex items-center gap-1 text-warning"><TerminalSquare className="h-3 w-3" aria-hidden />install scripts</span>);
  if (a?.partial) parts.push(<span key="part" className="text-fg-subtle">partial</span>);
  return (
    <span className={cn('flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[12px] text-fg-muted', className)}>
      <AdvisorySummary assessment={a} />
      {parts.map((p, i) => (
        <React.Fragment key={i}>
          {(i > 0 || activeAdvisoryTotal(a) > 0) && <span className="text-fg-subtle" aria-hidden>·</span>}
          {p}
        </React.Fragment>
      ))}
    </span>
  );
};

// --- rows -------------------------------------------------------------------

const NodeRow: React.FC<{
  node: PackageNode;
  depth: number;
  expandable: boolean;
  expanded: boolean;
  cyclic?: boolean;
  hotDescendant?: boolean;
  selected?: boolean;
  onToggle?: () => void;
  onOpen: () => void;
}> = ({ node, depth, expandable, expanded, cyclic, hotDescendant, selected, onToggle, onOpen }) => {
  const published = node.published_at;
  const age = ageHours(published);
  const hot = nodeHotRank(node) >= 4;
  return (
    <div
      className={cn(
        'group flex items-start gap-2 border-b border-border py-2 pr-3 text-[13px] last:border-b-0',
        hot && 'bg-danger-soft/40',
        selected && 'bg-accent-soft/60'
      )}
      style={{ paddingLeft: 8 + depth * 18 }}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-label={expanded ? 'Collapse dependencies' : 'Expand dependencies'}
        aria-expanded={expandable ? expanded : undefined}
        disabled={!expandable}
        className={cn('mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-fg-subtle', expandable ? 'hover:bg-surface-3 hover:text-fg' : 'opacity-0')}
      >
        <ChevronRight className={cn('h-4 w-4 transition-transform', expanded && 'rotate-90')} aria-hidden />
      </button>
      <button type="button" onClick={onOpen} className="min-w-0 flex-1 text-left">
        <span className="flex flex-wrap items-center gap-1.5">
          <NodeStateChip state={node.state} />
          <span className="min-w-0 break-all font-mono text-[12.5px] font-medium text-fg">{nameVersion(node.name, node.version, node.display_name)}</span>
          <RiskBadge risk={node.assessment?.risk} malware={hasMalware(node.assessment)} />
          {node.root && <Badge tone="accent" size="sm">root</Badge>}
          {node.deprecated && <Badge tone="warning" size="sm">deprecated</Badge>}
          {node.yanked && <Badge tone="danger" size="sm">yanked</Badge>}
          {(node.kinds ?? []).map((k) => (
            <KindBadge key={k} kind={k} />
          ))}
          {cyclic && (
            <span className="inline-flex items-center gap-1 text-[11.5px] text-fg-subtle" title="This dependency forms a cycle back to an ancestor.">
              <Repeat2 className="h-3 w-3" aria-hidden />cycle
            </span>
          )}
          {hotDescendant && !expanded && (
            <span className="inline-flex items-center gap-1 text-[11.5px] font-medium text-danger" title="A high-risk dependency is nested below this node.">
              <ShieldAlert className="h-3 w-3" aria-hidden />high risk inside
            </span>
          )}
        </span>
        <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[12px] text-fg-subtle">
          {node.license ? <span>{node.license}</span> : <span className="text-fg-subtle">license unknown</span>}
          {published && (
            <>
              <span aria-hidden>·</span>
              <RelativeTime value={published} prefix="published" />
              {age !== null && <span>(cooldown {humanHours(age)})</span>}
            </>
          )}
        </span>
        <NodeSummary node={node} className="mt-1" />
      </button>
    </div>
  );
};

// --- component --------------------------------------------------------------

export const DependencyGraph: React.FC<{
  nodes: PackageNode[] | null | undefined;
  rootKey?: string;
  selectedKey?: string;
  onOpenNode: (node: PackageNode) => void;
}> = ({ nodes, rootKey, selectedKey, onOpenNode }) => {
  const list = nodes ?? [];
  const g = useMemo(() => buildGraph(list, rootKey), [list, rootKey]);
  const auto = useMemo(() => autoExpanded(g), [g]);
  const [view, setView] = useState<'tree' | 'state'>('tree');
  const [expanded, setExpanded] = useState<Set<string>>(auto);
  // Re-seed expansion when the graph changes shape (e.g. resolution finished during polling).
  const sig = `${list.length}:${rootKey ?? ''}`;
  useEffect(() => setExpanded(new Set(auto)), [sig]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggle = (pathKey: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(pathKey)) next.delete(pathKey);
      else next.add(pathKey);
      return next;
    });

  const byState = useMemo(() => {
    const groups = new Map<string, PackageNode[]>();
    for (const n of list) {
      const arr = groups.get(n.state) ?? [];
      arr.push(n);
      groups.set(n.state, arr);
    }
    return [...groups.entries()]
      .sort((a, b) => nodeStateMeta(a[0]).order - nodeStateMeta(b[0]).order)
      .map(([state, ns]) => ({ state, nodes: ns.sort((a, b) => nodeHotRank(b) - nodeHotRank(a) || a.name.localeCompare(b.name)) }));
  }, [list]);

  if (list.length === 0) {
    return <p className="text-[13px] text-fg-subtle">The dependency graph is empty or still being resolved.</p>;
  }

  const hotNodes = list
    .filter((n) => nodeHotRank(n) >= 4)
    .sort((a, b) => nodeHotRank(b) - nodeHotRank(a) || a.name.localeCompare(b.name));

  const rows: React.ReactNode[] = [];
  const renderTree = (node: PackageNode, parentPath: string, depth: number, ancestors: Set<string>) => {
    const pathKey = parentPath ? `${parentPath}>${node.key}` : node.key;
    const cyclic = ancestors.has(node.key);
    const kids = cyclic ? [] : sortChildren(g, g.childrenOf.get(node.key) ?? []);
    const expandable = kids.length > 0;
    const isOpen = expanded.has(pathKey);
    const hotDescendant = kids.some((k) => (g.subtreeRank.get(k.key) ?? 0) >= 4);
    rows.push(
      <NodeRow
        key={pathKey}
        node={node}
        depth={depth}
        expandable={expandable}
        expanded={isOpen}
        cyclic={cyclic}
        hotDescendant={hotDescendant}
        selected={selectedKey === node.key}
        onToggle={expandable ? () => toggle(pathKey) : undefined}
        onOpen={() => onOpenNode(node)}
      />
    );
    if (expandable && isOpen) {
      const next = new Set(ancestors).add(node.key);
      for (const k of kids) renderTree(k, pathKey, depth + 1, next);
    }
  };
  if (view === 'tree') {
    for (const r of g.roots) renderTree(r, '', 0, new Set());
  }

  return (
    <div className="min-w-0 space-y-3">
      {hotNodes.length > 0 && (
        <Callout tone="danger" icon={ShieldAlert} title={`${hotNodes.length} high-risk ${hotNodes.length === 1 ? 'package' : 'packages'} in this graph`}>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {hotNodes.slice(0, 12).map((n) => (
              <button
                key={n.key}
                type="button"
                onClick={() => onOpenNode(n)}
                className="inline-flex items-center gap-1.5 rounded-md border border-danger-border bg-surface px-1.5 py-0.5 font-mono text-[12px] text-fg hover:border-danger"
              >
                <RiskBadge risk={n.assessment?.risk} malware={hasMalware(n.assessment)} />
                {nameVersion(n.name, n.version, n.display_name)}
              </button>
            ))}
          </div>
        </Callout>
      )}

      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] text-fg-subtle">
          {list.length} {list.length === 1 ? 'package' : 'packages'}
        </span>
        <SegmentedControl<'tree' | 'state'>
          size="sm"
          aria-label="Graph layout"
          value={view}
          onChange={setView}
          options={[
            { value: 'tree', label: 'Tree' },
            { value: 'state', label: 'By state' },
          ]}
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-surface shadow-card">
        {view === 'tree' ? (
          rows
        ) : (
          <div>
            {byState.map(({ state, nodes: ns }) => (
              <div key={state}>
                <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-3 py-1.5 text-[12px] font-medium text-fg-muted">
                  <NodeStateChip state={state} />
                  <span>
                    {ns.length} {ns.length === 1 ? 'package' : 'packages'}
                  </span>
                </div>
                {ns.map((n) => {
                  const path = pathToRoot(g.byKey, n);
                  return (
                    <button
                      key={n.key}
                      type="button"
                      onClick={() => onOpenNode(n)}
                      className={cn(
                        'flex w-full items-start gap-2 border-b border-border px-3 py-2 text-left text-[13px] last:border-b-0 hover:bg-surface-2',
                        nodeHotRank(n) >= 4 && 'bg-danger-soft/40',
                        selectedKey === n.key && 'bg-accent-soft/60'
                      )}
                    >
                      <EcosystemBadge ecosystem={n.ecosystem} short className="mt-0.5" />
                      <span className="min-w-0 flex-1">
                        <span className="flex flex-wrap items-center gap-1.5">
                          <span className="break-all font-mono text-[12.5px] font-medium text-fg">{nameVersion(n.name, n.version, n.display_name)}</span>
                          <RiskBadge risk={n.assessment?.risk} malware={hasMalware(n.assessment)} />
                          {(n.kinds ?? []).map((k) => (
                            <KindBadge key={k} kind={k} />
                          ))}
                        </span>
                        {path.length > 1 && (
                          <span className="mt-0.5 block truncate text-[11.5px] text-fg-subtle" title={path.join(' → ')}>
                            {path.join(' → ')}
                          </span>
                        )}
                        <NodeSummary node={n} className="mt-1" />
                      </span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
      <p className="flex items-center gap-1.5 text-[11.5px] text-fg-subtle">
        <FileWarning className="h-3 w-3 shrink-0" aria-hidden />
        A critical node nested under a healthy average is surfaced above and marked on its collapsed ancestors.
      </p>
    </div>
  );
};
