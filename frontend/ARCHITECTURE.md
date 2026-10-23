# AegisProxy console — architecture

React 18 + TypeScript + Vite 8 (Rolldown) + Tailwind 4 (`@tailwindcss/vite`) + lucide-react. No router, UI kit or
chart library: the console ships its own small router (`src/lib/router.tsx`), design system (`src/ui/`) and SVG charts.
`npm audit` must stay at 0 findings (dev dependencies included).

```bash
npm install
AEGIS_DEV_API=http://127.0.0.1:8081 npm run dev   # Vite dev server, proxies /api to the control-plane
npm run build                                      # tsc (type check) + vite build → dist/
```

The production CSP is `script-src 'self'` (no inline scripts, no CDNs) and `style-src 'self' 'unsafe-inline'`.
Use the system font stack (already configured) and never add external fonts/scripts.

Tailwind has no JS config: the theme lives in `src/index.css` (`@theme` / `@theme inline` map the `--c-*` tokens to
utilities, `@custom-variant dark` follows the `.dark` class, sources are listed with `@source`). Tailwind 4 names:
`shadow-xs` (old `shadow-sm`), `outline-hidden` (old `outline-none`), `backdrop-blur-sm`, important as suffix
(`h-[18px]!`). `space-y-*` puts the margin on the *preceding* sibling — inline children (spans) need `block`.
Vite splits `react` and `icons` vendor chunks (`build.rolldownOptions.output.codeSplitting`); no chunk may exceed 500 kB.

## Folder structure

```
src/
  main.tsx              entry: applies the stored theme, renders <App/>
  App.tsx               providers + gate: public portal (?portal=block) / login / signed-in shell
  routes.tsx            route table (path → page component)
  index.css             Tailwind 4 entry: @theme mapping, design tokens (light/dark/density), base + component classes
  types.ts              JSON models of the control-plane (mirror of models.go, snake_case)
  config.ts             runtime config (window.__AEGIS_CONFIG__.apiBaseUrl from public/config.js)
  utils.ts              small helpers (copyText, password policy); formatting lives in lib/format.ts
  api/
    http.ts             fetch wrapper: cookies, X-Requested-With, ApiError, 401 → sign-out
    client.ts           typed client for every endpoint in docs/api.md: api.policySets.publish(…)
    index.ts            barrel (import from '../api')
  lib/
    router.tsx          history router: Routes, Link, NavLink, navigate, useParams, useSearchParams …
    theme.tsx           ThemeProvider: light / dark / system + comfortable / compact density
    hooks.ts            useAsync, useNow, useHotkey, useIsMobile, useDocumentTitle, focus trap …
    useUrlFilters.ts    DataTable search/facet state in the query string
    format.ts           numbers, bytes, durations, relative times
    storage.ts          localStorage that never throws
    cn.ts               className join
  data/
    session.tsx         SessionProvider: meta, signed-in user, login/logout, session expiry
    AppData.tsx         DataProvider: /api/state polling, live flows (SSE), useConsole, useAction
    permissions.ts      role helpers mirroring the server RBAC (UI hints only)
    lookups.ts          useLookups(): id → group / server / user / policy set
  ui/                   design system (see below), barrel: import { Button, DataTable } from '../ui'
  shell/                AppShell, Sidebar (+ nav.ts), Topbar, CommandPalette, ChangePasswordDialog, Logo
  components/           shared domain components
    common/             GroupChip, ServerChip, UserName, LabelChips, ChipList; Secrets (SecretField = write-only secret
                        with "Stored ••••" / Replace / Keep stored, OneTimeSecretModal = key shown once + acknowledgement);
                        ProviderLogo (Entra / OIDC mark for sign-in buttons)
    policy/             badges, RulesTable, RuleFormDrawer, RuleDetailDrawer, DiffView/Impact wrappers,
                        SubmitChangeDialog, policyUtils (spec conversion + client-side validation)
    traffic/            VerdictBadge
    fleet/              server/group chips, fleetUtils (health, static vs. label memberships, CSV), Server/Group form
                        drawers, OnboardingDrawer, ImportServersDrawer, FlowsTable, useServerActions,
                        DefenderDevice (Defender card / risk badge, quarantinedByLabel for `microsoft-defender`)
    requests/           requestUtils (states, grant durations + Team Lead cap), RequestsTable, ReviewPanel,
                        DurationPicker, AssignCard, RequestActivity, BulkReviewDialog
  pages/<area>/         one file per page (+ sub-folders for tabs / page-local hooks)
    auth/               LoginPage (SSO button, sso_error messages, break-glass password form), LoginRedirect
    governance/         AuditTrailPage, SettingsPage (+ settings/ sections), PosturePage (+ posture/postureMeta: ScoreRing)
    security/threats/   tabs of /threats incl. YaraTab / YaraEditor (+ yara.ts: rule count, heartbeat parsing)
    system/             NotFoundPage
```

## Routing

`src/routes.tsx` lists all routes; the first matching pattern wins. Patterns support `:param`,
optional `:param?` and a trailing `*`. Pages read params with `useParams<{ id: string }>()`.

- Navigate with `<Link to>` / `<ButtonLink to>` or `navigate(path, { replace?, preserveScroll? })`.
- Query state: `useSearchParams()` (merging setter, replaces history by default), `useQueryParam(name)`,
  `useUrlTab(allowed, fallback)` for `?tab=` and `useUrlFilters([...])` for DataTable filters.
  Path-segment tabs (e.g. `/policies/:id/:tab?`) are used for entity detail pages.
- Unsaved changes: `useNavigationBlocker(dirty, message, allow?)` — `allow(nextUrl)` exempts tab switches.
- Deep links work on reload (Go server and nginx serve `index.html` for unknown paths).
- The public block portal stays reachable at `/?portal=block&bt=<token>` (also `url`, `ip`, `trace`).
- Unknown paths render `NotFoundPage`. Larger pages are code-split with `React.lazy`
  (the shell wraps routes in `<Suspense>`).

Navigation entries (sidebar + command palette) live in `src/shell/nav.ts`, including the count badges
derived from `state.overview` / `state.stats` and `visible(perms)` for role-restricted pages (Security posture).
The command palette also indexes the settings sections (`SETTINGS_SECTIONS` incl. `keywords`), threat-protection
tabs, block page templates, learning sessions, policy sets, change/access requests, servers and groups, plus
role-aware quick actions (create policy set / YARA rule set / service account, import policy sets).

## Data layer

| Hook | Purpose |
|---|---|
| `useSession()` | `user`, `meta`, `login()`, `logout()`. A 401 anywhere signs out and shows a message. |
| `useConsole()` | `state` (`/api/state?exclude_flows=1`, polled every 30 s while visible), `refresh()`, `perms`, `demoMode`, `version` |
| `useConsoleState()` | the loaded state (pages render only after the first load) |
| `useFlows()` | `{ flows, connected }` live flows from `/api/flows/stream` (newest first, max 300) |
| `usePermissions()` | `canManageSystem`, `isSuperAdmin`, `isTeamLead`, `isReadOnly`, `canApproveFor(groups)`, `canManageSet(set)`, `canEditBlockRules` |
| `useAction()` | `run(fn, { success, errorTitle, key, refresh })`: toast success / server error, then `refresh()` |
| `useAsync(fn, deps)` | detail endpoints not in `/api/state` (e.g. `api.policySets.get(id)`); add `state.revision` to deps to reload after any change |
| `useLookups()` | maps and name helpers for groups, servers, users, policy sets |

Rules of thumb:

- Every mutation goes through `api.*`; afterwards call `refresh()` (and `reload()` of a `useAsync`).
- Endpoints outside `/api/state` are loaded with `useAsync`: `api.serviceAccounts`, `api.defender`, `api.yara`,
  `api.system.posture`, `api.exports`, `api.policySets.importBundle`. Write-only secrets (`client_secret`,
  `auth_header_value`, `secret`) are sent only when a new value was typed; the API reports `has_*` flags.
- Always show the server's error (`toast.error(err)`); permissions in the UI only hide/disable actions.
- Go may send `null` for empty arrays — read them as `x ?? []`.
- `useConfirm()` dialogs render in `ConfirmProvider`, *outside* `DataProvider`: a `body` must not use components that
  call `useConsole` / `useLookups` (e.g. `GroupChip`, `UserName`) — pass plain names instead.
- Policy set drafts: send the full spec with `PUT /draft`, keep rule ids, and pass untouched rules through
  unchanged (`toSpecInput`), otherwise the server reports them as modified.

## Design system (`src/ui/`)

Colors are tokens (`src/index.css`, RGB triplets) exposed as Tailwind colors: `bg`, `surface`, `surface-2/3`,
`border`, `border-strong`, `fg`, `fg-muted`, `fg-subtle`, `accent`, `primary`, `sidebar-*` and status tones
`success | warning | danger | info | neutral | violet` with `-soft`, `-border`, `-solid` variants
(`bg-danger-soft text-danger border-danger-border`). Never hard-code palette classes like `bg-slate-50`
in new code — tokens switch automatically between light and dark. Density changes `--control-h`,
`--cell-py/px` and `--card-p`.

| Component | Key props |
|---|---|
| `Button`, `ButtonLink`, `IconButton` | `variant` primary/secondary/ghost/danger/danger-ghost/link, `size` xs/sm/md/lg, `loading`, `icon`, `iconRight`; IconButton needs `label` (aria + tooltip) |
| `Badge`, `StatusChip`, `CountBadge` | `tone`, `variant` soft/solid/outline, `icon`, `dot`, `pulse` |
| `Card`, `CardHeader`, `CardBody`, `CardFooter`, `DescriptionList` | `padded`, `interactive`; header `title`, `description`, `icon`, `actions` |
| `PageHeader` | `title`, `description`, `breadcrumbs[{label,to}]`, `meta`, `actions` |
| `Tabs`, `TabPanel`, `useUrlTab` | `tabs[{id,label,icon,count,countTone,hidden}]`, `value`, `onChange` (arrow-key navigation; on phones the bar scrolls horizontally and keeps the active tab in view) |
| `DataTable` | `rows`, `columns[{id,header,cell,sortValue,width,align,hideBelow,mobileLabel}]`, `getRowId`, `getSearchText`, `facets[{id,label,getValue,options}]`, controlled `search`/`facetValues`, `selectable` + `bulkActions`, `rowHref`/`onRowClick`, `groupBy`, `empty`, `toolbar`, `mobileCard`, `maxHeight`, `pageSize` — cards on phones |
| `Drawer`, `Modal` | `open`, `onClose`, `title`, `description`, `footer`, `width`/`size`, `dismissible` (Esc + backdrop close, focus trap) |
| `ConfirmDialog`, `useConfirm()` | `title`, `description`, `body`, `tone`, `confirmLabel`, `typeToConfirm`, `reason{label,required,minLength}`, async `onConfirm(reason)` (errors are toasted, dialog stays open) |
| `useToast()` | `success/info/warning(title, {description, action})`, `error(errOrMessage, {title})` |
| `Tooltip`, `HelpTip`, `Callout` | tooltip `content`, `side`; HelpTip = "?" with explanation; Callout `tone`, `title`, `action` |
| `Field`, `Input`, `SearchInput`, `Textarea`, `Select`, `Checkbox`, `Switch`, `SegmentedControl`, `RadioCards` | Field wires label/hint/error/aria to its child; Input `icon`, `trailing`, `mono` |
| `MultiSelect`, `Combobox` | `value`, `onChange`, `options[{value,label,description,group,color,disabled}]` (searchable, keyboard) |
| `TagInput`, `KeyValueEditor` | chips with `validate`/`suggestions`; label maps with `allowWildcard` |
| `Menu`, `Popover` | `items[{id,label,icon,onSelect|to,danger,disabled,description,separator,hidden}]`, `trigger(props)` |
| `CodeBlock`, `CopyButton` | `code`, `title`, `wrap` (breaks long tokens only where needed), `maxHeight` |
| `CodeEditor` | `value`, `onChange`, `rows`, `errorLines` (highlighted gutter), `readOnly`; Tab/Shift+Tab indent, Esc releases Tab |
| `StatTile`, `Sparkline` | tile `label`, `value`, `icon`, `tone`, `hint`, `to`, `attention`; sparkline `data[{label,value}]`, `ariaLabel`, `format` |
| `Skeleton`, `SkeletonText`, `PageSkeleton`, `EmptyState`, `Spinner` | loading / empty states (`icon`, `title`, `description`, `action`) |
| `Timeline` | `items[{id,icon,tone,title,meta,body,current}]` |
| `DiffView` | backend `PolicyDiff` + optional `from`/`to` specs; use `PolicyDiffView` for group/server names |
| `PatternText`, `CompanionText`, `MethodList` | destination patterns with highlighted wildcards |
| `RelativeTime`, `CountdownChip` | relative time with absolute tooltip; deadline chip (`kind` due/expiry/review) |
| `Avatar`, `UserTag`, `Kbd` | initials avatar, keyboard hints (`modKey()`) |

## Adding or replacing a page

1. Create `src/pages/<area>/<Name>Page.tsx` exporting `export const <Name>Page: React.FC`.
   Start with `useDocumentTitle('…')` and a `PageHeader`.
2. Register it in `src/routes.tsx`.
   Top-level pages also need an entry in `src/shell/nav.ts`.
3. Read data with `useConsoleState()` / `useAsync(() => api.x.y(id), [id, state.revision])`;
   mutate with `api.*` + `useAction()` or `useConfirm()` for anything destructive.
4. Gate actions with `usePermissions()`; explain disabled actions (tooltip / Callout).
5. Lists: `DataTable` with `useUrlFilters` so filters are deep-linkable; provide `empty` states.
6. Check light + dark, desktop + phone (390 px): no horizontal scrolling, cards on phones.
7. `npm run build` must pass without warnings (no chunk above 500 kB) and `npm audit` must report 0 vulnerabilities.

## Route status

| Route | Status |
|---|---|
| `/` | built — Overview |
| `/policies`, `/policies/new`, `/policies/:id/:tab?` (rules, draft, changes, impact, history, requests) | built |
| `/changes`, `/changes/:id` | built |
| `/settings`, `/settings/:tab` (governance, notifications, identity, sso, service-accounts, data-planes, log-export, defender) | built — section sub-navigation (`pages/governance/settings/`, `systemOnly` sections show a restricted notice to other roles); identity: users with SSO / break-glass badges and the break-glass toggle (Super Admins only); sso: OIDC (Entra ID or generic) with write-only client secret, client authentication method, connection test, redirect URI to copy, group → role and group → Team Lead scope mapping, password sign-in / break-glass; service-accounts: API keys (shown once, rotate, disable, delete; `?new=1`); data-planes: ClamAV / YARA / ICAP heartbeat status; log export: destinations with live status, write-only secrets, test before save (`?edit=<id>`, `?new=1`); defender: Microsoft Defender for Endpoint (indicators import, device sync, automatic quarantine, test, sync now) |
| `/requests`, `/requests/:id` | built — inbox (`?status=pending\|mine\|overdue\|approved\|closed\|all`, facets, bulk review); detail with rule review, extend / revoke, assignment, activity |
| `/learning` | built — sessions (`?session=`), start / stop, candidate review, publish into a new or existing set (demo: simulate traffic) |
| `/servers`, `/servers/:id/:tab?` (overview, policy, traffic, requests, audit) | built — inventory (`?view=discovered`), register / import / export, onboarding, quarantine |
| `/groups`, `/groups/:id/:tab?` (members, policy, traffic, requests) | built — editor with label selector preview |
| `/traffic` | built — live flows with URL filters, pause/resume, flow drawer (`?flow=<id>`), simulator, "create rule from flow" → `/policies/new?host=…` |
| `/bandwidth` | built — KPIs, stacked throughput chart (chart/table), groups, top servers and destinations |
| `/threats/:tab?/:id?` (events, events/:id, feeds, iocs, exceptions, yara, yara/:id, policy, lookup) | built — `/threats/events/:id` is the deep link used by notifications; feeds include TAXII 2.1 / MISP sources and the Defender-managed feed; `yara/:id` (`new` creates) is the rule set editor with server lint errors inline and per-worker compile status; policy includes ICAP (RESPMOD/REQMOD) and YARA (`#icap`, `#yara` anchors) |
| `/tls`, `/audit` | built — TLS exceptions (scoped) + root CA; audit trail with URL filters, chain verify, full JSON Lines export (`GET /api/audit/export`), entity links (`?event=<id>`) |
| `/posture` | built — security posture score and hardening checks by category (`?status=fail\|warn\|pass\|info\|attention`); InfoSec / Super Admin only (compact card on the overview) |
| `/policies` (Export / Import) | built — policy as code: export bundle download, import drawer with dry-run preview, apply as drafts (`?import=1`) |
| `/login` | redirects to `/` once signed in (the SSO callback sends errors to `/login?sso_error=<code>`) |
| `/block-pages`, `/block-pages/:id` (`new` creates) | built — template cards with live thumbnails; designer with sandboxed live preview (`POST /api/block-pages/preview`), group assignment via `POST /api/groups` |
| `/?portal=block&bt=…` | built — anonymous portal (`pages/public/`) |

## Copy conventions

English, sentence case, no ALL-CAPS labels. Buttons say what happens ("Publish", "Submit for review",
"Save draft") and the toast repeats the verb ("Published v3"). Errors state what failed and show the
server message. Empty states tell the user what to do next.
