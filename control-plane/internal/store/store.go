package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/notify"
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/threatintel"
)

const (
	currentSchemaVersion = 4
	maxFlows             = 2000
	maxAuditEvents       = 2000
	maxSecurityEvents    = 1000
	maxRequests          = 5000
	maxPendingRequests   = 500
	maxPendingUnverified = 100 // self-reported requests without a data-plane block token
	maxPendingPerSource  = 5   // unverified requests per source IP
	maxPendingPerServer  = 50
)

func newRandomID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// RevokedToken records a signed-out session (JWT ID) until the token would have expired anyway.
type RevokedToken struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StateSnapshot struct {
	SchemaVersion int                  `json:"schema_version"`
	Revision      uint64               `json:"revision"`
	Users         []models.User        `json:"users"`
	EntraConfig   models.EntraIDConfig `json:"entra_config"`
	// GroupMapKeysTyped records that group mapping keys use the 2.1 id:/name: semantics
	// (migrateGroupMappingKeysLocked ran once).
	GroupMapKeysTyped bool                      `json:"group_map_keys_typed,omitempty"`
	Groups            []models.ServerGroup      `json:"groups"`
	Servers           []models.Server           `json:"servers"`
	Rules             []models.PolicyRule       `json:"rules"`
	TLSBypass         []models.TLSBypassRule    `json:"tls_bypass"`
	Sessions          []models.LearningSession  `json:"sessions"`
	Requests          []models.AccessRequest    `json:"requests"`
	Flows             []models.TrafficFlow      `json:"flows"`
	NotifyConfig      models.NotificationConfig `json:"notify_config"`
	AuditEvents       []models.AuditEvent       `json:"audit_events"`
	SecurityPolicy    models.SecurityPolicy     `json:"security_policy"`
	ThreatFeeds       []models.ThreatFeed       `json:"threat_feeds"`
	Indicators        []models.Indicator        `json:"indicators"`
	ThreatExceptions  []models.ThreatException  `json:"threat_exceptions"`
	SecurityEvents    []models.SecurityEvent    `json:"security_events"`
	RevokedTokens     []RevokedToken            `json:"revoked_tokens"`
	// Policy management (schema v3). Rules above is the compiled, effective rule list derived from
	// the published content of enabled policy sets; it is kept in the state file for diagnostics
	// and downgrade compatibility but never edited directly.
	PolicySets     []models.PolicySet         `json:"policy_sets"`
	PolicyVersions []models.PolicySetVersion  `json:"policy_versions"`
	ChangeRequests []models.ChangeRequest     `json:"change_requests"`
	Governance     models.GovernanceSettings  `json:"governance"`
	BlockPages     []models.BlockPageTemplate `json:"block_pages"`
	// RuleStats holds hit counters per rule ID (file storage; the cluster keeps them in a table).
	RuleStats map[string]RuleStat `json:"rule_stats,omitempty"`
	// FlowJournalSeq is the last flow journal segment this state includes (file storage; flowjournal.go).
	FlowJournalSeq uint64 `json:"flow_journal_seq,omitempty"`
	// ExportSinks configures log forwarding (secrets persisted, never returned by the API).
	ExportSinks []models.ExportSink `json:"export_sinks"`
	// ServiceAccounts are API identities for automation (key digests only).
	ServiceAccounts []models.ServiceAccount `json:"service_accounts"`
	// Defender configures the Microsoft Defender for Endpoint integration.
	Defender models.DefenderConfig `json:"defender"`
	// YaraRuleSets are applied by the data-plane to downloads (yara_mode).
	YaraRuleSets []models.YaraRuleSet `json:"yara_rule_sets"`
	// AuditChainKey keys the audit hash chain (hex, sealed at rest); never exposed by the API.
	AuditChainKey sealed.String `json:"audit_chain_key,omitempty"`
	// AuditAnchor seals where the audit trail starts and where its unkeyed pre-2.1 prefix ends
	// (JSON keyed with the audit chain key, sealed at rest); never exposed by the API.
	AuditAnchor sealed.String `json:"audit_anchor,omitempty"`
	// AuditCheckpoint seals the newest end of the audit trail together with this state (keyed with
	// the audit chain key, recomputed on every save); never exposed by the API.
	AuditCheckpoint *AuditCheckpoint `json:"audit_checkpoint,omitempty"`
	// SSOClientKeys authenticate the console to the IdP with private_key_jwt (private keys sealed).
	SSOClientKeys []models.SSOClientKey `json:"sso_client_keys,omitempty"`
	// SCIM configures inbound provisioning (token digests only); SCIMGroups are the pushed groups.
	SCIM       models.SCIMConfig  `json:"scim"`
	SCIMGroups []models.SCIMGroup `json:"scim_groups,omitempty"`
	// Packages is the package firewall (3.0): settings, rules, approvals and blocks. These travel in the
	// data-plane bundle, so a change to them is a policy change (the bundle ETag covers them).
	Packages models.PackageFirewall `json:"packages"`
	// PackageWork is the firewall's work-store: open/closed requests with their resolved graphs, the
	// assessment cache and the sandbox analysis queue. It is persisted and cluster-replicated in this
	// configuration document but is NOT part of the data-plane bundle (the bundle ETag ignores it), so
	// analysis churn does not resync the workers. Raw sandbox reports are kept out-of-band by ReportKey.
	PackageWork PackageWorkState `json:"package_work"`
}

// PackageWorkState holds the firewall's request/assessment/job records.
type PackageWorkState struct {
	Requests    []models.PackageRequest             `json:"requests,omitempty"`
	Assessments map[string]models.PackageAssessment `json:"assessments,omitempty"` // key: ecosystem:name@version
	Jobs        []models.AnalysisJob                `json:"jobs,omitempty"`
}

type Options struct {
	DataDir                string
	DemoMode               bool
	BootstrapAdminPassword string
	DashboardURL           string
	Engine                 *engine.PolicyEngine
	Notifier               *notify.Dispatcher
	ThreatIntel            *threatintel.Manager
	AuditSink              *AuditSink
	Exporter               *export.Manager
	Logger                 *slog.Logger
	// Cluster enables active-active operation on shared storage (nil = single-node file storage).
	Cluster        ClusterBackend
	FlowRetention  time.Duration
	EventRetention time.Duration
	// AuditVerifyInterval verifies the complete audit trail in the background: at start-up, at this
	// interval and after the audit log rotated (0 = only on request, GET /api/audit/verify).
	AuditVerifyInterval time.Duration
}

type Store struct {
	mu          sync.RWMutex
	opts        Options
	log         *slog.Logger
	filePath    string
	state       StateSnapshot
	compiledIdx *engine.CompiledPolicyIndex
	// bundleGen increments whenever a data-plane-bundle input is recompiled (buildIndexLocked); it does
	// NOT move on work-store churn (bumpConfigLocked), so the bundle handler can cache the built bundle.
	bundleGen   uint64
	ruleIndex   map[string]int
	quarantined map[string]bool
	saByHash    map[string]int
	// Package approval/block lookup indexes (ecosystem+"\x00"+normalized-name -> positions in
	// Packages.Approvals/Blocks), rebuilt in buildIndexLocked. Used by the coordinator's per-node read
	// path so it does not scan every approval/block; the intra-mutation scans stay linear.
	pkgApprovalIdx map[string][]int
	pkgBlockIdx    map[string][]int
	saTouchMu   sync.Mutex
	saTouched   map[string]time.Time
	revoked     map[string]time.Time

	saveSignal chan struct{}
	dirty      bool // state changed without a config revision bump (last login, ...): saved within a second
	// telemetryDirty marks new traffic records only: the flow window is saved at most every
	// telemetryPersistInterval, so busy proxies do not rewrite the state file every second.
	telemetryDirty bool
	lastPersist    time.Time

	cluster      ClusterBackend
	writeMu      sync.Mutex
	pendingAudit []models.AuditEvent
	telemetry    *telemetryQueue
	flowCursor   int64
	eventCursor  time.Time
	seenFlows    seenSet

	// Data-plane telemetry (flowjournal.go, flows.go): ingestion is serialized, acknowledged after durable storage.
	ingestMu       sync.Mutex
	flushMu        sync.Mutex
	journal        *flowJournal // file storage only
	flowDuplicates atomic.Int64
	flowDropsMu    sync.Mutex
	flowDrops      map[string]int64

	importedTelemetry bool
	importedFileState bool // the cluster was initialized from a single-node state file
	// auditIntegrityErr is set at start-up when the audit trail cannot be trusted (state and audit log
	// diverged, invalid or missing anchor or checkpoint); verification and the posture check report
	// it. auditViolations are the violations not yet recorded (reportAuditViolationsLocked).
	auditIntegrityErr string
	auditViolations   []string
	auditAtLoad       auditLoaded
	// Last AUDIT_CHECKPOINT record published to the audit export stream.
	lastCheckpointExport time.Time
	lastCheckpointHead   string
	lastCheckpointEvents int
	// Security events raised before the store went live (goLive) are queued: the exporter has no
	// sinks and the notifier no channels yet. raisedAudit notes the audit alerts raised at this start.
	alertsLive    bool
	exportLive    bool
	pendingAlerts []models.SecurityEvent
	raisedAudit   map[string]bool
	full          fullCheckState // complete verification of the audit trail (audit_verify.go)
	closed        chan struct{}
	closeOnce     sync.Once
	persistWG     sync.WaitGroup

	engine   *engine.PolicyEngine
	notifier *notify.Dispatcher
	threat   *threatintel.Manager
	traffic  *trafficAggregator
	bursts   *burstDetector

	flowSubsMu sync.Mutex
	flowSubs   map[chan models.TrafficFlow]struct{}

	bwMu       sync.Mutex
	bwCache    *models.BandwidthSummary
	bwCachedAt time.Time
}

func NewStore(opts Options) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.FlowRetention <= 0 {
		opts.FlowRetention = 7 * 24 * time.Hour
	}
	if opts.EventRetention <= 0 {
		opts.EventRetention = 90 * 24 * time.Hour
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{
		opts:       opts,
		log:        opts.Logger.With("component", "store"),
		filePath:   filepath.Join(opts.DataDir, "aegis_state.json"),
		engine:     opts.Engine,
		notifier:   opts.Notifier,
		threat:     opts.ThreatIntel,
		traffic:    newTrafficAggregator(),
		bursts:     newBurstDetector(),
		flowSubs:   make(map[chan models.TrafficFlow]struct{}),
		saveSignal: make(chan struct{}, 1),
		closed:     make(chan struct{}),
		revoked:    make(map[string]time.Time),
		cluster:    opts.Cluster,
	}
	s.full.kick = make(chan string, 1)
	if s.cluster != nil {
		s.telemetry = newTelemetryQueue()
		if err := s.initCluster(s.seedClusterLocked); err != nil {
			return nil, err
		}
		if err := s.loadClusterTelemetry(); err != nil {
			return nil, fmt.Errorf("load telemetry from cluster storage: %w", err)
		}
		if err := s.ensureClusterAuditAnchor(); err != nil {
			s.log.Error("could not seal the audit trail anchor", "error", err)
		}
		s.mu.Lock()
		for _, f := range s.state.Flows {
			s.traffic.add(f)
		}
		s.mu.Unlock()
		s.goLive()
		s.persistWG.Add(3)
		go s.clusterLoops()
		go s.housekeepingLoop()
		go s.defenderLoop()
		s.startAuditVerification()
		s.registerCollectors()
		return s, nil
	}
	if err := s.loadOrSeed(); err != nil {
		return nil, err
	}
	if err := s.openFlowJournal(); err != nil {
		return nil, err
	}
	s.goLive()
	s.persistWG.Add(3)
	go s.asyncDiskPersistLoop()
	go s.housekeepingLoop()
	go s.defenderLoop()
	s.startAuditVerification()
	s.registerCollectors()
	return s, nil
}

// goLive configures the notification channels and starts the export sinks of the loaded
// configuration (with the key that authenticates their spool records), and only then delivers the
// security events raised while loading, such as integrity violations found at start-up, and reminds
// of audit-trail states that persist across restarts.
func (s *Store) goLive() {
	s.mu.Lock()
	s.exportLive = true
	if s.notifier != nil {
		s.notifier.UpdateConfig(s.state.NotifyConfig) // also for a cluster seeded or imported from a state file
	}
	if s.opts.Exporter != nil {
		s.opts.Exporter.SetSpoolKey(s.exportSpoolKeyLocked())
		s.opts.Exporter.SetAlertHandler(s.RecordExportAlert)
	}
	s.syncExportLocked()
	s.mu.Unlock()
	s.opts.Exporter.Sync() // outside the store lock: stopping replaced sinks may take a moment

	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertsLive = true
	pending := s.pendingAlerts
	s.pendingAlerts = nil
	for _, ev := range pending {
		s.announceSecurityEventLocked(ev)
	}
	s.remindAuditStateLocked()
	s.exportAuditCheckpointLocked()
}

// startAuditVerification starts the background verification of the complete audit trail.
func (s *Store) startAuditVerification() {
	if s.opts.AuditVerifyInterval <= 0 {
		return
	}
	if s.cluster == nil {
		s.opts.AuditSink.OnChange(s.kickAuditVerify)
	}
	s.persistWG.Add(1)
	go s.auditVerifyLoop()
}

// seedClusterLocked initializes an empty cluster: an existing single-node state file is imported
// (migration path from file storage), otherwise a fresh production or demo state is seeded.
func (s *Store) seedClusterLocked() error {
	if data, err := os.ReadFile(s.filePath); err == nil && len(data) > 0 {
		var legacy StateSnapshot
		if err := json.Unmarshal(data, &legacy); err == nil {
			if err := requireSealedAuditSecrets(data); err != nil {
				return fmt.Errorf("state file %s: %w", s.filePath, err)
			}
			s.state = legacy
			s.importedTelemetry, s.importedFileState = true, true
			s.log.Warn("imported existing file state into cluster storage — keep the file as backup, it is no longer used", "path", s.filePath)
			return nil
		}
	}
	s.state = StateSnapshot{SchemaVersion: currentSchemaVersion}
	if s.opts.DemoMode {
		s.seedDemoData()
	} else {
		s.seedProduction()
	}
	s.importedTelemetry = true
	return nil
}

// Close flushes pending state to disk and stops the persistence loop.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.stopAuditVerification()
		s.persistWG.Wait()
	})
}

func (s *Store) SubscribeFlows() chan models.TrafficFlow {
	ch := make(chan models.TrafficFlow, 256)
	s.flowSubsMu.Lock()
	s.flowSubs[ch] = struct{}{}
	s.flowSubsMu.Unlock()
	return ch
}

func (s *Store) UnsubscribeFlows(ch chan models.TrafficFlow) {
	s.flowSubsMu.Lock()
	if _, ok := s.flowSubs[ch]; ok {
		delete(s.flowSubs, ch)
		close(ch)
	}
	s.flowSubsMu.Unlock()
}

func (s *Store) broadcastFlow(flow models.TrafficFlow) {
	s.flowSubsMu.Lock()
	for ch := range s.flowSubs {
		select {
		case ch <- flow:
		default:
		}
	}
	s.flowSubsMu.Unlock()
}

func (s *Store) rebuildIndexLocked() {
	s.state.Revision++
	s.buildIndexLocked(s.state.Revision)
}

// buildIndexLocked derives everything that is computed from the configuration: effective group
// membership, the compiled rule list and the matching index.
func (s *Store) buildIndexLocked(rev uint64) {
	s.bundleGen++ // a data-plane-relevant input changed; the cached bundle is now stale
	s.computeEffectiveGroupsLocked()
	s.compileRulesLocked()
	s.compiledIdx = engine.BuildCompiledIndex(rev, s.state.Groups, s.effectiveServersLocked(), s.state.Rules)
	s.saByHash = make(map[string]int, len(s.state.ServiceAccounts))
	for i, sa := range s.state.ServiceAccounts {
		if sa.KeyHash != "" {
			s.saByHash[sa.KeyHash] = i
		}
	}
	s.quarantined = map[string]bool{}
	for _, srv := range s.state.Servers {
		if srv.Quarantined {
			s.quarantined[srv.ID] = true
		}
	}
	s.ruleIndex = make(map[string]int, len(s.state.Rules))
	for i, r := range s.state.Rules {
		s.ruleIndex[r.ID] = i
	}
	s.pkgApprovalIdx = make(map[string][]int, len(s.state.Packages.Approvals))
	for i := range s.state.Packages.Approvals {
		a := &s.state.Packages.Approvals[i]
		k := a.Ecosystem + "\x00" + a.Name
		s.pkgApprovalIdx[k] = append(s.pkgApprovalIdx[k], i)
	}
	s.pkgBlockIdx = make(map[string][]int, len(s.state.Packages.Blocks))
	for i := range s.state.Packages.Blocks {
		b := &s.state.Packages.Blocks[i]
		k := b.Ecosystem + "\x00" + normalizePackageName(b.Ecosystem, b.Name)
		s.pkgBlockIdx[k] = append(s.pkgBlockIdx[k], i)
	}
}

// saveLocked bumps the configuration revision (data-plane bundle ETag), recompiles the policy
// index and schedules persistence. Callers must hold s.mu.
func (s *Store) saveLocked() {
	s.rebuildIndexLocked()
	s.markDirtyLocked()
}

func (s *Store) markDirtyLocked() {
	s.dirty = true
	select {
	case s.saveSignal <- struct{}{}:
	default:
	}
}

// bumpConfigLocked persists a configuration change that does not affect the data-plane bundle or the
// policy index (the package firewall's work-store: requests, assessments, analysis jobs). It bumps the
// revision so cluster peers reload the document, but skips the rule/index recompile. The data-plane
// bundle ETag ignores the revision, so the workers are not resynced. Callers hold s.mu.
func (s *Store) bumpConfigLocked() {
	s.state.Revision++
	s.markDirtyLocked()
}

const telemetryPersistInterval = 15 * time.Second

func (s *Store) markTelemetryDirtyLocked() { s.telemetryDirty = true }

// registerCollectors connects integration-backed threat-intel sources.
func (s *Store) registerCollectors() {
	if s.threat != nil {
		s.threat.SetCollector(threatintel.FeedFormatMDE, s.defenderCollector)
	}
}

// syncThreatIntelLocked pushes feed/IOC/exception configuration to the threat-intel manager.
func (s *Store) syncThreatIntelLocked() {
	if s.threat == nil {
		return
	}
	feeds := append([]models.ThreatFeed(nil), s.state.ThreatFeeds...)
	inds := append([]models.Indicator(nil), s.state.Indicators...)
	excs := append([]models.ThreatException(nil), s.state.ThreatExceptions...)
	go s.threat.Configure(feeds, inds, excs)
}

func (s *Store) asyncDiskPersistLoop() {
	defer s.persistWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.saveSignal:
		case <-ticker.C:
		case <-s.closed:
			s.persist(true)
			return
		}
		s.persist(false)
		s.retryAuditSink()
		s.exportAuditCheckpointIfDue()
	}
}

// persist writes the state file when the configuration changed (or, at most every
// telemetryPersistInterval, when only traffic records were added). Serialization runs under the
// read lock, so API reads and data-plane evaluations are not blocked.
func (s *Store) persist(force bool) {
	s.mu.Lock()
	due := s.dirty || (s.telemetryDirty && (force || time.Since(s.lastPersist) >= telemetryPersistInterval))
	if !due {
		s.mu.Unlock()
		return
	}
	s.dirty, s.telemetryDirty = false, false
	s.lastPersist = time.Now()
	s.pruneRevokedLocked()
	s.mu.Unlock()

	journalCut := s.rotateFlowJournal() // every journaled flow is in s.state from here on

	s.mu.RLock()
	data, err := s.marshalStateLocked()
	s.mu.RUnlock()
	if err != nil {
		s.log.Error("state marshal failed", "error", err)
		return
	}
	if err := writeStateFile(s.filePath, data); err != nil {
		s.log.Error("state persist failed", "error", err)
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return
	}
	s.releaseFlowJournal(journalCut)
}

// writeStateFile writes atomically (temp file + fsync + rename) with 0600 permissions and keeps
// the previous version as .bak for manual recovery.
func writeStateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".aegis_state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path + ".bak")
		_ = os.Link(path, path+".bak")
		_ = os.Chmod(path+".bak", 0o600)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (s *Store) loadOrSeed() error {
	staleBefore := sealed.StaleCount()
	data, err := os.ReadFile(s.filePath)
	existing := err == nil && len(data) > 0
	switch {
	case existing:
		if err := requireSealedAuditSecrets(data); err != nil {
			return fmt.Errorf("state file %s: %w", s.filePath, err)
		}
		if err := json.Unmarshal(data, &s.state); err != nil {
			return fmt.Errorf("state file %s is corrupt (%v); restore %s.bak or move it away to start fresh", s.filePath, err, s.filePath)
		}
		_ = os.Chmod(s.filePath, 0o600)
		s.noteAuditLoadedLocked()
		s.log.Info("state loaded", "path", s.filePath, "revision", s.state.Revision, "schema", s.state.SchemaVersion)
	case err == nil || errors.Is(err, os.ErrNotExist):
		s.state = StateSnapshot{SchemaVersion: currentSchemaVersion}
		if s.opts.DemoMode {
			s.log.Warn("AEGIS_DEMO_MODE=true: seeding showcase data with PUBLIC demo credentials — never use in production")
			s.seedDemoData()
		} else {
			s.seedProduction()
		}
	default:
		return fmt.Errorf("read state: %w", err)
	}
	// Before anything appends to the chain: check the sealed end of the trail saved with the state,
	// line up the audit log with it, then check (or seal) the anchor; violations are recorded last.
	var recovered *models.AuditEvent
	if existing {
		s.checkAuditCheckpointLocked()
		recovered = s.reconcileAuditTrailLocked()
	}
	s.ensureFileAuditAnchorLocked(existing)
	if recovered != nil {
		s.appendAuditLocked(*recovered)
	}
	s.reportAuditViolationsLocked()

	s.migrateLocked()
	if err := s.ensureBootstrapAdminLocked(); err != nil {
		return err
	}
	for _, rt := range s.state.RevokedTokens {
		s.revoked[rt.JTI] = rt.ExpiresAt
	}
	for _, f := range s.state.Flows {
		s.traffic.add(f)
	}
	if s.notifier != nil {
		s.notifier.UpdateConfig(s.state.NotifyConfig)
	}
	s.rebuildIndexLocked()
	s.syncThreatIntelLocked()
	s.syncExportLocked()
	if n := sealed.StaleCount() - staleBefore; n > 0 {
		s.log.Info("re-encrypting secrets with the current key", "secrets", n, "key_id", sealed.KeyID())
	}
	if err := s.syncAuditSinkLocked(); err != nil { // seeded events never went through the sink
		s.log.Error("audit log could not be completed", "error", err)
	}
	s.dirty = true // always rewritten at start: migrations and re-encryption after a key rotation
	s.persistNow()
	return nil
}

// syncExportLocked pushes the export sink configuration to the exporter (from goLive on).
func (s *Store) syncExportLocked() {
	if s.opts.Exporter == nil || !s.exportLive {
		return
	}
	s.opts.Exporter.Apply(s.state.ExportSinks)
}

// emitAudit writes a committed audit event to the local JSONL sink and the log exporter. With file
// storage the audit log is the trail of record: it receives every window event it is missing (after
// a failed write too), and a write failure makes the store refuse further changes (withWrite).
func (s *Store) emitAudit(ev models.AuditEvent) {
	if s.cluster == nil {
		_ = s.syncAuditSinkLocked()
	} else {
		_ = s.opts.AuditSink.Write(ev)
	}
	s.opts.Exporter.Publish(export.AuditEvent(ev))
	if cp := s.state.AuditCheckpoint; cp != nil && cp.Events/auditCheckpointEvery != s.lastCheckpointEvents/auditCheckpointEvery {
		s.exportAuditCheckpointLocked()
	}
}

// marshalStateLocked serializes the state with its audit checkpoint sealed for exactly this content.
func (s *Store) marshalStateLocked() ([]byte, error) {
	snap := s.state
	snap.AuditCheckpoint = s.sealedCheckpointLocked()
	return json.Marshal(snap)
}

func (s *Store) persistNow() {
	data, err := s.marshalStateLocked()
	if err != nil {
		return
	}
	if err := writeStateFile(s.filePath, data); err != nil {
		s.log.Error("initial state persist failed", "error", err)
		return
	}
	s.dirty = false
}

func (s *Store) seedProduction() {
	now := time.Now().UTC()
	s.state.EntraConfig = models.EntraIDConfig{AllowLocalLogin: true, GroupRoleMap: map[string]models.Role{}}
	s.state.NotifyConfig = models.NotificationConfig{DashboardBaseURL: s.opts.DashboardURL, NotifySecurityEvents: true}
	s.state.SecurityPolicy = DefaultSecurityPolicy()
	s.state.ThreatFeeds = threatintel.DefaultFeeds()
	s.state.Users = []models.User{}
	s.state.Governance = DefaultGovernance()
	s.state.BlockPages = []models.BlockPageTemplate{DefaultBlockPageTemplate()}
	s.state.PolicySets = []models.PolicySet{}
	s.state.Packages = DefaultPackageFirewall()
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "SYSTEM_INITIALIZED", Category: "SYSTEM",
		EntityType: "control_plane", EntityID: "aegis", EntityName: "AegisProxy Control-Plane",
		Summary:   "Initialized empty production data directory (default-deny policy, threat intelligence enabled)",
		Timestamp: now,
	})
}

// migrateLocked upgrades state written by older releases.
func (s *Store) migrateLocked() {
	// v0 -> v1: proxy tokens were stored in plaintext.
	for i := range s.state.Servers {
		srv := &s.state.Servers[i]
		if srv.ProxyAuthToken != "" {
			srv.ProxyAuthTokenHash = engine.HashProxyToken(srv.ProxyAuthToken)
			srv.ProxyAuthToken = ""
		}
	}
	if s.state.SchemaVersion < 1 {
		// Legacy releases hard-coded the zero-internet tier.
		for i := range s.state.Groups {
			if s.state.Groups[i].ID == "grp-db-vault" {
				s.state.Groups[i].StrictIsolation = true
			}
		}
	}
	if s.state.SchemaVersion < 2 {
		if s.state.SecurityPolicy.ThreatIntelMode == "" {
			s.state.SecurityPolicy = DefaultSecurityPolicy()
		}
		s.state.NotifyConfig.NotifySecurityEvents = true
	}
	if s.state.SecurityPolicy.ThreatIntelMode == "" {
		s.state.SecurityPolicy = DefaultSecurityPolicy()
	}
	// 2.0 prepared Entra ID with a different callback path.
	if ru := s.state.EntraConfig.RedirectURI; strings.HasSuffix(ru, "/api/auth/entra/callback") {
		s.state.EntraConfig.RedirectURI = strings.TrimSuffix(ru, "/api/auth/entra/callback") + "/api/auth/sso/callback"
	}
	if s.state.SecurityPolicy.ICAPMode == "" { // 2.1 additions
		def := DefaultSecurityPolicy()
		p := &s.state.SecurityPolicy
		p.ICAPMode, p.ICAPFailMode, p.ICAPTimeoutSeconds, p.ICAPMaxBytes, p.ICAPAllowModified = def.ICAPMode, def.ICAPFailMode, def.ICAPTimeoutSeconds, def.ICAPMaxBytes, def.ICAPAllowModified
		p.YARAMode, p.YARAMaxBytes = def.YARAMode, def.YARAMaxBytes
	}
	if s.state.SecurityPolicy.DLPOversizeAction == "" {
		s.state.SecurityPolicy.DLPOversizeAction = "allow"
	}
	s.mergeBuiltinFeedsLocked()
	if s.state.Users == nil {
		s.state.Users = []models.User{}
	}
	// Break-glass accounts (2.1): keep the previous behaviour that local Super Admins can always sign in.
	if !slices.ContainsFunc(s.state.Users, func(u models.User) bool { return u.BreakGlass }) {
		for i := range s.state.Users {
			if u := &s.state.Users[i]; u.Role == models.RoleSuperAdmin && u.AuthProvider != "oidc" && u.PasswordHash != "" {
				u.BreakGlass = true
			}
		}
	}
	s.migrateGroupMappingKeysLocked()
	// v2 -> v3: flat rules become policy sets; hit counters move to RuleStats.
	s.migratePolicySetsLocked()
	if s.state.SchemaVersion < 4 {
		// v3 -> v4: '*' in path patterns is one segment (2.1); legacy patterns keep their meaning.
		s.migratePathPatternsLocked()
	}
	if s.state.Governance.RequestSLAHours == 0 {
		s.state.Governance = DefaultGovernance()
	}
	if !slices.ContainsFunc(s.state.BlockPages, func(t models.BlockPageTemplate) bool { return t.IsDefault }) {
		s.state.BlockPages = append([]models.BlockPageTemplate{DefaultBlockPageTemplate()}, s.state.BlockPages...)
	}
	// 3.0: the package firewall. A state written before 3.0 has no ecosystems configured; seed the
	// defaults (every ecosystem off, so an upgrade changes no traffic until an operator enables one),
	// and add newly shipped default advisory sources while keeping the operator's choices.
	if s.state.Packages.Settings.Ecosystems == nil {
		s.state.Packages = DefaultPackageFirewall()
	} else {
		mergePackageAuditDefaultsLocked(&s.state.Packages.Settings)
	}
	s.state.SchemaVersion = currentSchemaVersion
}

// mergeBuiltinFeedsLocked adds new catalog feeds and refreshes metadata of built-in feeds while
// preserving the operator's enabled/refresh/auth choices.
func (s *Store) mergeBuiltinFeedsLocked() {
	existing := make(map[string]int, len(s.state.ThreatFeeds))
	for i, f := range s.state.ThreatFeeds {
		existing[f.ID] = i
	}
	for _, def := range threatintel.DefaultFeeds() {
		if i, ok := existing[def.ID]; ok {
			cur := &s.state.ThreatFeeds[i]
			if cur.Builtin {
				cur.Name, cur.Description, cur.URL, cur.Format = def.Name, def.Description, def.URL, def.Format
				cur.Category, cur.License = def.Category, def.License
			}
			continue
		}
		s.state.ThreatFeeds = append(s.state.ThreatFeeds, def)
	}
}

// ensureBootstrapAdminLocked guarantees that at least one Super Admin can sign in.
func (s *Store) ensureBootstrapAdminLocked() error {
	now := time.Now().UTC()
	if s.opts.DemoMode {
		for i := range s.state.Users {
			u := &s.state.Users[i]
			if pw, ok := demoPasswords[u.Username]; ok && u.PasswordHash == "" {
				u.PasswordHash = auth.HashPassword(pw)
				u.PasswordSetAt = &now
			}
		}
	}
	for _, u := range s.state.Users {
		if u.Role == models.RoleSuperAdmin && !u.Disabled && u.PasswordHash != "" {
			return nil
		}
	}

	password := s.opts.BootstrapAdminPassword
	generated := password == ""
	if generated {
		password = auth.GeneratePassword()
	} else if err := auth.ValidatePasswordStrength(password, "admin"); err != nil {
		return fmt.Errorf("AEGIS_BOOTSTRAP_ADMIN_PASSWORD rejected: %w", err)
	}

	idx := -1
	for i, u := range s.state.Users {
		if strings.EqualFold(u.Username, "admin") {
			idx = i
			break
		}
	}
	if idx == -1 {
		s.state.Users = append(s.state.Users, models.User{
			ID: "usr-admin", Username: "admin", DisplayName: "Bootstrap Administrator",
			Role: models.RoleSuperAdmin, AuthProvider: "local", AllowedGroups: []string{"*"},
			Department: "Platform Security", CreatedAt: now, BreakGlass: true,
		})
		idx = len(s.state.Users) - 1
	}
	u := &s.state.Users[idx]
	u.Role = models.RoleSuperAdmin
	u.Disabled = false
	u.PasswordHash = auth.HashPassword(password)
	u.PasswordSetAt = &now
	u.SessionsNotBefore = &now

	if generated {
		path := filepath.Join(s.opts.DataDir, "secrets", "initial-admin-password")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
			return fmt.Errorf("write initial admin password: %w", err)
		}
		s.log.Warn("bootstrap Super Admin created — sign in as 'admin' with the password stored in the file below, then change it and delete the file",
			"password_file", path)
	} else {
		s.log.Warn("bootstrap Super Admin 'admin' password set from AEGIS_BOOTSTRAP_ADMIN_PASSWORD")
	}
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "BOOTSTRAP_ADMIN", Category: "IDENTITY",
		EntityType: "user", EntityID: u.ID, EntityName: u.Username,
		Summary: "Bootstrap Super Admin credentials (re)initialized because no usable Super Admin account existed",
	})
	return nil
}

// ---------------------------------------------------------------------------
// Session revocation (implements auth.RevocationChecker)
// ---------------------------------------------------------------------------

func (s *Store) IsTokenRevoked(jti string) bool {
	s.mu.RLock()
	_, ok := s.revoked[jti]
	s.mu.RUnlock()
	return ok
}

func (s *Store) RevokeToken(jti string, exp time.Time) error {
	return s.withWrite(func() error {
		s.revoked[jti] = exp
		s.state.RevokedTokens = append(s.state.RevokedTokens, RevokedToken{JTI: jti, ExpiresAt: exp})
		s.markDirtyLocked()
		return nil
	})
}

func (s *Store) pruneRevokedLocked() {
	now := time.Now()
	kept := s.state.RevokedTokens[:0]
	for _, rt := range s.state.RevokedTokens {
		if now.Before(rt.ExpiresAt) {
			kept = append(kept, rt)
		} else {
			delete(s.revoked, rt.JTI)
		}
	}
	s.state.RevokedTokens = kept
}

// ---------------------------------------------------------------------------
// Read accessors
// ---------------------------------------------------------------------------

func (s *Store) GetRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Revision
}

// BundleGeneration increments whenever a data-plane-bundle input changes (policy, groups, servers,
// sessions, YARA, block pages, package config) but not on work-store churn (requests / assessments /
// jobs). The data-plane bundle handler caches the compiled bundle keyed on this, so an unchanged poll
// skips the full snapshot + rebuild. Time-based rule/session expiry is handled separately by the cache.
func (s *Store) BundleGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundleGen
}

// AccessRequests returns a copy of the access-request list (shallow per element, matching GetSnapshot),
// so the request list/detail endpoints need not clone the whole state snapshot just to read requests.
func (s *Store) AccessRequests() []models.AccessRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.AccessRequest(nil), s.state.Requests...)
}

// MetricCounts are the few fleet/queue counts the Prometheus endpoint needs, computed under one read
// lock without cloning the whole state (the scrape runs on an interval).
type MetricCounts struct {
	Revision           uint64
	Rules              int
	Servers            int
	PendingRequests    int
	OpenSecurityEvents int
}

// MetricCounts returns the gauge values for the metrics endpoint without a full GetSnapshot clone.
func (s *Store) MetricCounts() MetricCounts {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := MetricCounts{Revision: s.state.Revision, Rules: len(s.state.Rules), Servers: len(s.state.Servers)}
	for _, rq := range s.state.Requests {
		if rq.Status == "pending" {
			m.PendingRequests++
		}
	}
	for _, ev := range s.state.SecurityEvents {
		if !ev.Acknowledged {
			m.OpenSecurityEvents++
		}
	}
	return m
}

func (s *Store) GetUserByID(userID string) (*models.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.state.Users {
		if u.ID == userID {
			cp := u
			cp.AllowedGroups = append([]string(nil), u.AllowedGroups...)
			if u.SCIM != nil {
				sc := *u.SCIM
				sc.Emails = append([]models.SCIMEmail(nil), sc.Emails...)
				cp.SCIM = &sc
			}
			return &cp, true
		}
	}
	return nil, false
}

func (s *Store) SecurityPolicy() models.SecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePolicy(s.state.SecurityPolicy)
}

func clonePolicy(p models.SecurityPolicy) models.SecurityPolicy {
	p.DLPDetectors = append([]string(nil), p.DLPDetectors...)
	p.BlockedFileTypes = append([]string(nil), p.BlockedFileTypes...)
	p.AllowedPorts = append([]int(nil), p.AllowedPorts...)
	if p.GroupBlockedFileTypes != nil {
		m := make(map[string][]string, len(p.GroupBlockedFileTypes))
		for k, v := range p.GroupBlockedFileTypes {
			m[k] = append([]string(nil), v...)
		}
		p.GroupBlockedFileTypes = m
	}
	return p
}

// GetSnapshot returns a deep-enough copy of the state for read-only API use. Secrets
// (password hashes, feed auth headers) are redacted.
func (s *Store) GetSnapshot() StateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]models.PolicyRule, len(s.state.Rules))
	for i, r := range s.state.Rules {
		rules[i] = cloneRule(r)
	}
	sessions := make([]models.LearningSession, len(s.state.Sessions))
	for i, sess := range s.state.Sessions {
		sess.GroupIDs = append([]string(nil), sess.GroupIDs...)
		sess.CompiledCandidates = append([]models.CompiledRuleCandidate(nil), sess.CompiledCandidates...)
		sessions[i] = sess
	}
	audits := make([]models.AuditEvent, len(s.state.AuditEvents))
	for i, ev := range s.state.AuditEvents {
		ev.ScopeGroups = append([]string(nil), ev.ScopeGroups...)
		if ev.RollbackRule != nil {
			rb := cloneRule(*ev.RollbackRule)
			ev.RollbackRule = &rb
		}
		audits[i] = ev
	}
	users := make([]models.User, len(s.state.Users))
	for i, u := range s.state.Users {
		users[i] = u.Public()
	}
	feeds := make([]models.ThreatFeed, len(s.state.ThreatFeeds))
	for i, f := range s.state.ThreatFeeds {
		feeds[i] = f.Public()
	}
	servers := make([]models.Server, len(s.state.Servers))
	for i, srv := range s.state.Servers {
		servers[i] = cloneServer(srv)
	}
	sets := make([]models.PolicySet, len(s.state.PolicySets))
	for i, set := range s.state.PolicySets {
		sets[i] = s.decorateSetLocked(set)
	}
	pages := make([]models.BlockPageTemplate, len(s.state.BlockPages))
	for i, t := range s.state.BlockPages {
		pages[i] = cloneTemplate(t)
	}
	groups := make([]models.ServerGroup, len(s.state.Groups))
	for i, g := range s.state.Groups {
		groups[i] = cloneGroup(g)
	}

	return StateSnapshot{
		SchemaVersion:    s.state.SchemaVersion,
		Revision:         s.state.Revision,
		EntraConfig:      s.state.EntraConfig,
		NotifyConfig:     s.state.NotifyConfig,
		Users:            users,
		Groups:           groups,
		Servers:          servers,
		Rules:            rules,
		TLSBypass:        append([]models.TLSBypassRule(nil), s.state.TLSBypass...),
		Sessions:         sessions,
		Requests:         append([]models.AccessRequest(nil), s.state.Requests...),
		Flows:            append([]models.TrafficFlow(nil), s.state.Flows...),
		AuditEvents:      audits,
		SecurityPolicy:   clonePolicy(s.state.SecurityPolicy),
		ThreatFeeds:      feeds,
		Indicators:       append([]models.Indicator(nil), s.state.Indicators...),
		ThreatExceptions: append([]models.ThreatException(nil), s.state.ThreatExceptions...),
		SecurityEvents:   append([]models.SecurityEvent(nil), s.state.SecurityEvents...),
		PolicySets:       sets,
		ChangeRequests:   append([]models.ChangeRequest(nil), s.state.ChangeRequests...),
		Governance:       s.state.Governance,
		BlockPages:       pages,
		Packages:         clonePackageFirewall(s.state.Packages, true),
	}
}

func cloneRule(r models.PolicyRule) models.PolicyRule {
	r.Methods = append([]string(nil), r.Methods...)
	r.CompanionRules = append([]string(nil), r.CompanionRules...)
	r.RedirectHosts = append([]string(nil), r.RedirectHosts...)
	r.GroupIDs = append([]string(nil), r.GroupIDs...)
	r.ServerIDs = append([]string(nil), r.ServerIDs...)
	return r
}

// ThreatIntel exposes the threat-intel manager (may be nil in tests).
func (s *Store) ThreatIntel() *threatintel.Manager { return s.threat }

func (s *Store) DemoMode() bool { return s.opts.DemoMode }

// StorageName reports the active persistence backend.
func (s *Store) StorageName() string {
	if s.cluster != nil {
		return s.cluster.Name()
	}
	return "file"
}

// Ping checks that the persistence backend is reachable (readiness probe).
func (s *Store) Ping(ctx context.Context) error {
	if s.cluster == nil {
		return nil
	}
	_, err := s.cluster.StoredRevision(ctx)
	return err
}
