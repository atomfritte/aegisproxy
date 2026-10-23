package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/ca"
	"aegisproxy/control-plane/internal/config"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/notify"
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/store"
)

type Deps struct {
	Store    *store.Store
	Auth     *auth.AuthManager
	CA       *ca.CAManager
	Notifier *notify.Dispatcher
	Config   *config.Config
	Logger   *slog.Logger
	Version  string
	Exporter *export.Manager
}

type Server struct {
	exporter *export.Manager
	store    *store.Store
	authMgr  *auth.AuthManager
	caMgr    *ca.CAManager
	notifier *notify.Dispatcher
	cfg      *config.Config
	log      *slog.Logger
	version  string
	started  time.Time

	mux          *http.ServeMux
	handler      http.Handler
	metrics      *Metrics
	loginLimiter *auth.LoginLimiter
	publicLimit  *rateLimiter
	caLimit      *rateLimiter

	sseMu      sync.Mutex
	sseClients int
	ssePerUser map[string]int

	draining atomic.Bool

	dpMu       sync.Mutex
	dataPlanes map[string]*DataPlaneStatus

	sso ssoProviders

	bpMu    sync.Mutex
	bpRev   uint64
	bpCache map[string]any
}

// DataPlaneStatus is the last heartbeat of a mitmproxy worker (reported on bundle sync).
type DataPlaneStatus struct {
	ID              string    `json:"id"`
	Version         string    `json:"version"`
	RemoteIP        string    `json:"remote_ip"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	BundleRevision  string    `json:"bundle_revision"`
	ThreatVersion   string    `json:"threat_intel_version"`
	ClamAVAvailable string    `json:"clamav_available"`
	YARAStatus      string    `json:"yara_status"`
	ICAPStatus      string    `json:"icap_status"`
	Healthy         bool      `json:"healthy"`
}

func NewServer(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := &Server{
		store:        d.Store,
		exporter:     d.Exporter,
		authMgr:      d.Auth,
		caMgr:        d.CA,
		notifier:     d.Notifier,
		cfg:          d.Config,
		log:          d.Logger.With("component", "api"),
		version:      d.Version,
		started:      time.Now(),
		mux:          http.NewServeMux(),
		metrics:      NewMetrics(),
		loginLimiter: auth.NewLoginLimiter(),
		publicLimit:  newRateLimiter(20, time.Minute),
		caLimit:      newRateLimiter(120, time.Minute),
		dataPlanes:   make(map[string]*DataPlaneStatus),
		ssePerUser:   make(map[string]int),
	}
	s.routes()
	s.handler = s.middleware(http.HandlerFunc(s.serveMux))
	return s
}

// SetDraining makes /readyz fail so that traffic is routed away before shutdown.
func (s *Server) SetDraining() { s.draining.Store(true) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// serveMux dispatches to the router; unknown API routes and wrong methods get the same JSON error
// body as every other API error instead of the router's plain-text reply.
func (s *Server) serveMux(w http.ResponseWriter, r *http.Request) {
	h, pattern := s.mux.Handler(r)
	isSCIM := r.URL.Path == scimPrefix || strings.HasPrefix(r.URL.Path, scimPrefix+"/")
	if (pattern != "" && !(isSCIM && pattern == "GET /")) || !strings.HasPrefix(r.URL.Path, "/api/") {
		s.mux.ServeHTTP(w, r)
		return
	}
	if pattern == "GET /" { // SCIM path that only the console catch-all matches
		scimNotFound(w, r, http.StatusNotFound)
		return
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if allow := rec.Header().Get("Allow"); allow != "" {
		w.Header().Set("Allow", allow)
	}
	if rec.Code == http.StatusMethodNotAllowed {
		// Only the console catch-all ("GET /") matches this path for another method: not an API route.
		probe := r.Clone(r.Context())
		probe.Method = http.MethodGet
		if _, p := s.mux.Handler(probe); p == "GET /" {
			w.Header().Del("Allow")
			rec.Code = http.StatusNotFound
		}
	}
	if isSCIM {
		scimNotFound(w, r, rec.Code) // SCIM clients expect SCIM error documents
		return
	}
	switch rec.Code {
	case http.StatusMethodNotAllowed:
		writeError(w, http.StatusMethodNotAllowed, "method "+r.Method+" is not allowed for "+r.URL.Path)
	default:
		writeError(w, http.StatusNotFound, "no API endpoint "+r.URL.Path)
	}
}

func (s *Server) routes() {
	// Operational endpoints
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Unauthenticated public endpoints (CA trust bootstrap & self-service block portal)
	s.mux.HandleFunc("GET /api/public/meta", s.handlePublicMeta)
	s.mux.HandleFunc("GET /api/openapi.yaml", s.handleOpenAPI)
	s.mux.HandleFunc("GET /api/public/ca/info", s.handlePublicCAInfo)
	s.mux.HandleFunc("GET /api/public/ca/aegis-ca.crt", s.handlePublicCACertPEM)
	s.mux.HandleFunc("GET /api/public/ca/aegis-ca.pem", s.handlePublicCACertPEM)
	s.mux.HandleFunc("GET /api/public/ca/aegis-ca.der", s.handlePublicCACertDER)
	s.mux.HandleFunc("GET /api/public/ca/install-linux.sh", s.handlePublicLinuxInstallScript)
	s.mux.HandleFunc("GET /api/public/ca/install-windows.ps1", s.handlePublicWindowsInstallScript)
	s.mux.HandleFunc("POST /api/public/requests", s.handlePublicCreateRequest)
	s.mux.HandleFunc("GET /api/public/request-options", s.handlePublicRequestOptions)
	s.mux.HandleFunc("OPTIONS /api/public/requests", s.handlePublicPreflight)

	// Data-plane worker API (X-Aegis-DataPlane-Key)
	s.mux.HandleFunc("GET /api/dataplane/bundle", s.dataPlaneOnly(s.handleDataPlaneBundle))
	s.mux.HandleFunc("GET /api/dataplane/threatintel", s.dataPlaneOnly(s.handleDataPlaneThreatIntel))
	s.mux.HandleFunc("POST /api/dataplane/evaluate", s.dataPlaneOnly(s.handleDataPlaneEvaluate))
	s.mux.HandleFunc("POST /api/dataplane/flows", s.dataPlaneOnly(s.handleDataPlaneRecordFlow))
	s.mux.HandleFunc("POST /api/dataplane/flows/batch", s.dataPlaneOnly(s.handleDataPlaneRecordFlowBatch))

	// Authentication
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.authed(s.handleAuthMe))
	s.mux.HandleFunc("POST /api/auth/password", s.authed(s.handleChangePassword))

	// Console API
	s.mux.HandleFunc("GET /api/state", s.authed(s.handleGetState))
	s.mux.HandleFunc("GET /api/flows/stream", s.authed(s.handleFlowStream))
	s.mux.HandleFunc("POST /api/requests/{id}/review", s.authed(s.handleReviewRequest))
	s.mux.HandleFunc("POST /api/sessions", s.authed(s.handleStartSession))
	s.mux.HandleFunc("POST /api/sessions/{id}/stop", s.authed(s.handleStopSession))
	s.mux.HandleFunc("POST /api/sessions/{id}/publish", s.authed(s.handlePublishSession))
	s.mux.HandleFunc("POST /api/sessions/{id}/simulate", s.authed(s.handleSimulateSessionFlows))
	s.mux.HandleFunc("POST /api/tls-bypass", s.authed(s.handleAddTLSBypass))
	s.mux.HandleFunc("POST /api/tls-bypass/{id}/toggle", s.authed(s.handleToggleTLSBypass))
	s.mux.HandleFunc("DELETE /api/tls-bypass/{id}", s.authed(s.handleDeleteTLSBypass))
	s.mux.HandleFunc("POST /api/settings/entra", s.authed(s.handleUpdateEntra))
	s.mux.HandleFunc("POST /api/settings/notifications", s.authed(s.handleUpdateNotifications))
	s.mux.HandleFunc("POST /api/settings/notifications/test", s.authed(s.handleTestNotification))
	s.mux.HandleFunc("POST /api/simulate/request", s.authed(s.handleSimulateProxyRequest))
	s.mux.HandleFunc("GET /api/audit/verify", s.authed(s.handleVerifyAudit))
	s.mux.HandleFunc("GET /api/audit/export", s.authed(s.handleExportAudit))

	// Identity administration
	s.mux.HandleFunc("POST /api/users", s.authed(s.handleUpsertUser))
	s.mux.HandleFunc("DELETE /api/users/{id}", s.authed(s.handleDeleteUser))
	s.mux.HandleFunc("POST /api/users/{id}/reset-password", s.authed(s.handleResetPassword))

	// Fleet inventory
	s.mux.HandleFunc("POST /api/groups", s.authed(s.handleUpsertGroup))
	s.mux.HandleFunc("DELETE /api/groups/{id}", s.authed(s.handleDeleteGroup))
	s.mux.HandleFunc("POST /api/servers", s.authed(s.handleUpsertServer))
	s.mux.HandleFunc("DELETE /api/servers/{id}", s.authed(s.handleDeleteServer))
	s.mux.HandleFunc("POST /api/servers/{id}/rotate-token", s.authed(s.handleRotateToken))

	// Threat protection
	s.mux.HandleFunc("POST /api/security/policy", s.authed(s.handleUpdateSecurityPolicy))
	s.mux.HandleFunc("POST /api/security/feeds", s.authed(s.handleUpsertFeed))
	s.mux.HandleFunc("DELETE /api/security/feeds/{id}", s.authed(s.handleDeleteFeed))
	s.mux.HandleFunc("POST /api/security/feeds/refresh", s.authed(s.handleRefreshFeeds))
	s.mux.HandleFunc("POST /api/security/indicators", s.authed(s.handleAddIndicator))
	s.mux.HandleFunc("DELETE /api/security/indicators/{id}", s.authed(s.handleDeleteIndicator))
	s.mux.HandleFunc("POST /api/security/exceptions", s.authed(s.handleAddException))
	s.mux.HandleFunc("DELETE /api/security/exceptions/{id}", s.authed(s.handleDeleteException))
	s.mux.HandleFunc("POST /api/security/events/{id}/ack", s.authed(s.handleAckEvent))
	s.mux.HandleFunc("POST /api/security/lookup", s.authed(s.handleThreatLookup))
	s.mux.HandleFunc("GET /api/security/yara", s.authed(s.handleListYara))
	s.mux.HandleFunc("POST /api/security/yara", s.authed(s.handleSaveYara))
	s.mux.HandleFunc("PUT /api/security/yara/{id}", s.authed(s.handleSaveYara))
	s.mux.HandleFunc("DELETE /api/security/yara/{id}", s.authed(s.handleDeleteYara))

	s.policyRoutes()
	s.serviceAccountRoutes()
	s.ssoRoutes()
	s.scimRoutes()
	s.defenderRoutes()
	s.mux.HandleFunc("GET /api/system/posture", s.authed(s.handlePosture))

	// Log export (SIEM / observability)
	s.mux.HandleFunc("GET /api/integrations/exports", s.authed(s.handleListExports))
	s.mux.HandleFunc("POST /api/integrations/exports", s.authed(s.handleSaveExport))
	s.mux.HandleFunc("PUT /api/integrations/exports/{id}", s.authed(s.handleSaveExport))
	s.mux.HandleFunc("DELETE /api/integrations/exports/{id}", s.authed(s.handleDeleteExport))
	s.mux.HandleFunc("POST /api/integrations/exports/test", s.authed(s.handleTestExport))

	// Bundled web console (production builds)
	s.mountUI()
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeStoreError maps domain errors onto HTTP status codes.
func writeStoreError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "RBAC"):
		writeError(w, http.StatusForbidden, msg)
	case errors.Is(err, store.ErrSessionRecording):
		writeError(w, http.StatusConflict, msg)
	case strings.Contains(msg, "not found"):
		writeError(w, http.StatusNotFound, msg)
	case strings.Contains(msg, "already"):
		writeError(w, http.StatusConflict, msg)
	default:
		writeError(w, http.StatusBadRequest, msg)
	}
}

// decodeJSON parses a JSON request body (size already limited by middleware).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	if err := jsonDecode(r, v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		case errors.Is(err, io.EOF):
			writeError(w, http.StatusBadRequest, "request body is empty")
		case errors.Is(err, errSealedInput):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusBadRequest, "invalid JSON payload")
		}
		return false
	}
	return true
}

var errSealedInput = errors.New("encrypted values (enc:v1:…) cannot be submitted; enter the secret in plain text")

// jsonDecode parses a request body. Sealed values are only ever read from storage: a ciphertext in
// API input (for example copied from a backup) would otherwise be decrypted by the server and could
// then be sent to a destination of the caller's choice.
func jsonDecode(r *http.Request, v any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return io.EOF
	}
	// Data-plane payloads carry attacker-controlled traffic fields and no secrets: not checked, so a
	// crafted User-Agent cannot make the control-plane drop flow records.
	if !strings.HasPrefix(r.URL.Path, "/api/dataplane/") {
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return err
		}
		if containsSealed(generic) {
			return errSealedInput
		}
	}
	return json.Unmarshal(raw, v)
}

func containsSealed(v any) bool {
	switch t := v.(type) {
	case string:
		return sealed.IsSealed(t)
	case []any:
		for _, e := range t {
			if containsSealed(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if containsSealed(e) {
				return true
			}
		}
	}
	return false
}
