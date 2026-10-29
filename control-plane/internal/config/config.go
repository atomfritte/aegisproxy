// Package config loads and validates the control-plane configuration from the environment.
//
// Every secret can be supplied directly (AEGIS_X) or via a file (AEGIS_X_FILE, Docker/K8s secrets
// convention). Secrets that are not supplied are generated once and persisted with 0600 permissions
// under DATA_DIR/secrets so that restarts keep sessions and data-plane trust intact.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const minSecretLen = 32

// proxySecretChars may appear in AEGIS_TRUSTED_PROXY_SECRET: it is a header value in proxy configurations.
const proxySecretChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/="

type Config struct {
	ListenAddr string
	CertsDir   string
	DataDir    string
	UIDir      string
	// DocsURL is the base URL of the product documentation (the docs/ folder), used for links in
	// the console (security posture). Empty: links are shown as paths.
	DocsURL string

	// PublicURL is the externally reachable base URL of the control-plane (used in install
	// scripts, block pages and notification deep links). Never derived from the Host header.
	PublicURL    string
	DashboardURL string
	// ProxyAddress is the host:port servers use as their HTTP(S) proxy (onboarding snippets).
	ProxyAddress string

	TLSCertFile string
	TLSKeyFile  string

	JWTSecret []byte
	// EncryptionKey protects secrets stored in the configuration (AES-256-GCM); EncryptionKeyPrevious
	// can still decrypt values during a key rotation.
	EncryptionKey          string
	EncryptionKeyPrevious  string
	EncryptionKeyGenerated bool
	// EncryptionKeyInDataDir is true when the key is read from the data directory (the auto-generated
	// secrets/encryption.key, or an AEGIS_ENCRYPTION_KEY_FILE inside DATA_DIR): whoever can read the
	// data directory can then decrypt the secrets and the audit chain key stored there.
	EncryptionKeyInDataDir bool
	DataPlaneKey           string
	// DataPlaneKeyGenerated is true when the key was auto-generated (single-host / dev setups).
	DataPlaneKeyGenerated bool
	DataPlaneKeyPath      string

	SessionTTL time.Duration
	// ShutdownDelay keeps serving (with /readyz failing) after SIGTERM so load balancers and
	// Kubernetes endpoints stop routing new requests before the listener closes.
	ShutdownDelay  time.Duration
	CookieSecure   bool
	CookieSameSite http.SameSite
	CookieDomain   string

	// Storage selects the persistence backend: "file" (single node) or "postgres" (HA cluster).
	Storage        string
	DatabaseURL    string
	FlowRetention  time.Duration
	EventRetention time.Duration

	CORSOrigins    []string
	TrustedProxies []netip.Prefix
	// TrustedProxyHosts are DNS names (e.g. a headless Service of the console pods) whose current
	// addresses are trusted like TrustedProxies. Names with a dot are resolved as absolute names (never
	// below the DNS search domains); stored without the trailing dot.
	TrustedProxyHosts []string
	// TrustedProxySecret (AEGIS_TRUSTED_PROXY_SECRET) is sent by the trusted proxies in X-Aegis-Proxy-Auth.
	// When set, forwarding headers count only from trusted peers that send it: an address such as loopback
	// or a bridge gateway is shared by every local account, the secret only by the proxy.
	TrustedProxySecret string
	InternalSuffix     []string

	MetricsToken string

	DemoMode               bool
	BootstrapAdminPassword string

	ThreatIntelAutoUpdate bool
	FeedHTTPProxy         string

	AuditLogPath string
	// AuditRotateBytes rotates audit.jsonl by size inside the process (0 = external rotation only).
	AuditRotateBytes int64
	// AuditVerifyInterval: the complete audit trail is verified at start-up, at this interval and
	// after the audit log rotated.
	AuditVerifyInterval time.Duration
	// ExportDir is where "file" log export sinks write; ExportSpoolDir holds undelivered records.
	ExportDir      string
	ExportSpoolDir string
	LogFormat      string
	LogFile        string
	LogLevel       slog.Level
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if s := strings.TrimSpace(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// readSecret resolves KEY or KEY_FILE. It returns "" if neither is set.
func readSecret(key string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v, nil
	}
	if p := strings.TrimSpace(os.Getenv(key + "_FILE")); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// loadOrCreateSecret reads a persisted secret or creates a new random one (hex, 64 chars).
func loadOrCreateSecret(path string) (string, bool, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= minSecretLen {
			return s, false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	s := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
		return "", false, err
	}
	return s, true, nil
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:   ":" + env("CONTROL_PLANE_PORT", "8081"),
		CertsDir:     env("CERTS_DIR", filepath.Join("..", "certs")),
		DataDir:      env("DATA_DIR", "./data"),
		UIDir:        env("AEGIS_UI_DIR", ""),
		DocsURL:      env("AEGIS_DOCS_URL", ""),
		PublicURL:    strings.TrimRight(env("AEGIS_PUBLIC_URL", "http://localhost:8081"), "/"),
		DashboardURL: strings.TrimRight(env("AEGIS_DASHBOARD_URL", ""), "/"),
		TLSCertFile:  env("AEGIS_TLS_CERT_FILE", ""),
		TLSKeyFile:   env("AEGIS_TLS_KEY_FILE", ""),
		CORSOrigins:  splitList(env("AEGIS_CORS_ORIGINS", "")),
		InternalSuffix: splitList(env("AEGIS_INTERNAL_DOMAINS",
			".internal.corp,.local,.localdomain,.internal,.lan,.home.arpa,.corp")),
		DemoMode:              envBool("AEGIS_DEMO_MODE", false),
		ThreatIntelAutoUpdate: envBool("AEGIS_THREATINTEL_AUTOUPDATE", true),
		FeedHTTPProxy:         env("AEGIS_FEED_HTTP_PROXY", ""),
		LogFormat:             env("AEGIS_LOG_FORMAT", "json"),
		LogFile:               env("AEGIS_LOG_FILE", ""),
	}
	if addr := env("AEGIS_LISTEN_ADDR", ""); addr != "" {
		c.ListenAddr = addr
	}
	if c.DashboardURL == "" {
		c.DashboardURL = c.PublicURL
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("AEGIS_PUBLIC_URL must be an absolute http(s) URL, got %q", c.PublicURL)
	}
	c.ProxyAddress = env("AEGIS_PROXY_ADDRESS", net.JoinHostPort(u.Hostname(), "8080"))
	if _, _, err := net.SplitHostPort(c.ProxyAddress); err != nil {
		return nil, fmt.Errorf("AEGIS_PROXY_ADDRESS must be host:port, got %q", c.ProxyAddress)
	}
	c.CookieSecure = envBool("AEGIS_COOKIE_SECURE", strings.HasPrefix(c.PublicURL, "https://") || c.TLSCertFile != "")
	c.CookieDomain = env("AEGIS_COOKIE_DOMAIN", "")
	switch strings.ToLower(env("AEGIS_COOKIE_SAMESITE", "strict")) {
	case "strict":
		c.CookieSameSite = http.SameSiteStrictMode
	case "lax":
		c.CookieSameSite = http.SameSiteLaxMode
	case "none":
		// Only for consoles hosted on a different *site* than the API; requires HTTPS.
		c.CookieSameSite = http.SameSiteNoneMode
		if !c.CookieSecure {
			return nil, errors.New("AEGIS_COOKIE_SAMESITE=none requires HTTPS (AEGIS_COOKIE_SECURE=true)")
		}
	default:
		return nil, errors.New("AEGIS_COOKIE_SAMESITE must be strict, lax or none")
	}

	c.Storage = strings.ToLower(env("AEGIS_STORAGE", "file"))
	if c.Storage != "file" && c.Storage != "postgres" {
		return nil, fmt.Errorf("AEGIS_STORAGE must be 'file' or 'postgres', got %q", c.Storage)
	}
	for _, d := range []struct {
		key string
		def string
		dst *time.Duration
	}{{"AEGIS_FLOW_RETENTION", "168h", &c.FlowRetention}, {"AEGIS_EVENT_RETENTION", "2160h", &c.EventRetention}} {
		v, err := time.ParseDuration(env(d.key, d.def))
		if err != nil || v < time.Hour {
			return nil, fmt.Errorf("%s must be a duration of at least 1h", d.key)
		}
		*d.dst = v
	}

	switch strings.ToLower(env("AEGIS_LOG_LEVEL", "info")) {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "warn", "warning":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		c.LogLevel = slog.LevelInfo
	}

	ttl, err := time.ParseDuration(env("AEGIS_SESSION_TTL", "8h"))
	if err != nil || ttl < 5*time.Minute || ttl > 7*24*time.Hour {
		return nil, fmt.Errorf("AEGIS_SESSION_TTL must be a duration between 5m and 168h")
	}
	c.SessionTTL = ttl
	if c.ShutdownDelay, err = time.ParseDuration(env("AEGIS_SHUTDOWN_DELAY", "3s")); err != nil || c.ShutdownDelay < 0 || c.ShutdownDelay > 2*time.Minute {
		return nil, fmt.Errorf("AEGIS_SHUTDOWN_DELAY must be a duration between 0s and 2m")
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, errors.New("AEGIS_TLS_CERT_FILE and AEGIS_TLS_KEY_FILE must be set together")
	}

	for _, raw := range splitList(env("AEGIS_TRUSTED_PROXIES", "")) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("AEGIS_TRUSTED_PROXIES: invalid entry %q", raw)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}
	for _, h := range splitList(env("AEGIS_TRUSTED_PROXY_HOSTS", "")) {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !validProxyHost(h) {
			return nil, fmt.Errorf("AEGIS_TRUSTED_PROXY_HOSTS: invalid host name %q", h)
		}
		c.TrustedProxyHosts = append(c.TrustedProxyHosts, h)
	}
	if c.TrustedProxySecret, err = readSecret("AEGIS_TRUSTED_PROXY_SECRET"); err != nil {
		return nil, err
	}
	if s := c.TrustedProxySecret; s != "" && (len(s) < minSecretLen || strings.Trim(s, proxySecretChars) != "" || isKnownLeakedSecret(s)) {
		return nil, fmt.Errorf("AEGIS_TRUSTED_PROXY_SECRET must be at least %d characters of letters, digits and -._~+/= (openssl rand -hex 32)", minSecretLen)
	}
	for i, s := range c.InternalSuffix {
		s = strings.ToLower(s)
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		c.InternalSuffix[i] = s
	}

	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("DATA_DIR: %w", err)
	}
	secretsDir := filepath.Join(c.DataDir, "secrets")

	clustered := c.Storage == "postgres"
	if clustered {
		if c.DatabaseURL, err = readSecret("AEGIS_DATABASE_URL"); err != nil {
			return nil, err
		}
		if c.DatabaseURL == "" {
			return nil, errors.New("AEGIS_STORAGE=postgres requires AEGIS_DATABASE_URL (or AEGIS_DATABASE_URL_FILE)")
		}
	}

	// JWT signing secret
	jwt, err := readSecret("AEGIS_JWT_SECRET")
	if err != nil {
		return nil, err
	}
	if jwt == "" && clustered {
		return nil, errors.New("AEGIS_JWT_SECRET must be set explicitly (and identical on every replica) when AEGIS_STORAGE=postgres")
	}
	if jwt == "" {
		jwt, _, err = loadOrCreateSecret(filepath.Join(secretsDir, "jwt.key"))
		if err != nil {
			return nil, fmt.Errorf("generate JWT secret: %w", err)
		}
	}
	if len(jwt) < minSecretLen {
		return nil, fmt.Errorf("AEGIS_JWT_SECRET must be at least %d characters", minSecretLen)
	}
	if isKnownLeakedSecret(jwt) {
		return nil, errors.New("AEGIS_JWT_SECRET uses a publicly known default value; generate a new one (openssl rand -hex 32)")
	}
	c.JWTSecret = []byte(jwt)

	// Shared data-plane key (authenticates mitmproxy workers and signs block tokens)
	dpk, err := readSecret("AEGIS_DATAPLANE_KEY")
	if err != nil {
		return nil, err
	}
	if dpk == "" && clustered {
		return nil, errors.New("AEGIS_DATAPLANE_KEY must be set explicitly (and identical on every replica and worker) when AEGIS_STORAGE=postgres")
	}
	if dpk == "" {
		c.DataPlaneKeyPath = filepath.Join(secretsDir, "dataplane.key")
		dpk, c.DataPlaneKeyGenerated, err = loadOrCreateSecret(c.DataPlaneKeyPath)
		if err != nil {
			return nil, fmt.Errorf("generate data-plane key: %w", err)
		}
	}
	if len(dpk) < minSecretLen {
		return nil, fmt.Errorf("AEGIS_DATAPLANE_KEY must be at least %d characters", minSecretLen)
	}
	if isKnownLeakedSecret(dpk) {
		return nil, errors.New("AEGIS_DATAPLANE_KEY uses a publicly known default value; generate a new one (openssl rand -hex 32)")
	}
	c.DataPlaneKey = dpk

	// Encryption key for secrets at rest (feed API keys, export credentials, SSO/Defender secrets, webhooks)
	if c.EncryptionKey, err = readSecret("AEGIS_ENCRYPTION_KEY"); err != nil {
		return nil, err
	}
	if c.EncryptionKey == "" && clustered {
		return nil, errors.New("AEGIS_ENCRYPTION_KEY must be set explicitly (and identical on every replica) when AEGIS_STORAGE=postgres; it encrypts stored secrets (openssl rand -hex 32)")
	}
	if c.EncryptionKey == "" {
		c.EncryptionKey, c.EncryptionKeyGenerated, err = loadOrCreateSecret(filepath.Join(secretsDir, "encryption.key"))
		if err != nil {
			return nil, fmt.Errorf("generate encryption key: %w", err)
		}
		c.EncryptionKeyInDataDir = true
	} else if p := strings.TrimSpace(os.Getenv("AEGIS_ENCRYPTION_KEY_FILE")); p != "" && strings.TrimSpace(os.Getenv("AEGIS_ENCRYPTION_KEY")) == "" {
		c.EncryptionKeyInDataDir = pathInside(p, c.DataDir)
	}
	if c.EncryptionKeyInDataDir {
		slog.Warn("the encryption key for secrets at rest is stored in the data directory: anyone who can read DATA_DIR can decrypt the stored secrets and the audit chain key; provide AEGIS_ENCRYPTION_KEY or AEGIS_ENCRYPTION_KEY_FILE from a secret store outside DATA_DIR",
			"data_dir", c.DataDir)
	}
	if len(c.EncryptionKey) < minSecretLen || isKnownLeakedSecret(c.EncryptionKey) {
		return nil, fmt.Errorf("AEGIS_ENCRYPTION_KEY must be a random secret of at least %d characters", minSecretLen)
	}
	if c.EncryptionKeyPrevious, err = readSecret("AEGIS_ENCRYPTION_KEY_PREVIOUS"); err != nil {
		return nil, err
	}
	if c.EncryptionKey == jwt || c.EncryptionKey == dpk {
		return nil, errors.New("AEGIS_ENCRYPTION_KEY must differ from AEGIS_JWT_SECRET and AEGIS_DATAPLANE_KEY")
	}

	if c.MetricsToken, err = readSecret("AEGIS_METRICS_TOKEN"); err != nil {
		return nil, err
	}
	if c.BootstrapAdminPassword, err = readSecret("AEGIS_BOOTSTRAP_ADMIN_PASSWORD"); err != nil {
		return nil, err
	}

	c.AuditLogPath = env("AEGIS_AUDIT_LOG", filepath.Join(c.DataDir, "audit.jsonl"))
	rotateMB, err := strconv.Atoi(env("AEGIS_AUDIT_ROTATE_MB", "256"))
	if err != nil || rotateMB < 0 || rotateMB > 1<<20 {
		return nil, errors.New("AEGIS_AUDIT_ROTATE_MB must be a number of megabytes between 0 (off) and 1048576")
	}
	c.AuditRotateBytes = int64(rotateMB) << 20
	if c.AuditVerifyInterval, err = time.ParseDuration(env("AEGIS_AUDIT_VERIFY_INTERVAL", "6h")); err != nil || c.AuditVerifyInterval < time.Minute || c.AuditVerifyInterval > 7*24*time.Hour {
		return nil, errors.New("AEGIS_AUDIT_VERIFY_INTERVAL must be a duration between 1m and 168h")
	}
	c.ExportDir = env("AEGIS_EXPORT_DIR", filepath.Join(c.DataDir, "export"))
	c.ExportSpoolDir = env("AEGIS_EXPORT_SPOOL_DIR", filepath.Join(c.DataDir, "export-spool"))
	return c, nil
}

// pathInside reports whether path lies in dir (after resolving symbolic links where possible).
func pathInside(path, dir string) bool {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		return p
	}
	rel, err := filepath.Rel(resolve(dir), resolve(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// validProxyHost accepts DNS host names (letters, digits, hyphens, dots), no addresses or ports.
func validProxyHost(h string) bool {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// isKnownLeakedSecret rejects the hard-coded defaults shipped by earlier releases.
func isKnownLeakedSecret(s string) bool {
	switch s {
	case "aegis-enterprise-super-secret-jwt-key-2026", "aegis-dp-internal-key-2026-v1":
		return true
	}
	return false
}
