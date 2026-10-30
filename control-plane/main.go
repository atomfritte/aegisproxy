package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"aegisproxy/control-plane/internal/api"
	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/ca"
	"aegisproxy/control-plane/internal/config"
	"aegisproxy/control-plane/internal/coordinator"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages"
	"aegisproxy/control-plane/internal/notify"
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/store"
	"aegisproxy/control-plane/internal/threatintel"
)

// Version is overridden at build time: -ldflags "-X main.Version=..."
var Version = "2.1.0-dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			endpoint := "healthz"
			if len(os.Args) > 2 && os.Args[2] == "readyz" {
				endpoint = "readyz"
			}
			os.Exit(healthcheck(endpoint))
		case "version":
			fmt.Println(Version)
			return
		case "gen-ca":
			os.Exit(genCA(os.Args[2:]))
		case "gen-csr":
			os.Exit(genCSR(os.Args[2:]))
		case "import-ca":
			os.Exit(importCA(os.Args[2:]))
		case "sandbox-worker":
			os.Exit(runSandboxWorker())
		case "service":
			// Windows service entry point (ImagePath "aegis-control-plane.exe service").
			if _, err := runAsWindowsService(run, true); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "-h", "--help", "help":
			fmt.Println("usage: aegis-control-plane [service | sandbox-worker | healthcheck [healthz|readyz] | version | gen-ca <certs-dir> [public-cert-dir] | gen-csr <certs-dir> <subject> | import-ca <certs-dir> <cert.pem> [chain.pem]]\n\nConfiguration is read from AEGIS_* environment variables (see docs/configuration.md).")
			return
		}
	}
	// Started by the Windows Service Control Manager without the "service" argument (older installations).
	if handled, err := runAsWindowsService(run, false); handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// genCA pre-provisions the enterprise root CA (needed for clustered / Kubernetes deployments where
// the certificate is distributed as a secret instead of being generated on first start).
// With a second directory it also writes the public certificate files there (no key), for components
// that only publish the CA, such as the control-plane in docker compose.
func genCA(args []string) int {
	if len(args) != 1 && len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aegis-control-plane gen-ca <certs-dir> [public-cert-dir]")
		return 2
	}
	m, err := ca.NewCAManager(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Root CA ready in %s\n  subject:     %s\n  not after:   %s\n  fingerprint: %s\n", args[0], m.Subject, m.NotAfter.Format(time.RFC3339), m.Fingerprint)
	fmt.Println("Files: mitmproxy-ca.pem (KEY + cert, keep secret!), mitmproxy-ca-cert.pem, aegis-enterprise-ca.crt, aegis-enterprise-ca.der")
	if len(args) == 2 {
		if err := m.WritePublic(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Public certificate (no key) in %s\n", args[1])
	}
	return 0
}

// healthcheck is used by the container HEALTHCHECK (distroless images have no curl/wget).
// healthcheck probes the local API (healthz = alive, readyz = storage reachable and serving).
func healthcheck(endpoint string) int {
	port := os.Getenv("CONTROL_PLANE_PORT")
	if port == "" {
		port = "8081"
	}
	scheme := "http"
	if os.Getenv("AEGIS_TLS_CERT_FILE") != "" {
		scheme = "https"
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback liveness probe only
	}}
	resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%s/%s", scheme, port, endpoint))
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func newLogger(cfg *config.Config) (*slog.Logger, func(), error) {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var out io.Writer = os.Stdout
	closeFn := func() {}
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o700); err != nil {
			return nil, nil, fmt.Errorf("AEGIS_LOG_FILE: %w", err)
		}
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("AEGIS_LOG_FILE: %w", err)
		}
		out, closeFn = f, func() { _ = f.Close() }
	}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(out, opts)), closeFn, nil
	}
	return slog.New(slog.NewJSONHandler(out, opts)), closeFn, nil
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	baseLogger, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()
	logger := baseLogger.With("service", "aegis-control-plane", "version", Version)
	slog.SetDefault(logger)
	engine.SetInternalSuffixes(cfg.InternalSuffix)

	if cfg.DataPlaneKeyGenerated {
		logger.Warn("AEGIS_DATAPLANE_KEY not set: generated a new data-plane key. Provide the same key to every mitmproxy worker (AEGIS_DATAPLANE_KEY or AEGIS_DATAPLANE_KEY_FILE).",
			"key_file", cfg.DataPlaneKeyPath)
	}
	if !cfg.CookieSecure {
		logger.Warn("session cookies are not marked Secure (AEGIS_PUBLIC_URL is http://). Serve the console over HTTPS in production.")
	}

	caMgr, err := ca.NewCAManager(cfg.CertsDir)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	logger.Info("enterprise root CA ready", "subject", caMgr.Subject, "fingerprint_sha256", caMgr.Fingerprint, "not_after", caMgr.NotAfter)

	if err := configureSealing(cfg); err != nil {
		return err
	}
	logger.Info("secrets at rest are encrypted", "algorithm", "AES-256-GCM", "key_id", sealed.KeyID(),
		"previous_key", cfg.EncryptionKeyPrevious != "", "generated", cfg.EncryptionKeyGenerated)

	auditSink, err := store.NewAuditSink(cfg.AuditLogPath, logger)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	auditSink.RotateAtSize(cfg.AuditRotateBytes)
	defer auditSink.Close()

	notifier := notify.NewDispatcher(models.NotificationConfig{DashboardBaseURL: cfg.DashboardURL}, logger)
	ti, err := threatintel.NewManager(threatintel.Options{
		CacheDir:   filepath.Join(cfg.DataDir, "threatintel"),
		AutoUpdate: cfg.ThreatIntelAutoUpdate,
		HTTPProxy:  cfg.FeedHTTPProxy,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("threat intelligence: %w", err)
	}

	var cluster store.ClusterBackend
	if cfg.Storage == "postgres" {
		pg, err := connectPostgres(ctx, cfg.DatabaseURL, logger)
		if err != nil {
			return fmt.Errorf("cluster storage: %w", err)
		}
		defer pg.Close()
		cluster = pg
		logger.Info("using PostgreSQL cluster storage (active-active)", "node", pg.NodeID())
	} else {
		logger.Info("using single-node file storage", "data_dir", cfg.DataDir)
	}

	hostname, _ := os.Hostname()
	nodeID := hostname
	if pg, ok := cluster.(interface{ NodeID() string }); ok && cluster != nil {
		nodeID = pg.NodeID()
	}
	hecAckAttempts := 0
	if v := os.Getenv("AEGIS_EXPORT_HEC_ACK_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hecAckAttempts = n
		} else {
			logger.Warn("ignoring invalid AEGIS_EXPORT_HEC_ACK_ATTEMPTS (positive number expected)", "value", v)
		}
	}
	exporter := export.New(export.Options{SpoolDir: cfg.ExportSpoolDir, ExportDir: cfg.ExportDir, Node: nodeID,
		Host: hostname, Version: Version, Logger: logger, AuditReplay: true, HECAckAttempts: hecAckAttempts})
	defer exporter.Close() // runs after the store has been closed (LIFO): queued records go to the spool

	st, err := store.NewStore(store.Options{
		Cluster:                cluster,
		FlowRetention:          cfg.FlowRetention,
		EventRetention:         cfg.EventRetention,
		AuditVerifyInterval:    cfg.AuditVerifyInterval,
		DataDir:                cfg.DataDir,
		DemoMode:               cfg.DemoMode,
		BootstrapAdminPassword: cfg.BootstrapAdminPassword,
		DashboardURL:           cfg.DashboardURL,
		Engine:                 engine.NewPolicyEngine(),
		Notifier:               notifier,
		ThreatIntel:            ti,
		AuditSink:              auditSink,
		Exporter:               exporter,
		Logger:                 logger,
	})
	if err != nil {
		return fmt.Errorf("state store: %w", err)
	}
	defer st.Close()
	// Sinks replay audit records a crash may have lost from this node's audit trail and raise
	// delivery alerts as security events (the store attached its alert handler when it started the
	// sinks); both are detached before the store closes.
	exporter.SetAuditSource(st)
	defer exporter.SetAuditSource(nil)
	defer exporter.SetAlertHandler(nil)

	authMgr := auth.NewAuthManager(cfg.JWTSecret, cfg.SessionTTL)
	authMgr.SetRevocationChecker(st)

	// Package firewall (3.0): the registry/resolution/assessment service, the raw-report store and the
	// coordinator that drives request resolution, analysis and the re-audit / watch loops.
	pkgSvc := packages.NewService(packages.Options{
		HTTPProxy: cfg.PackageHTTPProxy,
		Settings:  func() models.PackageSettings { return st.PackageFirewall().Settings },
		Verifier:  packages.NewRegistryVerifier(cfg.PackageHTTPProxy, logger),
		Logger:    logger,
	})
	reportStore, err := packages.NewReportStore(filepath.Join(cfg.DataDir, "packages", "reports"))
	if err != nil {
		return fmt.Errorf("package report store: %w", err)
	}
	pkgCoord := coordinator.New(st, pkgSvc, reportStore, logger)
	pkgCoord.SetNotifier(notifier) // re-audit alerts to the configured Slack / Teams / webhook channels
	pkgCoord.Start()
	defer pkgCoord.Close()

	srv := api.NewServer(api.Deps{
		Store: st, Auth: authMgr, CA: caMgr, Notifier: notifier, Config: cfg, Logger: logger, Version: Version, Exporter: exporter,
		Packages: pkgCoord, PackageSvc: pkgSvc, PackageRepo: reportStore,
	})

	go ti.Run(ctx)
	if cfg.DemoMode {
		go runDemoTraffic(ctx, st)
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // SSE handlers lift this per response
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("control-plane API listening", "addr", cfg.ListenAddr, "public_url", cfg.PublicURL,
			"tls", cfg.TLSCertFile != "", "demo_mode", cfg.DemoMode)
		var err error
		if cfg.TLSCertFile != "" {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	case <-ctx.Done():
		srv.SetDraining()
		logger.Info("shutdown signal received; failing readiness and draining", "delay", cfg.ShutdownDelay.String())
		time.Sleep(cfg.ShutdownDelay)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown incomplete", "error", err)
	}
	st.Close()
	logger.Info("control-plane stopped, state flushed to disk")
	return nil
}

// connectPostgres waits for the database with exponential backoff (up to 5 minutes), so replicas
// can start before the database cluster is ready (e.g. during a fresh Kubernetes rollout).
func connectPostgres(ctx context.Context, dsn string, logger *slog.Logger) (*store.PostgresBackend, error) {
	deadline := time.Now().Add(5 * time.Minute)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		pg, err := store.NewPostgresBackend(ctx, dsn, logger)
		if err == nil {
			return pg, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, err
		}
		logger.Warn("PostgreSQL not reachable yet, retrying", "attempt", attempt, "retry_in", delay.String(), "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 20*time.Second)
	}
}

// runDemoTraffic generates synthetic flows so the demo dashboard is lively (AEGIS_DEMO_MODE only).
func runDemoTraffic(ctx context.Context, st *store.Store) {
	samples := []struct{ ip, user, method, url, host, path, ua string }{
		{"10.20.1.15", "svc-ci-runner-02", "GET", "https://github.com/microsoft/vscode/info/refs?service=git-upload-pack", "github.com", "/microsoft/vscode/info/refs", "git/2.43.0"},
		{"10.10.4.104", "svc-k8s-node-104", "GET", "https://registry-1.docker.io/v2/library/alpine/manifests/3.20", "registry-1.docker.io", "/v2/library/alpine/manifests/3.20", "containerd/1.7.22"},
		{"10.20.1.15", "svc-ci-runner-02", "GET", "https://github.com/openai/whisper/archive/refs/heads/main.zip", "github.com", "/openai/whisper/archive/refs/heads/main.zip", "curl/8.5.0"},
		{"10.30.12.55", "svc-billing-312", "GET", "https://security.ubuntu.com/ubuntu/dists/noble-security/InRelease", "security.ubuntu.com", "/ubuntu/dists/noble-security/InRelease", "APT-HTTP/1.3 (2.7.14)"},
		{"10.40.8.19", "svc-win-erp-09", "CONNECT", "https://fe2cr.update.microsoft.com.windowsupdate.com/", "fe2cr.update.microsoft.com.windowsupdate.com", "/", "Windows-Update-Agent/10.0"},
		{"10.50.2.14", "svc-ai-gpu-04", "GET", "https://huggingface.co/meta-llama/Llama-3.2-11B-Vision/resolve/main/config.json", "huggingface.co", "/meta-llama/Llama-3.2-11B-Vision/resolve/main/config.json", "huggingface_hub/0.25.1"},
		{"10.60.1.10", "svc-vault-01", "GET", "https://raw.githubusercontent.com/unknown-actor/exfil-script/main/install.sh", "raw.githubusercontent.com", "/unknown-actor/exfil-script/main/install.sh", "curl/7.88.1"},
	}
	ticker := time.NewTicker(6 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pick := samples[rand.IntN(len(samples))]
		res := st.Evaluate(engine.EvaluationRequest{
			ServerIP: pick.ip, ProxyAuthUser: pick.user, Method: pick.method, Scheme: "https",
			Host: pick.host, Path: pick.path, FullURL: pick.url, UserAgent: pick.ua,
		})
		status := 200
		if !res.Allowed {
			status = 403
		}
		st.RecordFlow(models.TrafficFlow{
			ServerIP: pick.ip, ServerID: res.ServerID, ServerHostname: res.ServerHostname, GroupIDs: res.GroupIDs,
			ProxyAuthUser: pick.user, Method: pick.method, Scheme: "https", Host: pick.host, Path: pick.path,
			FullURL: pick.url, UserAgent: pick.ua, Verdict: res.Verdict, MatchedRuleID: res.MatchedRuleID,
			MatchedRuleName: res.MatchedRuleName, StatusCode: status, LatencyMs: int64(8 + rand.IntN(75)),
			TLSIntercepted: !res.TLSBypass, SessionID: res.SessionID, BlockReason: res.BlockReason,
			ThreatCategory: res.ThreatCategory, ThreatSource: res.ThreatSource, ThreatIndicator: res.ThreatIndicator,
		})
	}
}

func configureSealing(cfg *config.Config) error {
	cur, err := sealed.DeriveKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("AEGIS_ENCRYPTION_KEY: %w", err)
	}
	var prev [][]byte
	if cfg.EncryptionKeyPrevious != "" {
		p, err := sealed.DeriveKey(cfg.EncryptionKeyPrevious)
		if err != nil {
			return fmt.Errorf("AEGIS_ENCRYPTION_KEY_PREVIOUS: %w", err)
		}
		prev = append(prev, p)
	}
	return sealed.Configure(cur, prev...)
}

// genCSR prepares a subordinate CA request for the corporate PKI.
func genCSR(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, `usage: aegis-control-plane gen-csr <certs-dir> "CN=AegisProxy Issuing CA,O=Example Corp,C=DE"`)
		return 2
	}
	path, err := ca.GenerateCSR(args[0], args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("CSR written to %s (RSA-3072, CA, pathlen 0).\nSubmit it to your corporate CA with a subordinate-CA template, then run:\n  aegis-control-plane import-ca %s <issued-cert.pem> [chain.pem]\n", path, args[0])
	return 0
}

// importCA installs the certificate issued for a pending CSR.
func importCA(args []string) int {
	if len(args) < 2 || len(args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: aegis-control-plane import-ca <certs-dir> <issued-cert.pem> [chain.pem]")
		return 2
	}
	chain := ""
	if len(args) == 3 {
		chain = args[2]
	}
	cert, err := ca.ImportSignedCA(args[0], args[1], chain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Installed interception CA %q issued by %q (valid until %s).\nRestart the control-plane and data-plane workers to load it.\n", cert.Subject, cert.Issuer, cert.NotAfter.Format("2006-01-02"))
	return 0
}
