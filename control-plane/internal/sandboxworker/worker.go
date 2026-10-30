package sandboxworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/packages/registry"
	"aegisproxy/control-plane/internal/sandbox"
)

// Config configures the worker.
type Config struct {
	ControlPlaneURL string
	SandboxKey      string
	WorkerID        string
	Ecosystems      []string // empty = any
	HTTPProxy       string   // egress proxy for artifact downloads
	MaxArtifactMB   int
	Poll            time.Duration
	Driver          Driver
	Logger          *slog.Logger
}

// Worker claims and runs sandbox analysis jobs.
type Worker struct {
	cfg      Config
	cp       *http.Client
	download *registry.Client
	log      *slog.Logger
}

// New builds a worker.
func New(cfg Config) *Worker {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.MaxArtifactMB <= 0 {
		cfg.MaxArtifactMB = 512
	}
	return &Worker{
		cfg:      cfg,
		cp:       &http.Client{Timeout: 60 * time.Second},
		download: registry.NewClient(cfg.HTTPProxy).WithMaxBytes(int64(cfg.MaxArtifactMB) << 20),
		log:      cfg.Logger.With("component", "sandbox-worker", "worker", cfg.WorkerID),
	}
}

// Run polls for jobs until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("sandbox worker started", "driver", w.cfg.Driver.Name(), "control_plane", w.cfg.ControlPlaneURL)
	ticker := time.NewTicker(w.cfg.Poll)
	defer ticker.Stop()
	for {
		job, err := w.claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			w.log.Warn("claim failed", "error", err)
		} else if job != nil {
			w.handle(ctx, *job)
			continue // immediately try for the next job
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) claim(ctx context.Context) (*sandbox.Job, error) {
	body, _ := json.Marshal(map[string]any{"drivers": []string{w.cfg.Driver.Name()}, "ecosystems": w.cfg.Ecosystems})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url("/api/sandbox/jobs/claim"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	w.auth(req)
	resp, err := w.cp.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Job sandbox.Job `json:"job"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out.Job, nil
}

func (w *Worker) handle(ctx context.Context, job sandbox.Job) {
	w.log.Info("analyzing", "job", job.ID, "package", job.Ecosystem+":"+job.Name+"@"+job.Version, "file", job.Filename)
	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go w.heartbeat(hbCtx, job.ID)

	artifact, err := w.fetchArtifact(ctx, job)
	if err != nil {
		w.postResult(ctx, job.ID, nil, "download failed: "+err.Error())
		return
	}
	report, err := w.cfg.Driver.Run(ctx, job, artifact)
	if err != nil {
		w.postResult(ctx, job.ID, nil, err.Error())
		return
	}
	w.postResult(ctx, job.ID, report, "")
}

// fetchArtifact downloads the artifact and verifies it against the job's expected digests before it is
// handed to the sandbox.
func (w *Worker) fetchArtifact(ctx context.Context, job sandbox.Job) ([]byte, error) {
	data, err := w.download.GetBytes(ctx, job.URL)
	if err != nil {
		return nil, err
	}
	if job.SHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), job.SHA256) {
			return nil, fmt.Errorf("sha256 mismatch for %s", job.Filename)
		}
	}
	if job.SHA512 != "" {
		sum := sha512.Sum512(data)
		if base64.StdEncoding.EncodeToString(sum[:]) != job.SHA512 {
			return nil, fmt.Errorf("sha512 mismatch for %s", job.Filename)
		}
	}
	return data, nil
}

func (w *Worker) heartbeat(ctx context.Context, jobID string) {
	t := time.NewTicker(4 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url("/api/sandbox/jobs/"+jobID+"/heartbeat"), nil)
			if err != nil {
				continue
			}
			w.auth(req)
			if resp, err := w.cp.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
}

func (w *Worker) postResult(ctx context.Context, jobID string, report *sandbox.Report, failure string) {
	payload := map[string]any{}
	if failure != "" {
		payload["error"] = failure
		w.log.Warn("analysis failed", "job", jobID, "error", failure)
	} else {
		payload["report"] = report
		w.log.Info("analysis complete", "job", jobID, "findings", len(report.Findings))
	}
	body, _ := json.Marshal(payload)
	// Use a detached context so the result is still delivered if the parent is shutting down.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, w.url("/api/sandbox/jobs/"+jobID+"/result"), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	w.auth(req)
	resp, err := w.cp.Do(req)
	if err != nil {
		w.log.Warn("could not post result", "job", jobID, "error", err)
		return
	}
	resp.Body.Close()
}

func (w *Worker) url(path string) string { return strings.TrimRight(w.cfg.ControlPlaneURL, "/") + path }

func (w *Worker) auth(req *http.Request) {
	req.Header.Set("X-Aegis-Sandbox-Key", w.cfg.SandboxKey)
	req.Header.Set("X-Aegis-Sandbox-Worker", w.cfg.WorkerID)
}
