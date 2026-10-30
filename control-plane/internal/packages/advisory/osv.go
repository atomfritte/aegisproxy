package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// OSV queries https://osv.dev. The batch endpoint returns advisory IDs per query; details (severity,
// summary, aliases, malware category) are fetched once per unique ID and cached for the call.
type OSV struct {
	HTTP    *http.Client
	BaseURL string
}

// NewOSV builds an OSV source using the given HTTP client (SSRF-guarded by the caller).
func NewOSV(httpClient *http.Client) *OSV {
	return &OSV{HTTP: httpClient, BaseURL: "https://api.osv.dev"}
}

func (*OSV) ID() string { return "osv" }

// Supports: OSV covers npm, PyPI and NuGet. PowerShell Gallery is not an OSV ecosystem.
func (*OSV) Supports(ecosystem string) bool {
	return osvEcosystem(ecosystem) != ""
}

func osvEcosystem(e string) string {
	switch e {
	case models.EcosystemNPM:
		return "npm"
	case models.EcosystemPyPI:
		return "PyPI"
	case models.EcosystemNuGet:
		return "NuGet"
	}
	return ""
}

const osvBatchSize = 1000

type osvBatchReq struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Aliases          []string        `json:"aliases"`
	Withdrawn        string          `json:"withdrawn"`
	References       []osvReference  `json:"references"`
	Severity         []osvSeverity   `json:"severity"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
	Affected         []struct {
		DatabaseSpecific json.RawMessage `json:"database_specific"`
	} `json:"affected"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (o *OSV) Lookup(ctx context.Context, queries []Query) ([][]models.PackageAdvisory, error) {
	out := make([][]models.PackageAdvisory, len(queries))
	cache := map[string]*models.PackageAdvisory{}
	// Map our queries onto OSV, skipping unsupported ecosystems (they get a nil slice = no answer).
	var batchIdx []int
	var batch []osvQuery
	for i, q := range queries {
		eco := osvEcosystem(q.Ecosystem)
		if eco == "" {
			continue
		}
		batchIdx = append(batchIdx, i)
		batch = append(batch, osvQuery{Package: osvPackage{Name: q.Name, Ecosystem: eco}, Version: q.Version})
	}
	for start := 0; start < len(batch); start += osvBatchSize {
		end := min(start+osvBatchSize, len(batch))
		resp, err := o.queryBatch(ctx, batch[start:end])
		if err != nil {
			return nil, err
		}
		for j, r := range resp.Results {
			idx := batchIdx[start+j]
			for _, v := range r.Vulns {
				adv, err := o.detail(ctx, v.ID, cache)
				if err != nil {
					return nil, err
				}
				if adv != nil && !adv.Withdrawn {
					out[idx] = append(out[idx], *adv)
				}
			}
		}
	}
	return out, nil
}

func (o *OSV) queryBatch(ctx context.Context, q []osvQuery) (*osvBatchResp, error) {
	body, _ := json.Marshal(osvBatchReq{Queries: q})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV querybatch: HTTP %d", resp.StatusCode)
	}
	var out osvBatchResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (o *OSV) detail(ctx context.Context, id string, cache map[string]*models.PackageAdvisory) (*models.PackageAdvisory, error) {
	if a, ok := cache[id]; ok {
		return a, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		cache[id] = nil
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vuln %s: HTTP %d", id, resp.StatusCode)
	}
	var v osvVuln
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&v); err != nil {
		return nil, err
	}
	adv := o.toAdvisory(v)
	cache[id] = adv
	return adv, nil
}

func (o *OSV) toAdvisory(v osvVuln) *models.PackageAdvisory {
	adv := &models.PackageAdvisory{
		ID: v.ID, Source: "osv", Summary: v.Summary, Aliases: v.Aliases,
		Withdrawn: v.Withdrawn != "",
	}
	for _, r := range v.References {
		if r.Type == "ADVISORY" || r.Type == "WEB" {
			adv.URL = r.URL
			break
		}
	}
	// Severity: prefer a CVSS vector score, fall back to the database-specific word.
	adv.CVSS, adv.Severity = osvScore(v.Severity)
	if adv.Severity == "" {
		adv.Severity = osvDBSeverity(v.DatabaseSpecific)
	}
	for _, a := range v.Affected {
		if adv.Severity == "" {
			adv.Severity = osvDBSeverity(a.DatabaseSpecific)
		}
	}
	if adv.Severity == "" {
		adv.Severity = models.RiskUnknown
	}
	// OSV "MAL-" identifiers (and the osv-malware source) are malicious-package reports.
	if strings.HasPrefix(v.ID, "MAL-") || hasMalwarePrefix(v.Aliases) {
		adv.Malware = true
		adv.Severity = models.RiskCritical
	}
	return adv
}

func hasMalwarePrefix(aliases []string) bool {
	for _, a := range aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

func osvScore(sev []osvSeverity) (float64, string) {
	best := 0.0
	for _, s := range sev {
		if score := cvssBaseScore(s.Score); score > best {
			best = score
		}
	}
	if best <= 0 {
		return 0, ""
	}
	return best, severityFromCVSS(best)
}

func osvDBSeverity(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var ds struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(raw, &ds); err != nil {
		return ""
	}
	return normalizeSeverity(ds.Severity)
}

var _ = time.Now
