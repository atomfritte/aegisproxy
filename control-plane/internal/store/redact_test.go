package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

// TestRedactionVectors: the data-plane (aegis_dp/redact.py) is tested against the same file.
func TestRedactionVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "redaction_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct{ Mode, In, Out string }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 20 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		if got := RedactURL(v.In, v.Mode); got != v.Out {
			t.Errorf("RedactURL(%q, %q) = %q, want %q", v.In, v.Mode, got, v.Out)
		}
	}
}

func TestTelemetryQueryRedactionSetting(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	p := st.SecurityPolicy()
	if p.TelemetryQueryRedaction != RedactSensitive {
		t.Fatalf("default: %q", p.TelemetryQueryRedaction)
	}
	p.TelemetryQueryRedaction = "bogus"
	if _, err := st.UpdateSecurityPolicy(p, adminClaims); err == nil {
		t.Fatal("invalid mode accepted")
	}
	p.TelemetryQueryRedaction = ""
	if got, err := st.UpdateSecurityPolicy(p, adminClaims); err != nil || got.TelemetryQueryRedaction != RedactSensitive {
		t.Fatalf("empty mode: %q, %v", got.TelemetryQueryRedaction, err)
	}
	p.TelemetryQueryRedaction = RedactAll
	if _, err := st.UpdateSecurityPolicy(p, adminClaims); err != nil {
		t.Fatal(err)
	}
	// The control-plane redacts as well: workers that predate the setting send full URLs.
	f := ingestTestFlows("redact", 1)[0]
	f.RedirectLocation = "https://cdn.example/obj?X-Amz-Signature=abc"
	recorded, _, err := st.IngestFlowBatch(t.Context(), []models.TrafficFlow{f})
	if err != nil || len(recorded) != 1 {
		t.Fatal(err)
	}
	if got := recorded[0]; got.FullURL != "https://pkg.example/" || got.RedirectLocation != "https://cdn.example/obj" {
		t.Fatalf("mode all: %q, %q", got.FullURL, got.RedirectLocation)
	}
}
