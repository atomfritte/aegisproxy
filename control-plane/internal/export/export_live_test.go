//go:build live

package export

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

func TestLiveSentinelTokenErrorForUnknownTenant(t *testing.T) {
	t.Setenv("AZURE_AUTHORITY_HOST", "")
	s := models.ExportSink{Name: "live", Type: "sentinel", Streams: []string{"audit"}, Endpoint: "https://dce-live.westeurope-1.ingest.monitor.azure.com",
		TenantID: "00000000-0000-4000-8000-00000000a315", ClientID: "00000000-0000-4000-8000-000000000001", Secret: "not-a-real-secret-0815", DCRImmutableID: "dcr-00000000000000000000000000000000"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	drv, err := newDriver(s, meta, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = drv.(*sentinelDriver).accessToken(ctx)
	var pe *permanentError
	if err == nil || !errors.As(err, &pe) || !strings.Contains(err.Error(), "AADSTS") || strings.Contains(err.Error(), "not-a-real-secret") {
		t.Fatalf("token error must be permanent, readable and without the secret: %v", err)
	}
	t.Logf("%v", err)
}

// Datadog's real intake rejects an invalid API key with 403: a permanent error (no endless retries).
func TestLiveDatadogRejectsInvalidKey(t *testing.T) {
	s := models.ExportSink{Name: "dd", Type: "datadog", Streams: []string{"audit"}, Endpoint: "https://http-intake.logs.datadoghq.eu", Secret: "00000000000000000000000000000000"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	err := sendOne(t, s, AuditEvent(models.AuditEvent{ID: "live-1", Timestamp: time.Now(), Actor: "conformance", Action: "TEST"}))
	var pe *permanentError
	if err == nil || !errors.As(err, &pe) || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "00000000000000000000000000000000") {
		t.Fatalf("invalid key: %v", err)
	}
	t.Logf("%v", ShortError(err.Error()))
}
