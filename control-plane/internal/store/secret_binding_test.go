package store

import (
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

// Stored export credentials stay with the saved destination, and audit summaries never carry the
// secret path of a webhook URL.
func TestExportSinkCredentialsStayWithDestination(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	const pathSecret = "B2/tok3n-path-secret"
	saved, err := st.UpsertExportSink(models.ExportSink{Name: "hook", Type: "webhook", Streams: []string{"audit"},
		Endpoint: "https://hooks.example/services/T1/" + pathSecret, Secret: "hmac-secret", Headers: sealed.Map{"X-Key": "header-secret"}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if ev := lastAuditAction(st, "EXPORT_SINK_CREATED"); ev == nil || strings.Contains(ev.Summary, pathSecret) || strings.Contains(ev.Summary, "tok3n") {
		t.Fatalf("create summary leaks the webhook path: %+v", ev)
	}

	// The console sends back what it shows: masked endpoint, empty secret and header values.
	edit := saved
	edit.Headers = sealed.Map{"X-Key": ""}
	edit.Enabled = false
	if _, err := st.UpsertExportSink(edit, adminClaims); err != nil {
		t.Fatalf("unchanged destination: %v", err)
	}
	if got, _ := st.ExportSinkWithSecrets(saved.ID); got.Secret != "hmac-secret" || got.Headers["X-Key"] != "header-secret" || !strings.HasSuffix(got.Endpoint, pathSecret) {
		t.Fatalf("stored credentials lost: %+v", got)
	}
	if ev := lastAuditAction(st, "EXPORT_SINK_UPDATED"); ev == nil || strings.Contains(ev.Summary, "tok3n") {
		t.Fatalf("update summary leaks the webhook path: %+v", ev)
	}

	moved := edit
	moved.Endpoint = "https://attacker.example/collect"
	for name, m := range map[string]func(*models.ExportSink){
		"secret": func(s *models.ExportSink) { s.Headers = sealed.Map{"X-Key": "new-header"} },
		"header": func(s *models.ExportSink) { s.Secret = "new-secret" },
	} {
		try := moved
		m(&try)
		if _, err := st.UpsertExportSink(try, adminClaims); err == nil || !strings.Contains(err.Error(), "enter the credentials again") {
			t.Errorf("stored %s followed the new destination: %v", name, err)
		}
		if _, err := st.MergeExportSecretsForTest(try); err == nil {
			t.Errorf("test connection reused the stored %s for a new destination", name)
		}
	}
	if got, _ := st.ExportSinkWithSecrets(saved.ID); got.Endpoint == moved.Endpoint {
		t.Fatal("refused update was applied")
	}

	// New credentials (or none) for the new destination are fine.
	moved.Secret, moved.Headers = "new-secret", sealed.Map{"X-Key": "new-header"}
	if _, err := st.UpsertExportSink(moved, adminClaims); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ExportSinkWithSecrets(saved.ID); got.Secret != "new-secret" || got.Headers["X-Key"] != "new-header" {
		t.Fatalf("new credentials not stored: %+v", got)
	}
	cleared := moved
	cleared.Endpoint, cleared.Secret, cleared.ClearSecret, cleared.Headers = "https://other.example/in", "", true, nil
	if _, err := st.UpsertExportSink(cleared, adminClaims); err != nil {
		t.Fatalf("moving without credentials: %v", err)
	}
	if got, _ := st.ExportSinkWithSecrets(saved.ID); got.Secret != "" || len(got.Headers) != 0 {
		t.Fatalf("credentials kept after clear: %+v", got)
	}

	// Omitted fields that validation defaults (azure_auth) are not a destination change.
	sentinel, err := st.UpsertExportSink(models.ExportSink{Name: "sentinel", Type: "sentinel", Streams: []string{"audit"},
		Endpoint: "https://dce-1.westeurope-1.ingest.monitor.azure.com", DCRImmutableID: "dcr-1", TenantID: "t", ClientID: "c", Secret: "azure-secret"}, adminClaims)
	if err != nil || sentinel.AzureAuth != "client_secret" {
		t.Fatalf("sentinel: %v %q", err, sentinel.AzureAuth)
	}
	sentinel.AzureAuth, sentinel.BatchSize = "", 100
	if _, err := st.UpsertExportSink(sentinel, adminClaims); err != nil {
		t.Fatalf("update without azure_auth: %v", err)
	}

	if err := st.DeleteExportSink(saved.ID, adminClaims); err != nil {
		t.Fatal(err)
	}
	if ev := lastAuditAction(st, "EXPORT_SINK_DELETED"); ev == nil || !strings.Contains(ev.Summary, "other.example") {
		t.Fatalf("delete summary: %+v", ev)
	}
}

func TestDefenderSecretBoundToDestination(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	cfg := models.DefenderConfig{TenantID: "72f988bf-86f1-41af-91ab-2d7cd011db47", ClientID: "app-1", ClientSecret: "mde-secret"}
	if _, err := st.UpdateDefenderConfig(cfg, adminClaims); err != nil {
		t.Fatal(err)
	}
	keep := cfg
	keep.ClientSecret = ""
	keep.SyncMinutes = 15
	if _, err := st.UpdateDefenderConfig(keep, adminClaims); err != nil || st.state.Defender.ClientSecret != "mde-secret" {
		t.Fatalf("unchanged destination did not keep the secret: %v", err)
	}
	for _, change := range []func(*models.DefenderConfig){
		func(c *models.DefenderConfig) { c.TenantID = "11111111-2222-3333-4444-555555555555" },
		func(c *models.DefenderConfig) { c.ClientID = "app-2" },
		func(c *models.DefenderConfig) { c.AuthorityURL = "https://login.microsoftonline.us" },
		func(c *models.DefenderConfig) { c.APIBaseURL = "https://api-gov.securitycenter.microsoft.us" },
	} {
		moved := keep
		change(&moved)
		if _, err := st.UpdateDefenderConfig(moved, adminClaims); err == nil || !strings.Contains(err.Error(), "re-enter the client secret") {
			t.Errorf("stored secret followed %+v: %v", moved, err)
		}
		moved.ClientSecret = "other-secret"
		if _, err := st.UpdateDefenderConfig(moved, adminClaims); err != nil {
			t.Errorf("new secret refused: %v", err)
		}
		if _, err := st.UpdateDefenderConfig(cfg, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	// Clearing the registration drops the secret instead of failing.
	if _, err := st.UpdateDefenderConfig(models.DefenderConfig{}, adminClaims); err != nil || st.state.Defender.ClientSecret != "" {
		t.Fatalf("clearing the registration: %v (secret kept=%v)", err, st.state.Defender.ClientSecret != "")
	}
}
