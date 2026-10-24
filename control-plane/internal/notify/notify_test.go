package notify

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The webhook URL is the credential: failed deliveries must not put it into the notification log
// (visible in the console) or the service log.
func TestDeliveryErrorsHideWebhookURL(t *testing.T) {
	var logs bytes.Buffer
	d := NewDispatcher(models.NotificationConfig{}, slog.New(slog.NewTextHandler(&logs, nil)))
	d.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset by peer")
	})}
	d.deliver(job{channel: "slack", eventType: "SECURITY_EVENT", payload: "{}", enabled: true,
		webhookURL: "https://hooks.slack.test/services/T1/B1/PathSecret?token=QuerySecret"})
	entries := d.GetLogs()
	if len(entries) != 1 {
		t.Fatalf("log entries: %d", len(entries))
	}
	note := entries[0].StatusNote
	if !strings.Contains(note, "https://hooks.slack.test/"+models.MaskedSecretMarker) || !strings.Contains(note, "connection reset by peer") {
		t.Errorf("status note lacks destination or cause: %q", note)
	}
	for _, out := range []string{note, logs.String()} {
		if strings.Contains(out, "PathSecret") || strings.Contains(out, "QuerySecret") || strings.Contains(out, "/services/") {
			t.Errorf("webhook URL leaked: %s", out)
		}
	}
}
