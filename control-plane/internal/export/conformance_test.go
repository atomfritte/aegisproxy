package export

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// fakeHEC emulates a Splunk HEC token with indexer acknowledgement behind a sticky load balancer:
// events need a request channel, acknowledgements are only answered by the indexer that the cookie pins.
type fakeHEC struct {
	mu       sync.Mutex
	nextAck  int64
	pending  map[string]map[int64]int // channel -> ackId -> remaining "not yet indexed" polls
	channels []string
	events   int
	ackPolls int
	never    bool
}

func (f *fakeHEC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Splunk hec-token" {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"text":"Invalid token","code":4}`)
		return
	}
	switch r.URL.Path {
	case "/services/collector/event":
		ch := r.Header.Get("X-Splunk-Request-Channel")
		if ch == "" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"text":"Data channel is missing","code":10}`)
			return
		}
		f.channels = append(f.channels, ch)
		f.events++
		if f.pending[ch] == nil {
			f.pending[ch] = map[int64]int{}
		}
		id := f.nextAck
		f.nextAck++
		f.pending[ch][id] = 2
		http.SetCookie(w, &http.Cookie{Name: "hec_lb", Value: "indexer-7"})
		fmt.Fprintf(w, `{"text":"Success","code":0,"ackId":%d}`, id)
	case "/services/collector/ack":
		f.ackPolls++
		if c, err := r.Cookie("hec_lb"); err != nil || c.Value != "indexer-7" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"text":"Invalid data channel","code":11}`)
			return
		}
		var req struct {
			Acks []int64 `json:"acks"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := map[string]bool{}
		for _, id := range req.Acks {
			left := f.pending[r.URL.Query().Get("channel")][id]
			if left > 0 {
				f.pending[r.URL.Query().Get("channel")][id] = left - 1
			}
			out[fmt.Sprint(id)] = left <= 1 && !f.never
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"acks": out})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSplunkIndexerAcknowledgement(t *testing.T) {
	hec := &fakeHEC{pending: map[string]map[int64]int{}}
	srv := httptest.NewServer(hec)
	defer srv.Close()

	s := models.ExportSink{ID: "exp-splunk-1", Name: "splunk", Type: "splunk_hec", Streams: []string{"audit"}, Endpoint: srv.URL, Secret: "hec-token"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sendOne(t, s, AuditEvent(models.AuditEvent{ID: fmt.Sprintf("a%d", i), Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"})); err != nil {
			t.Fatalf("delivery with indexer acknowledgement: %v", err)
		}
	}
	hec.mu.Lock()
	channels, polls := append([]string(nil), hec.channels...), hec.ackPolls
	hec.mu.Unlock()
	if len(channels) != 2 || channels[0] != channels[1] {
		t.Fatalf("the request channel must be stable per destination: %v", channels)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(channels[0]) {
		t.Fatalf("channel is not a GUID: %s", channels[0])
	}
	if polls < 4 {
		t.Fatalf("acknowledgements were not polled until indexed (%d polls)", polls)
	}
	if r1, r2 := hecChannel(""), hecChannel(""); hecChannel("exp-other") == channels[0] || r1 == r2 {
		t.Fatal("channels must differ per destination and be random for unsaved destinations")
	}

	// No acknowledgement in time: the batch is reported as failed (and resent by the spool), not as delivered.
	old := splunkAckTimeout
	splunkAckTimeout = 700 * time.Millisecond
	defer func() { splunkAckTimeout = old }()
	hec.mu.Lock()
	hec.never = true
	hec.mu.Unlock()
	err := sendOne(t, s, AuditEvent(models.AuditEvent{ID: "a-late", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"}))
	if err == nil || !strings.Contains(err.Error(), "no indexer acknowledgement") {
		t.Fatalf("missing acknowledgement must fail the batch: %v", err)
	}
	var perm *permanentError
	if errors.As(err, &perm) {
		t.Fatal("a missing acknowledgement must be retried, not dropped as permanent")
	}
}

func TestSplunkWithoutAcknowledgement(t *testing.T) {
	var c captured
	srv := httptest.NewServer(c.handler(ok))
	defer srv.Close()
	s := models.ExportSink{ID: "exp-plain", Name: "splunk", Type: "splunk_hec", Streams: []string{"audit"}, Endpoint: srv.URL, Secret: "t"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	if err := sendOne(t, s, AuditEvent(models.AuditEvent{ID: "a1", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"})); err != nil {
		t.Fatal(err)
	}
	if len(c.paths) != 1 || c.paths[0] != "/services/collector/event" || c.hdrs[0].Get("X-Splunk-Request-Channel") != hecChannel("exp-plain") {
		t.Fatalf("one event request with the channel header expected: %v %v", c.paths, c.hdrs)
	}
}

func TestShortErrorKeepsDestination(t *testing.T) {
	for in, want := range map[string]string{
		`HTTP 401 from https://hec.example:8088/services/collector/event: {"text":"Invalid token","code":4}`:                                                   "HTTP 401 from https://hec.example:8088/services/collector/event",
		`sentinel: HTTP 403 from https://dce.westeurope-1.ingest.monitor.azure.com/dataCollectionRules/dcr-1/streams/Custom-X: {"error":{"code":"Forbidden"}}`: "sentinel: HTTP 403 from https://dce.westeurope-1.ingest.monitor.azure.com/dataCollectionRules/dcr-1/streams/Custom-X",
		"HTTP 500 from http://10.0.0.5/hook: line one\nline two: secret":                                                                                       "HTTP 500 from http://10.0.0.5/hook",
		"dial tcp 10.0.0.5:514: connection refused":                                                                                                            "dial tcp 10.0.0.5:514: connection refused",
	} {
		if got := ShortError(in); got != want {
			t.Errorf("ShortError(%q) = %q, want %q", in, got, want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The Logs Ingestion API uses a different token audience (and Entra authority) per cloud, as the Azure SDKs do.
func TestSentinelSovereignClouds(t *testing.T) {
	t.Setenv("AZURE_AUTHORITY_HOST", "")
	for endpoint, want := range map[string][2]string{
		"https://dce-1.westeurope-1.ingest.monitor.azure.com":   {"https://login.microsoftonline.com", "https://monitor.azure.com//.default"},
		"https://dce-1.usgovvirginia-1.ingest.monitor.azure.us": {"https://login.microsoftonline.us", "https://monitor.azure.us//.default"},
		"https://dce-1.chinanorth3-1.ingest.monitor.azure.cn":   {"https://login.chinacloudapi.cn", "https://monitor.azure.cn//.default"},
	} {
		var gotURL, gotScope string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_ = r.ParseForm()
			gotURL, gotScope = r.URL.Scheme+"://"+r.URL.Host, r.Form.Get("scope")
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"t","expires_in":3600}`)), Header: http.Header{}}, nil
		})}
		d := &sentinelDriver{httpBase: httpBase{client: client, cfg: models.ExportSink{Type: "sentinel", Endpoint: endpoint, TenantID: "tenant-1", ClientID: "app", Secret: "s"}}}
		if _, err := d.accessToken(t.Context()); err != nil {
			t.Fatal(err)
		}
		if gotURL != want[0] || gotScope != want[1] {
			t.Errorf("%s: token from %s with scope %s, want %s with %s", endpoint, gotURL, gotScope, want[0], want[1])
		}
	}
}

// AKS workload identity: tenant and client may come from the pod environment injected by the webhook.
func TestSentinelWorkloadIdentityFromPodEnvironment(t *testing.T) {
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("federated.jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	t.Setenv("AZURE_AUTHORITY_HOST", "")
	s := models.ExportSink{Name: "wi", Type: "sentinel", Streams: []string{"audit"}, Endpoint: "https://dce-1.westeurope-1.ingest.monitor.azure.com",
		DCRImmutableID: "dcr-1", AzureAuth: "workload_identity"}
	if err := Validate(&s); err != nil {
		t.Fatalf("workload identity without tenant/client in the destination must validate: %v", err)
	}
	var form url.Values
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_ = r.ParseForm()
		form = r.PostForm
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"t","expires_in":3600}`)), Header: http.Header{}}, nil
	})}
	d := &sentinelDriver{httpBase: httpBase{client: client, cfg: s}}
	if _, err := d.accessToken(t.Context()); err == nil || !strings.Contains(err.Error(), "AZURE_TENANT_ID") {
		t.Fatalf("missing tenant/client must be reported: %v", err)
	}
	t.Setenv("AZURE_TENANT_ID", "tenant-env")
	t.Setenv("AZURE_CLIENT_ID", "client-env")
	if _, err := d.accessToken(t.Context()); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_id") != "client-env" || form.Get("client_assertion") != "federated.jwt" || form.Get("client_secret") != "" {
		t.Fatalf("token request: %v", form)
	}
	cs := models.ExportSink{Name: "cs", Type: "sentinel", Streams: []string{"audit"}, Endpoint: s.Endpoint, DCRImmutableID: "dcr-1", Secret: "x"}
	if err := Validate(&cs); err == nil {
		t.Fatal("client secret authentication still requires tenant_id and client_id")
	}
}
