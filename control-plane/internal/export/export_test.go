package export

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

var meta = Meta{Node: "node-1", Host: "cp-1", Version: "2.1.0"}

func flow(verdict string) models.TrafficFlow {
	return models.TrafficFlow{ID: "flw-1", Timestamp: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), ServerIP: "10.1.0.5",
		ServerID: "srv-1", ServerHostname: "web|01=x", GroupIDs: []string{"grp-a"}, Method: "GET", Scheme: "https", Host: "pkgs.example.org",
		Port: 443, Path: "/a?token=secret", FullURL: "https://pkgs.example.org/a?token=secret", Verdict: verdict,
		MatchedRuleName: "rule\nwith newline", StatusCode: 403, UserAgent: "curl/8"}
}

func TestFormats(t *testing.T) {
	ev := FlowEvent(flow(models.VerdictBlocked))
	cef := CEF(ev, meta)
	if !strings.HasPrefix(cef, "CEF:0|AegisProxy|Egress Gateway|2.1.0|BLOCKED|") || !strings.Contains(cef, `shost=web|01\=x`) ||
		!strings.Contains(cef, `cs1=rule\nwith newline`) || strings.Contains(cef, "\n") {
		t.Errorf("CEF: %s", cef)
	}
	leef := LEEF(ev, meta)
	if !strings.HasPrefix(leef, "LEEF:2.0|AegisProxy|Egress Gateway|2.1.0|BLOCKED|x09|") || !strings.Contains(leef, "\tsrc=10.1.0.5") || strings.Contains(leef, "\n") {
		t.Errorf("LEEF: %q", leef)
	}
	f := Fields(ev, meta)
	if f["event.outcome"] != "failure" || f["url.domain"] != "pkgs.example.org" || f["http.response.status_code"] != 403 || f["source.ip"] != "10.1.0.5" {
		t.Errorf("fields: %v", f)
	}
	sink := &models.ExportSink{RedactQuery: true}
	if r := redacted(ev, sink); strings.Contains(r.Flow.FullURL, "secret") || strings.Contains(ev.Flow.FullURL, "secret") == false {
		t.Error("query redaction must apply to a copy")
	}
	b, _ := Payload(ev, "json", meta)
	var native map[string]any
	if err := json.Unmarshal(b, &native); err != nil || native["stream"] != "traffic" || native["data"] == nil {
		t.Errorf("native: %s", b)
	}
}

func TestFilters(t *testing.T) {
	rt := &runtime{cfg: models.ExportSink{Streams: []string{"traffic", "security"}, TrafficFilter: "blocked", MinSeverity: "high"}}
	if rt.accepts(FlowEvent(flow(models.VerdictAllowed))) || !rt.accepts(FlowEvent(flow(models.VerdictThreatBlocked))) {
		t.Error("traffic filter")
	}
	if rt.accepts(SecurityEvent(models.SecurityEvent{Severity: "medium"})) || !rt.accepts(SecurityEvent(models.SecurityEvent{Severity: "critical"})) {
		t.Error("severity filter")
	}
	if rt.accepts(AuditEvent(models.AuditEvent{})) {
		t.Error("stream filter")
	}
}

func TestSyslogTCPAndUDP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		for {
			lenStr, err := r.ReadString(' ')
			if err != nil {
				return
			}
			n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			got <- string(buf)
		}
	}()
	s := models.ExportSink{Name: "rsyslog", Type: "syslog", Streams: []string{"audit"}, Endpoint: ln.Addr().String(), Transport: "tcp", Format: "cef", SyslogFacility: "local4"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	drv, _ := newDriver(s, meta, "")
	rec, _ := drv.encode(AuditEvent(models.AuditEvent{ID: "a1", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN", Summary: "x"}))
	if err := drv.send(context.Background(), [][]byte{rec, rec}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			// local4 (20) * 8 + info (6) = 166
			if !strings.HasPrefix(m, "<166>1 ") || !strings.Contains(m, " cp-1 aegisproxy - AUDIT - CEF:0|") {
				t.Errorf("syslog message: %q", m)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no syslog message received")
		}
	}
	drv.close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil && strings.Contains(err.Error(), "wsaioctl") {
		t.Skip("UDP sockets need SIO_UDP_CONNRESET, which Wine does not implement (real Windows does):", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u := models.ExportSink{Name: "udp", Type: "syslog", Streams: []string{"security"}, Endpoint: pc.LocalAddr().String(), Transport: "udp", SyslogProtocol: "rfc3164"}
	if err := Validate(&u); err != nil {
		t.Fatal(err)
	}
	ud, _ := newDriver(u, meta, "")
	rec, _ = ud.encode(SecurityEvent(models.SecurityEvent{ID: "s1", Timestamp: time.Now(), Severity: "critical", Type: "MALWARE"}))
	if err := ud.send(context.Background(), [][]byte{rec}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "<130>") || !strings.Contains(string(buf[:n]), " cp-1 aegisproxy: {") {
		t.Fatalf("udp syslog: %q %v", buf[:n], err)
	}
}

type captured struct {
	mu     sync.Mutex
	bodies [][]byte
	hdrs   []http.Header
	paths  []string
}

func (c *captured) handler(status func(n int) int) http.HandlerFunc {
	var n atomic.Int32
	return func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			body = zr
		}
		b, _ := io.ReadAll(body)
		c.mu.Lock()
		c.bodies, c.hdrs, c.paths = append(c.bodies, b), append(c.hdrs, r.Header.Clone()), append(c.paths, r.URL.Path)
		c.mu.Unlock()
		w.WriteHeader(status(int(n.Add(1))))
	}
}

func ok(int) int { return 200 }

func sendOne(t *testing.T, s models.ExportSink, ev Event) error {
	t.Helper()
	if err := Validate(&s); err != nil {
		t.Fatalf("validate %s: %v", s.Type, err)
	}
	drv, err := newDriver(s, meta, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := drv.encode(ev)
	if err != nil {
		t.Fatal(err)
	}
	return drv.send(context.Background(), [][]byte{rec})
}

func TestHTTPDrivers(t *testing.T) {
	var c captured
	srv := httptest.NewServer(c.handler(ok))
	defer srv.Close()
	ev := FlowEvent(flow(models.VerdictAllowed))
	base := models.ExportSink{Name: "x", Streams: []string{"traffic"}, Endpoint: srv.URL}

	otlp := base
	otlp.Type, otlp.Headers = "otlp", sealed.Map{"X-Tenant": "t1"}
	if err := sendOne(t, otlp, ev); err != nil {
		t.Fatal(err)
	}
	var o struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					SeverityNumber int              `json:"severityNumber"`
					Body           map[string]any   `json:"body"`
					Attributes     []map[string]any `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(c.bodies[0], &o); err != nil || c.paths[0] != "/v1/logs" || c.hdrs[0].Get("X-Tenant") != "t1" ||
		len(o.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 || o.ResourceLogs[0].ScopeLogs[0].LogRecords[0].SeverityNumber != 9 {
		t.Fatalf("otlp: %s %v", c.bodies[0], err)
	}

	hec := base
	hec.Type, hec.Secret, hec.Index = "splunk_hec", "hec-token", "aegis_{stream}"
	if err := sendOne(t, hec, ev); err != nil {
		t.Fatal(err)
	}
	if c.paths[1] != "/services/collector/event" || c.hdrs[1].Get("Authorization") != "Splunk hec-token" || !strings.Contains(string(c.bodies[1]), `"index":"aegis_traffic"`) {
		t.Errorf("hec: %s %s", c.paths[1], c.bodies[1])
	}

	es := base
	es.Type, es.Secret = "elasticsearch", "apikey"
	if err := sendOne(t, es, ev); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(c.bodies[2])), "\n")
	if c.paths[2] != "/_bulk" || len(lines) != 2 || !strings.Contains(lines[0], `"_index":"logs-aegisproxy.traffic-default"`) ||
		!strings.Contains(lines[0], `"_id":"flw-1"`) || c.hdrs[2].Get("Authorization") != "ApiKey apikey" || !strings.Contains(lines[1], `"@timestamp"`) {
		t.Errorf("elastic: %s", c.bodies[2])
	}

	loki := base
	loki.Type, loki.Username, loki.Secret, loki.Labels = "loki", "u", "p", map[string]string{"env": "prod"}
	if err := sendOne(t, loki, ev); err != nil {
		t.Fatal(err)
	}
	if c.paths[3] != "/loki/api/v1/push" || !strings.Contains(string(c.bodies[3]), `"env":"prod"`) || !strings.Contains(string(c.bodies[3]), `"verdict":"ALLOWED"`) {
		t.Errorf("loki: %s", c.bodies[3])
	}

	hook := base
	hook.Type, hook.Secret = "webhook", "hmac-key"
	if err := sendOne(t, hook, ev); err != nil {
		t.Fatal(err)
	}
	h := c.hdrs[4]
	if h.Get("X-Aegis-Signature") != WebhookSignature("hmac-key", h.Get("X-Aegis-Timestamp"), c.bodies[4]) {
		t.Error("webhook signature does not verify")
	}

	dd := base
	dd.Type, dd.Secret = "datadog", "dd-key"
	dd.Endpoint = strings.Replace(srv.URL, "http://", "https://", 1) // validated as https; re-pointed below
	if err := Validate(&dd); err != nil {
		t.Fatal(err)
	}
	dd.Endpoint = srv.URL
	drv, _ := newDriver(dd, meta, "")
	rec, _ := drv.encode(ev)
	if err := drv.send(context.Background(), [][]byte{rec}); err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	if err := json.Unmarshal(c.bodies[5], &items); err != nil || len(items) != 1 {
		t.Fatalf("datadog body: %s", c.bodies[5])
	}
	allowed := map[string]bool{"ddsource": true, "ddtags": true, "hostname": true, "service": true, "status": true, "timestamp": true, "message": true}
	for k := range items[0] {
		if !allowed[k] {
			t.Errorf("datadog: attribute %q outside the agent schema", k)
		}
	}
	var inner map[string]any
	if json.Unmarshal([]byte(items[0]["message"].(string)), &inner) != nil || inner["url"] == nil {
		t.Errorf("datadog: attributes not in the JSON message: %v", items[0]["message"])
	}
	if c.paths[5] != "/api/v2/logs" || c.hdrs[5].Get("DD-API-KEY") != "dd-key" {
		t.Errorf("datadog: %s", c.bodies[5])
	}
}

func TestSentinel(t *testing.T) {
	var tokens atomic.Int32
	var c captured
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("scope") != "https://monitor.azure.com//.default" {
			w.WriteHeader(401)
			return
		}
		tokens.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	mux.HandleFunc("POST /dataCollectionRules/dcr-1/streams/Custom-AegisProxy_CL", c.handler(func(int) int { return 204 }))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	s := models.ExportSink{Name: "sentinel", Type: "sentinel", Streams: []string{"audit"}, Endpoint: srv.URL, TenantID: "tenant-1",
		ClientID: "app", Secret: "s3cret", DCRImmutableID: "dcr-1", AuthorityURL: srv.URL, TLSSkipVerify: true}
	for i := 0; i < 2; i++ {
		if err := sendOne(t, s, AuditEvent(models.AuditEvent{ID: "a", Timestamp: time.Now(), Actor: "admin", Action: "X"})); err != nil {
			t.Fatal(err)
		}
	}
	var recs []map[string]any
	if err := json.Unmarshal(c.bodies[0], &recs); err != nil || recs[0]["Stream"] != "audit" || recs[0]["Actor"] != "admin" || c.hdrs[0].Get("Authorization") != "Bearer tok" {
		t.Fatalf("sentinel: %s %v", c.bodies[0], err)
	}
}

func TestPermanentAndPartialErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer bad.Close()
	err := sendOne(t, models.ExportSink{Name: "x", Type: "webhook", Streams: []string{"audit"}, Endpoint: bad.URL}, AuditEvent(models.AuditEvent{ID: "a"}))
	if _, ok := err.(*permanentError); !ok {
		t.Fatalf("403 must be permanent: %v", err)
	}
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":409}},{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad"}}}]}`))
	}))
	defer es.Close()
	s := models.ExportSink{Name: "es", Type: "elasticsearch", Streams: []string{"traffic"}, Endpoint: es.URL}
	_ = Validate(&s)
	drv, _ := newDriver(s, meta, "")
	rec, _ := drv.encode(FlowEvent(flow(models.VerdictAllowed)))
	err = drv.send(context.Background(), [][]byte{rec, rec, rec})
	if pe, ok := err.(*partialError); !ok || len(pe.rejected) != 1 || !strings.Contains(pe.rejected[2], "mapper_parsing_exception: bad") || pe.retryFrom != 3 {
		t.Fatalf("partial: %#v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func TestSpoolReplayAcrossRestart(t *testing.T) {
	var up atomic.Bool
	var mu sync.Mutex
	var ids []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(503)
			return
		}
		var body struct {
			Events []struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, e := range body.Events {
			ids = append(ids, e.Data.ID)
		}
		mu.Unlock()
	}))
	defer srv.Close()
	dir := t.TempDir()
	sink := models.ExportSink{ID: "exp-1", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"}, Endpoint: srv.URL, BatchSize: 3, FlushSeconds: 1}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	m := New(Options{SpoolDir: filepath.Join(dir, "export-spool"), Node: "n1", Version: "t"})
	m.Configure([]models.ExportSink{sink})
	for i := 0; i < 10; i++ {
		m.Publish(AuditEvent(models.AuditEvent{ID: "a" + strconv.Itoa(i), Timestamp: time.Now()}))
	}
	waitFor(t, "records spooled while the destination is down", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].SpoolRecords == 10 && st[0].State == "retrying"
	})
	m.Close() // restart with a full spool
	if entries, _ := os.ReadDir(filepath.Join(dir, "export-spool", "exp-1")); len(entries) < 2 {
		t.Fatal("spool not persisted")
	}
	up.Store(true)
	m2 := New(Options{SpoolDir: filepath.Join(dir, "export-spool"), Node: "n1", Version: "t"})
	defer m2.Close()
	m2.Configure([]models.ExportSink{sink})
	m2.Publish(AuditEvent(models.AuditEvent{ID: "a10", Timestamp: time.Now()}))
	waitFor(t, "spool replayed in order", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(ids) == 11
	})
	mu.Lock()
	for i, id := range ids {
		if id != "a"+strconv.Itoa(i) {
			t.Fatalf("order lost: %v", ids)
		}
	}
	mu.Unlock()
	st := m2.Status()[0]
	if st.SpoolRecords != 0 || st.Sent != 11 || st.State != "ok" {
		t.Fatalf("status after replay: %+v", st)
	}
	// Deleting the sink removes its spool.
	m2.Configure(nil)
	if _, err := os.Stat(filepath.Join(dir, "export-spool", "exp-1")); !os.IsNotExist(err) {
		t.Error("spool of deleted sink kept")
	}
}

func TestFileSinkAndValidation(t *testing.T) {
	dir := t.TempDir()
	s := models.ExportSink{Name: "f", Type: "file", Streams: []string{"traffic"}, Endpoint: "events.jsonl", Format: "ecs"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	drv, _ := newDriver(s, meta, dir)
	rec, _ := drv.encode(FlowEvent(flow(models.VerdictAllowed)))
	if err := drv.send(context.Background(), [][]byte{rec, rec}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if strings.Count(string(b), "\n") != 2 {
		t.Errorf("file sink: %s", b)
	}
	bad := []models.ExportSink{
		{Name: "a", Type: "file", Streams: []string{"audit"}, Endpoint: "../etc/passwd"},
		{Name: "b", Type: "syslog", Streams: []string{"audit"}, Endpoint: "no-port"},
		{Name: "c", Type: "webhook", Streams: []string{"audit"}, Endpoint: "ftp://x"},
		{Name: "d", Type: "webhook", Streams: []string{"audit"}, Endpoint: "https://user:pw@x.example"},
		{Name: "e", Type: "splunk_hec", Streams: []string{"audit"}, Endpoint: "https://x.example"},
		{Name: "f", Type: "webhook", Streams: []string{"nope"}, Endpoint: "https://x.example"},
		{Name: "g", Type: "webhook", Streams: []string{"audit"}, Endpoint: "https://x.example", Headers: sealed.Map{"Host": "evil"}},
		{Name: "h", Type: "webhook", Streams: []string{"audit"}, Endpoint: "https://x.example", Headers: sealed.Map{"X-A": "a\r\nB: c"}},
		{Name: "i", Type: "syslog", Streams: []string{"audit"}, Endpoint: "x:514", Format: "xml"},
	}
	for _, b := range bad {
		if err := Validate(&b); err == nil {
			t.Errorf("invalid sink %q accepted", b.Name)
		}
	}
	es := models.ExportSink{Name: "es", Type: "elasticsearch", Streams: []string{"audit"}, Endpoint: "https://x.example", Format: "cef"}
	if err := Validate(&es); err != nil || es.Format != "ecs" {
		t.Errorf("single-format types use their only format: %v %s", err, es.Format)
	}
	// Link-local destinations (cloud metadata) are refused at connect time.
	meta := models.ExportSink{Name: "m", Type: "webhook", Streams: []string{"audit"}, Endpoint: "http://169.254.169.254/latest"}
	if err := sendOne(t, meta, AuditEvent(models.AuditEvent{ID: "a"})); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("metadata endpoint: %v", err)
	}
}

func TestSentinelManagedAndWorkloadIdentity(t *testing.T) {
	var c captured
	var mu sync.Mutex
	var assertion string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata/identity/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Query().Get("resource") != "https://monitor.azure.com" || r.URL.Query().Get("client_id") != "uami-1" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"mi-token","expires_in":"3599"}`))
	})
	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		assertion = r.Form.Get("client_assertion")
		mu.Unlock()
		if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || r.Form.Get("client_secret") != "" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"wi-token","expires_in":3600}`))
	})
	mux.HandleFunc("POST /dataCollectionRules/dcr-1/streams/Custom-AegisProxy_CL", c.handler(func(int) int { return 204 }))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	plain := httptest.NewServer(mux) // IMDS is plain http
	defer plain.Close()
	old := imdsEndpoint
	imdsEndpoint = plain.URL + "/metadata/identity/oauth2/token"
	defer func() { imdsEndpoint = old }()

	ev := AuditEvent(models.AuditEvent{ID: "a", Timestamp: time.Now(), Actor: "admin", Action: "X"})
	mi := models.ExportSink{Name: "mi", Type: "sentinel", Streams: []string{"audit"}, Endpoint: srv.URL, DCRImmutableID: "dcr-1",
		AzureAuth: "managed_identity", ClientID: "uami-1", TLSSkipVerify: true}
	if err := sendOne(t, mi, ev); err != nil {
		t.Fatalf("managed identity: %v", err)
	}
	if c.hdrs[0].Get("Authorization") != "Bearer mi-token" {
		t.Errorf("mi token: %s", c.hdrs[0].Get("Authorization"))
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("federated-jwt\n"), 0o600)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	wi := models.ExportSink{Name: "wi", Type: "sentinel", Streams: []string{"audit"}, Endpoint: srv.URL, DCRImmutableID: "dcr-1",
		AzureAuth: "workload_identity", TenantID: "tenant-1", ClientID: "app-1", AuthorityURL: srv.URL, TLSSkipVerify: true}
	if err := sendOne(t, wi, ev); err != nil {
		t.Fatalf("workload identity: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if assertion != "federated-jwt" || c.hdrs[1].Get("Authorization") != "Bearer wi-token" {
		t.Errorf("workload identity: assertion=%q auth=%s", assertion, c.hdrs[1].Get("Authorization"))
	}
}
