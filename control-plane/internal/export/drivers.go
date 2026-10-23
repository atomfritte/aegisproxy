package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

// driver encodes events into records and delivers batches of records.
type driver interface {
	encode(ev Event) ([]byte, error)
	send(ctx context.Context, recs [][]byte) error
	close()
}

// permanentError marks rejections that retrying cannot fix (bad credentials, invalid payload).
type permanentError struct{ msg string }

func (e *permanentError) Error() string { return e.msg }

// partialError reports that some records of a batch were rejected permanently.
type partialError struct {
	rejected int
	msg      string
}

func (e *partialError) Error() string { return e.msg }

func newDriver(cfg models.ExportSink, meta Meta, exportDir string) (driver, error) {
	switch cfg.Type {
	case "syslog":
		tc, err := tlsConfig(cfg, hostOf(cfg.Endpoint))
		if err != nil {
			return nil, err
		}
		return &syslogDriver{cfg: cfg, meta: meta, tls: tc}, nil
	case "file":
		return &fileDriver{cfg: cfg, meta: meta, path: filepath.Join(exportDir, cfg.Endpoint)}, nil
	}
	hc, err := httpClient(cfg)
	if err != nil {
		return nil, err
	}
	base := httpBase{cfg: cfg, meta: meta, client: hc}
	switch cfg.Type {
	case "otlp":
		return &otlpDriver{base}, nil
	case "splunk_hec":
		// Load balancers in front of indexers pin acknowledgement queries to the indexer by cookie.
		jar, _ := cookiejar.New(nil)
		base.client.Jar = jar
		return &splunkDriver{httpBase: base, channel: hecChannel(cfg.ID)}, nil
	case "elasticsearch":
		return &elasticDriver{base}, nil
	case "sentinel":
		return &sentinelDriver{httpBase: base}, nil
	case "datadog":
		return &datadogDriver{base}, nil
	case "loki":
		return &lokiDriver{base}, nil
	case "webhook":
		return &webhookDriver{base}, nil
	}
	return nil, fmt.Errorf("unknown sink type %q", cfg.Type)
}

// hostOf returns the host of a URL or of a host:port endpoint.
func hostOf(endpoint string) string {
	if strings.Contains(endpoint, "://") {
		if u, err := url.Parse(endpoint); err == nil {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

func tlsConfig(cfg models.ExportSink, serverName string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // explicit, audited admin option
	if strings.TrimSpace(cfg.CACertPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, errors.New("ca_cert_pem contains no valid certificate")
		}
		tc.RootCAs = pool
	}
	if strings.TrimSpace(cfg.ClientCertPEM) != "" || strings.TrimSpace(string(cfg.ClientKeyPEM)) != "" {
		pair, err := tls.X509KeyPair([]byte(cfg.ClientCertPEM), []byte(string(cfg.ClientKeyPEM)))
		if err != nil {
			return nil, fmt.Errorf("client certificate: %v", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return tc, nil
}

// guardedDialer refuses link-local destinations (cloud metadata endpoints). Private and loopback
// addresses are allowed on purpose: SIEM collectors are usually internal or local sidecars.
func guardedDialer() *net.Dialer { return netguard.Dialer(5 * time.Second) }

func httpClient(cfg models.ExportSink) (*http.Client, error) {
	tc, err := tlsConfig(cfg, "")
	if err != nil {
		return nil, err
	}
	tc.ServerName = "" // derived per request
	d := guardedDialer()
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type httpBase struct {
	cfg    models.ExportSink
	meta   Meta
	client *http.Client
}

func (h *httpBase) close() { h.client.CloseIdleConnections() }

// endpointWithPath appends path when the configured endpoint has no path of its own.
func endpointWithPath(endpoint, path string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = path
	}
	return u.String()
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// post sends a request and classifies the outcome.
func (h *httpBase) post(ctx context.Context, target string, body []byte, contentType string, compress bool, hdr map[string]string) ([]byte, error) {
	if compress {
		body = gz(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, &permanentError{err.Error()}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "AegisProxy-Exporter/"+h.meta.Version)
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range h.cfg.Headers {
		req.Header.Set(k, string(v))
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", redactURL(target), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return respBody, nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, redactURL(target), snippet(respBody))
	default:
		return nil, &permanentError{fmt.Sprintf("HTTP %d from %s: %s", resp.StatusCode, redactURL(target), snippet(respBody))}
	}
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "endpoint"
	}
	u.User, u.RawQuery = nil, ""
	return u.String()
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func replaceStream(pattern, stream string) string {
	return strings.ReplaceAll(pattern, "{stream}", stream)
}

// ---------------------------------------------------------------------------
// Syslog (RFC 5424 / RFC 3164 over UDP, TCP or TLS)
// ---------------------------------------------------------------------------

var facilities = map[string]int{"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10, "security": 13,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}

type syslogDriver struct {
	cfg  models.ExportSink
	meta Meta
	tls  *tls.Config
	mu   sync.Mutex
	conn net.Conn
}

func (d *syslogDriver) encode(ev Event) ([]byte, error) {
	payload, err := Payload(ev, d.cfg.Format, d.meta)
	if err != nil {
		return nil, err
	}
	fac, ok := facilities[d.cfg.SyslogFacility]
	if !ok {
		fac = 16
	}
	pri := fac*8 + syslogSeverity(ev.Severity)
	host := d.meta.Host
	if host == "" {
		host = "-"
	}
	var b bytes.Buffer
	if d.cfg.SyslogProtocol == "rfc3164" {
		fmt.Fprintf(&b, "<%d>%s %s aegisproxy: ", pri, ev.Time.UTC().Format(time.Stamp), host)
	} else {
		fmt.Fprintf(&b, "<%d>1 %s %s aegisproxy - %s - ", pri, ev.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"), host, strings.ToUpper(ev.Stream))
	}
	b.Write(bytes.ReplaceAll(payload, []byte("\n"), []byte(" ")))
	return b.Bytes(), nil
}

func (d *syslogDriver) dial(ctx context.Context) (net.Conn, error) {
	network := "tcp"
	if d.cfg.Transport == "udp" {
		network = "udp"
	}
	dl := guardedDialer()
	c, err := dl.DialContext(ctx, network, d.cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if d.cfg.Transport == "tls" {
		tc := tls.Client(c, d.tls)
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			c.Close()
			return nil, err
		}
		return tc, nil
	}
	return c, nil
}

func (d *syslogDriver) send(ctx context.Context, recs [][]byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		c, err := d.dial(ctx)
		if err != nil {
			return fmt.Errorf("syslog %s/%s: %v", d.cfg.Transport, d.cfg.Endpoint, err)
		}
		d.conn = c
	}
	_ = d.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	var buf bytes.Buffer
	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}
		_, err := d.conn.Write(buf.Bytes())
		buf.Reset()
		return err
	}
	for _, r := range recs {
		switch {
		case d.cfg.Transport == "udp":
			if len(r) > 65000 {
				r = r[:65000]
			}
			if _, err := d.conn.Write(r); err != nil {
				d.conn.Close()
				d.conn = nil
				return fmt.Errorf("syslog udp write: %v", err)
			}
			continue
		case d.cfg.SyslogFraming == "newline":
			buf.Write(r)
			buf.WriteByte('\n')
		default: // RFC 6587 octet counting
			buf.WriteString(strconv.Itoa(len(r)))
			buf.WriteByte(' ')
			buf.Write(r)
		}
		if buf.Len() > 256<<10 {
			if err := flush(); err != nil {
				d.conn.Close()
				d.conn = nil
				return fmt.Errorf("syslog write: %v", err)
			}
		}
	}
	if err := flush(); err != nil {
		d.conn.Close()
		d.conn = nil
		return fmt.Errorf("syslog write: %v", err)
	}
	return nil
}

func (d *syslogDriver) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}
}

// ---------------------------------------------------------------------------
// OpenTelemetry OTLP/HTTP (JSON encoding)
// ---------------------------------------------------------------------------

type otlpDriver struct{ httpBase }

func otlpValue(v any) map[string]any {
	switch x := v.(type) {
	case string:
		return map[string]any{"stringValue": x}
	case bool:
		return map[string]any{"boolValue": x}
	case int:
		return map[string]any{"intValue": strconv.Itoa(x)}
	case int64:
		return map[string]any{"intValue": strconv.FormatInt(x, 10)}
	case float64:
		return map[string]any{"doubleValue": x}
	case []string:
		vals := make([]map[string]any, len(x))
		for i, s := range x {
			vals[i] = map[string]any{"stringValue": s}
		}
		return map[string]any{"arrayValue": map[string]any{"values": vals}}
	}
	return map[string]any{"stringValue": fmt.Sprint(v)}
}

func otlpAttributes(m map[string]any) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"key": k, "value": otlpValue(m[k])})
	}
	return out
}

func (d *otlpDriver) encode(ev Event) ([]byte, error) {
	fields := Fields(ev, d.meta)
	msg := fields["message"]
	delete(fields, "message")
	delete(fields, "@timestamp")
	fields["event.name"] = "aegisproxy." + ev.Stream
	num, text := otelSeverity(ev.Severity)
	ts := strconv.FormatInt(ev.Time.UnixNano(), 10)
	return json.Marshal(map[string]any{
		"timeUnixNano": ts, "observedTimeUnixNano": strconv.FormatInt(time.Now().UnixNano(), 10),
		"severityNumber": num, "severityText": text, "body": map[string]any{"stringValue": msg},
		"attributes": otlpAttributes(fields),
	})
}

func (d *otlpDriver) send(ctx context.Context, recs [][]byte) error {
	res := map[string]any{"service.name": "aegisproxy", "service.version": d.meta.Version,
		"service.instance.id": d.meta.Node, "host.name": d.meta.Host}
	for k, v := range d.cfg.Labels {
		res[k] = v
	}
	resJSON, _ := json.Marshal(map[string]any{"attributes": otlpAttributes(res)})
	scope, _ := json.Marshal(map[string]any{"name": "aegisproxy.export", "version": d.meta.Version})
	var b bytes.Buffer
	b.WriteString(`{"resourceLogs":[{"resource":`)
	b.Write(resJSON)
	b.WriteString(`,"scopeLogs":[{"scope":`)
	b.Write(scope)
	b.WriteString(`,"logRecords":[`)
	b.Write(bytes.Join(recs, []byte(",")))
	b.WriteString(`]}]}]}`)
	target := d.cfg.Endpoint
	if !strings.HasSuffix(strings.TrimRight(target, "/"), "/v1/logs") {
		target = strings.TrimRight(target, "/") + "/v1/logs"
	}
	hdr := map[string]string{}
	if d.cfg.Secret != "" {
		hdr["Authorization"] = "Bearer " + string(d.cfg.Secret)
	}
	_, err := d.post(ctx, target, b.Bytes(), "application/json", true, hdr)
	return err
}

// ---------------------------------------------------------------------------
// Splunk HTTP Event Collector
// ---------------------------------------------------------------------------

type splunkDriver struct {
	httpBase
	channel string
}

// splunkAckTimeout bounds the wait for an indexer acknowledgement; the batch is resent afterwards.
var splunkAckTimeout = 2 * time.Minute

// hecChannel is the HEC request channel (a GUID) of a destination: stable across restarts, so Splunk
// keeps one acknowledgement queue per destination. Unsaved destinations (connection test) get a random one.
func hecChannel(id string) string {
	if id == "" {
		return newUUID()
	}
	sum := sha256.Sum256([]byte("aegisproxy-hec-channel:" + id))
	return formatUUID(sum[:16])
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return formatUUID(b)
}

func formatUUID(b []byte) string {
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func structuredPayload(ev Event, format string, meta Meta) (any, error) {
	p, err := Payload(ev, format, meta)
	if err != nil {
		return nil, err
	}
	if format == "cef" || format == "leef" {
		return string(p), nil
	}
	return json.RawMessage(p), nil
}

func (d *splunkDriver) encode(ev Event) ([]byte, error) {
	payload, err := structuredPayload(ev, d.cfg.Format, d.meta)
	if err != nil {
		return nil, err
	}
	st := d.cfg.SourceType
	if st == "" {
		st = "aegisproxy"
	}
	m := map[string]any{"time": float64(ev.Time.UnixMilli()) / 1000, "host": d.meta.Host, "source": "aegisproxy",
		"sourcetype": st + ":" + ev.Stream, "event": payload}
	if d.cfg.Index != "" {
		m["index"] = replaceStream(d.cfg.Index, ev.Stream)
	}
	return json.Marshal(m)
}

// send posts a batch. Tokens with indexer acknowledgement require a request channel and answer with an
// ackId; the batch then counts as delivered only once Splunk confirms it was indexed.
func (d *splunkDriver) send(ctx context.Context, recs [][]byte) error {
	hdr := map[string]string{"Authorization": "Splunk " + string(d.cfg.Secret), "X-Splunk-Request-Channel": d.channel}
	target := endpointWithPath(d.cfg.Endpoint, "/services/collector/event")
	resp, err := d.post(ctx, target, bytes.Join(recs, []byte("\n")), "application/json", true, hdr)
	if err != nil {
		return err
	}
	var r struct {
		AckID *int64 `json:"ackId"`
	}
	if json.Unmarshal(resp, &r) != nil || r.AckID == nil {
		return nil // indexer acknowledgement is disabled for this token
	}
	return d.awaitAck(ctx, target, *r.AckID, hdr)
}

// awaitAck polls /services/collector/ack until the batch is indexed. Without a confirmation in time the
// batch is resent (at-least-once delivery, as Splunk recommends for acknowledged HEC).
func (d *splunkDriver) awaitAck(ctx context.Context, eventURL string, id int64, hdr map[string]string) error {
	u, err := url.Parse(eventURL)
	if err != nil {
		return &permanentError{err.Error()}
	}
	if strings.HasSuffix(u.Path, "/event") || strings.HasSuffix(u.Path, "/raw") {
		u.Path = u.Path[:strings.LastIndex(u.Path, "/")] + "/ack"
	} else {
		u.Path = "/services/collector/ack"
	}
	q := u.Query()
	q.Set("channel", d.channel)
	u.RawQuery = q.Encode()
	body := []byte(fmt.Sprintf(`{"acks":[%d]}`, id))
	key := strconv.FormatInt(id, 10)
	deadline := time.Now().Add(splunkAckTimeout)
	wait := 200 * time.Millisecond
	for {
		if resp, err := d.post(ctx, u.String(), body, "application/json", false, hdr); err == nil {
			var r struct {
				Acks map[string]bool `json:"acks"`
			}
			if json.Unmarshal(resp, &r) == nil && r.Acks[key] {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Splunk HEC: no indexer acknowledgement for ackId %d within %s on channel %s; the batch will be resent", id, splunkAckTimeout, d.channel)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait < 5*time.Second {
			wait *= 2
		}
	}
}

// ---------------------------------------------------------------------------
// Elasticsearch / OpenSearch bulk API (ECS documents, data streams)
// ---------------------------------------------------------------------------

type elasticDriver struct{ httpBase }

func (d *elasticDriver) encode(ev Event) ([]byte, error) {
	index := d.cfg.Index
	if index == "" {
		index = "logs-aegisproxy.{stream}-default"
	}
	action, _ := json.Marshal(map[string]any{"create": map[string]string{"_index": replaceStream(index, ev.Stream), "_id": ev.ID}})
	doc, err := json.Marshal(Fields(ev, d.meta))
	if err != nil {
		return nil, err
	}
	return append(append(append(action, '\n'), doc...), '\n'), nil
}

func (d *elasticDriver) send(ctx context.Context, recs [][]byte) error {
	hdr := map[string]string{}
	switch {
	case d.cfg.Username != "":
		hdr["Authorization"] = basicAuth(d.cfg.Username, string(d.cfg.Secret))
	case string(d.cfg.Secret) != "":
		hdr["Authorization"] = "ApiKey " + string(d.cfg.Secret)
	}
	body, err := d.post(ctx, strings.TrimRight(d.cfg.Endpoint, "/")+"/_bulk", bytes.Join(recs, nil), "application/x-ndjson", true, hdr)
	if err != nil {
		return err
	}
	var res struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &res); err != nil || !res.Errors {
		return nil
	}
	rejected, retry := 0, false
	msg := ""
	for _, item := range res.Items {
		for _, r := range item {
			switch {
			case r.Status < 300 || r.Status == http.StatusConflict:
			case r.Status == http.StatusTooManyRequests || r.Status >= 500:
				retry = true
			default:
				rejected++
				if msg == "" && r.Error != nil {
					msg = r.Error.Type + ": " + r.Error.Reason
				}
			}
		}
	}
	if retry {
		return errors.New("bulk request partially throttled (429/5xx); retrying")
	}
	if rejected > 0 {
		return &partialError{rejected: rejected, msg: fmt.Sprintf("%d documents rejected: %s", rejected, msg)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Microsoft Sentinel (Azure Monitor Logs Ingestion API)
// ---------------------------------------------------------------------------

type sentinelDriver struct {
	httpBase
	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// SentinelColumns are the columns sent to the custom table (see docs/log-export.md).
func sentinelRecord(ev Event, meta Meta) map[string]any {
	f := Fields(ev, meta)
	str := func(k string) string { s, _ := f[k].(string); return s }
	rec := map[string]any{
		"TimeGenerated": ev.Time.UTC().Format(time.RFC3339Nano), "Stream": ev.Stream, "Severity": ev.Severity,
		"Message": str("message"), "EventId": ev.ID, "Node": meta.Node, "Action": str("event.action"),
		"Outcome": str("event.outcome"), "ServerName": str("source.domain"), "ServerIP": str("source.ip"),
		"Destination": str("destination.domain"), "Url": str("url.full"), "Method": str("http.request.method"),
		"RuleName": str("rule.name"), "Actor": str("user.name"), "ThreatIndicator": str("threat.indicator.name"),
		"ThreatSource": str("threat.indicator.provider"), "Data": NativeJSON(ev, meta)["data"],
	}
	if v, ok := f["http.response.status_code"].(int); ok {
		rec["StatusCode"] = v
	}
	return rec
}

func (d *sentinelDriver) encode(ev Event) ([]byte, error) {
	return json.Marshal(sentinelRecord(ev, d.meta))
}

// imdsEndpoint is the Azure Instance Metadata Service (managed identity). It is link-local and
// therefore unreachable through the guarded export client; only this fixed URL may be used.
var imdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

// monitorResource is the token audience of the Logs Ingestion API in the cloud of the data collection
// endpoint: Azure Government and Azure operated by 21Vianet use their own audiences.
func monitorResource(endpoint string) string {
	host := strings.ToLower(hostOf(endpoint))
	switch {
	case strings.HasSuffix(host, ".azure.us"):
		return "https://monitor.azure.us"
	case strings.HasSuffix(host, ".azure.cn"):
		return "https://monitor.azure.cn"
	}
	return "https://monitor.azure.com"
}

func (d *sentinelDriver) accessToken(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.token != "" && time.Now().Before(d.tokenExp) {
		return d.token, nil
	}
	authority := strings.TrimRight(d.cfg.AuthorityURL, "/")
	if authority == "" {
		authority = strings.TrimRight(os.Getenv("AZURE_AUTHORITY_HOST"), "/")
	}
	if authority == "" {
		authority = map[string]string{"https://monitor.azure.us": "https://login.microsoftonline.us",
			"https://monitor.azure.cn": "https://login.chinacloudapi.cn"}[monitorResource(d.cfg.Endpoint)]
	}
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	var req *http.Request
	var err error
	client := d.client
	switch d.cfg.AzureAuth {
	case "managed_identity":
		q := url.Values{"api-version": {"2018-02-01"}, "resource": {monitorResource(d.cfg.Endpoint)}}
		if d.cfg.ClientID != "" {
			q.Set("client_id", d.cfg.ClientID) // user-assigned identity
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, imdsEndpoint+"?"+q.Encode(), nil)
		if err == nil {
			req.Header.Set("Metadata", "true")
		}
		client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}} // never via a proxy
	case "workload_identity":
		tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
		assertion, rerr := os.ReadFile(tokenFile)
		if tokenFile == "" || rerr != nil {
			return "", &permanentError{"workload identity: AZURE_FEDERATED_TOKEN_FILE is not available (enable azure.workload.identity/use on the pod)"}
		}
		clientID, tenant := d.cfg.ClientID, d.cfg.TenantID
		if clientID == "" {
			clientID = os.Getenv("AZURE_CLIENT_ID")
		}
		if tenant == "" {
			tenant = os.Getenv("AZURE_TENANT_ID")
		}
		if clientID == "" || tenant == "" {
			return "", &permanentError{"workload identity: set tenant_id and client_id, or AZURE_TENANT_ID and AZURE_CLIENT_ID in the pod (injected by the workload identity webhook)"}
		}
		form := url.Values{"client_id": {clientID}, "scope": {monitorResource(d.cfg.Endpoint) + "//.default"}, "grant_type": {"client_credentials"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {strings.TrimSpace(string(assertion))}}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, authority+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		form := url.Values{"client_id": {d.cfg.ClientID}, "client_secret": {string(d.cfg.Secret)},
			"scope": {monitorResource(d.cfg.Endpoint) + "//.default"}, "grant_type": {"client_credentials"}}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, authority+"/"+url.PathEscape(d.cfg.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return "", &permanentError{err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Entra ID token request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"` // number (Entra) or string (IMDS)
		Error       string          `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tok)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		msg := fmt.Sprintf("Entra ID token request failed (HTTP %d): %s", resp.StatusCode, snippet([]byte(tok.Error)))
		if resp.StatusCode >= 500 {
			return "", errors.New(msg)
		}
		return "", &permanentError{msg}
	}
	exp, _ := strconv.Atoi(strings.Trim(string(tok.ExpiresIn), `"`))
	d.token = tok.AccessToken
	d.tokenExp = time.Now().Add(time.Duration(max(exp-120, 60)) * time.Second)
	return d.token, nil
}

func (d *sentinelDriver) send(ctx context.Context, recs [][]byte) error {
	target := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01",
		strings.TrimRight(d.cfg.Endpoint, "/"), url.PathEscape(d.cfg.DCRImmutableID), url.PathEscape(d.cfg.StreamName))
	// The API accepts at most 1 MB per call.
	for start := 0; start < len(recs); {
		size, end := 2, start
		for end < len(recs) && (end == start || size+len(recs[end])+1 < 900<<10) {
			size += len(recs[end]) + 1
			end++
		}
		tok, err := d.accessToken(ctx)
		if err != nil {
			return err
		}
		body := append(append([]byte{'['}, bytes.Join(recs[start:end], []byte(","))...), ']')
		// The client request ID lets Microsoft support trace a failed upload.
		reqID := newUUID()
		if _, err := d.post(ctx, target, body, "application/json", true, map[string]string{"Authorization": "Bearer " + tok, "x-ms-client-request-id": reqID}); err != nil {
			var pe *permanentError
			if errors.As(err, &pe) && strings.Contains(pe.msg, "HTTP 401") {
				d.mu.Lock()
				d.token = ""
				d.mu.Unlock()
				return fmt.Errorf("%s (x-ms-client-request-id %s)", pe.msg, reqID) // retry with a fresh token
			}
			if errors.As(err, &pe) {
				return &permanentError{fmt.Sprintf("%s (x-ms-client-request-id %s)", pe.msg, reqID)}
			}
			return fmt.Errorf("%w (x-ms-client-request-id %s)", err, reqID)
		}
		start = end
	}
	return nil
}

// ---------------------------------------------------------------------------
// Datadog Logs API
// ---------------------------------------------------------------------------

type datadogDriver struct{ httpBase }

// nest turns dotted keys into nested objects.
func nest(flat map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range flat {
		parts := strings.Split(k, ".")
		cur := out
		for i, p := range parts {
			if i == len(parts)-1 {
				if _, exists := cur[p].(map[string]any); !exists {
					cur[p] = v
				}
				break
			}
			next, ok := cur[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[p] = next
			}
			cur = next
		}
	}
	return out
}

func (d *datadogDriver) encode(ev Event) ([]byte, error) {
	f := Fields(ev, d.meta)
	msg := f["message"]
	delete(f, "message")
	tags := []string{"stream:" + ev.Stream}
	keys := make([]string, 0, len(d.cfg.Labels))
	for k := range d.cfg.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		tags = append(tags, k+":"+d.cfg.Labels[k])
	}
	status := map[string]string{"info": "info", "low": "notice", "medium": "warning", "high": "error", "critical": "critical"}[ev.Severity]
	// Agent-compatible item: the reserved attributes at the top level and every other attribute as a JSON
	// message, which Datadog parses into (nested, facet-able) attributes. Datadog's intake also accepts
	// extra top-level attributes, but Observability Pipelines / Vector intakes only take this schema.
	attrs := nest(f)
	attrs["message"] = msg
	inner, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"ddsource": "aegisproxy", "service": "aegisproxy", "hostname": d.meta.Host,
		"ddtags": strings.Join(tags, ","), "status": status, "timestamp": ev.Time.UnixMilli(), "message": string(inner)})
}

func (d *datadogDriver) send(ctx context.Context, recs [][]byte) error {
	endpoint := d.cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://http-intake.logs.datadoghq.com"
	}
	body := append(append([]byte{'['}, bytes.Join(recs, []byte(","))...), ']')
	_, err := d.post(ctx, endpointWithPath(endpoint, "/api/v2/logs"), body, "application/json", true, map[string]string{"DD-API-KEY": string(d.cfg.Secret)})
	return err
}

// ---------------------------------------------------------------------------
// Grafana Loki push API
// ---------------------------------------------------------------------------

type lokiDriver struct{ httpBase }

type lokiRecord struct {
	L map[string]string `json:"l"`
	T string            `json:"t"`
	V string            `json:"v"`
}

func (d *lokiDriver) encode(ev Event) ([]byte, error) {
	line, err := Payload(ev, d.cfg.Format, d.meta)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{"job": "aegisproxy", "stream": ev.Stream, "level": ev.Severity, "node": d.meta.Node}
	if ev.Flow != nil {
		labels["verdict"] = ev.Flow.Verdict
	}
	for k, v := range d.cfg.Labels {
		labels[k] = v
	}
	return json.Marshal(lokiRecord{L: labels, T: strconv.FormatInt(ev.Time.UnixNano(), 10), V: string(line)})
}

func (d *lokiDriver) send(ctx context.Context, recs [][]byte) error {
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	byKey := map[string]*stream{}
	var order []string
	for _, raw := range recs {
		var r lokiRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		keys := make([]string, 0, len(r.L))
		for k := range r.L {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var kb strings.Builder
		for _, k := range keys {
			kb.WriteString(k + "=" + r.L[k] + ",")
		}
		key := kb.String()
		s := byKey[key]
		if s == nil {
			s = &stream{Stream: r.L}
			byKey[key] = s
			order = append(order, key)
		}
		s.Values = append(s.Values, [2]string{r.T, r.V})
	}
	streams := make([]*stream, 0, len(order))
	for _, k := range order {
		streams = append(streams, byKey[k])
	}
	body, _ := json.Marshal(map[string]any{"streams": streams})
	hdr := map[string]string{}
	switch {
	case d.cfg.Username != "":
		hdr["Authorization"] = basicAuth(d.cfg.Username, string(d.cfg.Secret))
	case string(d.cfg.Secret) != "":
		hdr["Authorization"] = "Bearer " + string(d.cfg.Secret)
	}
	_, err := d.post(ctx, endpointWithPath(d.cfg.Endpoint, "/loki/api/v1/push"), body, "application/json", false, hdr)
	return err
}

// ---------------------------------------------------------------------------
// Generic webhook (HMAC-signed JSON batches)
// ---------------------------------------------------------------------------

type webhookDriver struct{ httpBase }

func (d *webhookDriver) encode(ev Event) ([]byte, error) {
	p, err := structuredPayload(ev, d.cfg.Format, d.meta)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// WebhookSignature returns the X-Aegis-Signature value for a body.
func WebhookSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (d *webhookDriver) send(ctx context.Context, recs [][]byte) error {
	idb := make([]byte, 8)
	_, _ = rand.Read(idb)
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"source":"aegisproxy","version":%q,"node":%q,"sent_at":%q,"events":[`, d.meta.Version, d.meta.Node, time.Now().UTC().Format(time.RFC3339Nano))
	b.Write(bytes.Join(recs, []byte(",")))
	b.WriteString("]}")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	hdr := map[string]string{"X-Aegis-Timestamp": ts, "X-Aegis-Delivery": hex.EncodeToString(idb)}
	if d.cfg.Secret != "" {
		hdr["X-Aegis-Signature"] = WebhookSignature(string(d.cfg.Secret), ts, b.Bytes())
	}
	_, err := d.post(ctx, d.cfg.Endpoint, b.Bytes(), "application/json", false, hdr)
	return err
}

// ---------------------------------------------------------------------------
// Local file (JSON Lines / CEF / LEEF) for Filebeat, Fluent Bit, Vector, Splunk UF …
// ---------------------------------------------------------------------------

const (
	fileRotateBytes = 100 << 20
	fileKeep        = 5
)

type fileDriver struct {
	cfg  models.ExportSink
	meta Meta
	path string
	mu   sync.Mutex
}

func (d *fileDriver) encode(ev Event) ([]byte, error) { return Payload(ev, d.cfg.Format, d.meta) }

func (d *fileDriver) send(_ context.Context, recs [][]byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.path), 0o750); err != nil {
		return err
	}
	if fi, err := os.Stat(d.path); err == nil && fi.Size() > fileRotateBytes {
		for i := fileKeep - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", d.path, i), fmt.Sprintf("%s.%d", d.path, i+1))
		}
		_ = os.Rename(d.path, d.path+".1")
	}
	f, err := os.OpenFile(d.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	var b bytes.Buffer
	for _, r := range recs {
		b.Write(bytes.ReplaceAll(r, []byte("\n"), []byte(" ")))
		b.WriteByte('\n')
	}
	_, err = f.Write(b.Bytes())
	return err
}

func (d *fileDriver) close() {}

// The response excerpt follows the destination URL after ": " (the URL itself contains ":" without a space).
var httpErrDetail = regexp.MustCompile(`(?s)^(.*?HTTP \d{3} from \S+?): .*$`)

// ShortError drops the response body excerpt from a delivery error (shown to non-administrators).
func ShortError(msg string) string {
	if m := httpErrDetail.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	if len(msg) > 200 {
		return msg[:200]
	}
	return msg
}
