package export

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"aegisproxy/control-plane/internal/models"
)

// TypeInfo describes a sink type for the console.
type TypeInfo struct {
	Type        string   `json:"type"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Formats     []string `json:"formats"`
	Endpoint    string   `json:"endpoint_hint"`
	SecretLabel string   `json:"secret_label,omitempty"`
	Fields      []string `json:"fields"` // type-specific fields the form should show
}

var Types = []TypeInfo{
	{"syslog", "Syslog (rsyslog, syslog-ng, QRadar, ArcSight)", "RFC 5424 or RFC 3164 over UDP, TCP or TLS. Records as JSON, ECS JSON, CEF or LEEF.",
		[]string{"json", "ecs", "cef", "leef"}, "siem.corp.example:6514", "", []string{"transport", "syslog_protocol", "syslog_facility", "syslog_framing", "tls"}},
	{"otlp", "OpenTelemetry (OTLP/HTTP)", "OTLP logs (JSON encoding, gzip) to an OpenTelemetry Collector or any OTLP backend (Grafana, Elastic, Dynatrace, New Relic, Honeycomb …).",
		[]string{"otel"}, "https://otel-collector.corp.example:4318", "Bearer token (optional; or use headers)", []string{"headers", "labels", "tls"}},
	{"splunk_hec", "Splunk HTTP Event Collector", "Events to Splunk Enterprise / Splunk Cloud via HEC.",
		[]string{"json", "ecs", "cef", "leef"}, "https://splunk.corp.example:8088", "HEC token", []string{"index", "source_type", "tls"}},
	{"elasticsearch", "Elasticsearch / OpenSearch", "Bulk API with Elastic Common Schema documents (data streams by default).",
		[]string{"ecs"}, "https://elastic.corp.example:9200", "API key (or password with a user name)", []string{"index", "username", "tls"}},
	{"sentinel", "Microsoft Sentinel (Azure Monitor Logs Ingestion API)", "Custom table via a data collection rule; authenticates with an Entra ID app registration.",
		[]string{"structured"}, "https://<dce>.<region>.ingest.monitor.azure.com", "Client secret", []string{"tenant_id", "client_id", "dcr_immutable_id", "stream_name", "authority_url"}},
	{"datadog", "Datadog Logs", "Datadog HTTP log intake (choose the endpoint of your Datadog site).",
		[]string{"structured"}, "https://http-intake.logs.datadoghq.eu", "API key", []string{"labels"}},
	{"loki", "Grafana Loki", "Loki push API with low-cardinality labels (job, stream, level, verdict, node).",
		[]string{"json", "ecs", "cef", "leef"}, "https://loki.corp.example:3100", "Password or bearer token", []string{"username", "labels", "headers", "tls"}},
	{"webhook", "Webhook (HTTPS JSON)", "JSON batches with HMAC-SHA256 signature (X-Aegis-Signature) for custom pipelines, Kafka REST proxies, SOAR.",
		[]string{"json", "ecs"}, "https://hooks.corp.example/aegis", "HMAC signing secret (optional)", []string{"headers", "tls"}},
	{"file", "Local file (JSON Lines)", "Rotating file in the export directory for Filebeat, Fluent Bit, Vector or a Splunk forwarder.",
		[]string{"json", "ecs", "cef", "leef"}, "aegis-events.jsonl", "", nil},
}

var (
	fileNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)
	labelKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,63}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)
	streams      = []string{models.StreamAudit, models.StreamTraffic, models.StreamSecurity}
	forbiddenHdr = []string{"host", "content-length", "content-type", "content-encoding", "transfer-encoding", "connection", "te", "upgrade"}
)

func typeInfo(t string) (TypeInfo, bool) {
	for _, ti := range Types {
		if ti.Type == t {
			return ti, true
		}
	}
	return TypeInfo{}, false
}

func hasCtl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func httpURL(field, raw string, httpsOnly bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (httpsOnly || u.Scheme != "http")) || hasCtl(raw) || len(raw) > 500 {
		if httpsOnly {
			return fmt.Errorf("%s must be an https:// URL", field)
		}
		return fmt.Errorf("%s must be an http(s):// URL", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain credentials; use the secret field", field)
	}
	return nil
}

// Validate normalizes a sink (secrets already merged) and reports configuration errors.
func Validate(s *models.ExportSink) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 80 || hasCtl(s.Name) {
		return errors.New("name is required (max 80 characters)")
	}
	ti, ok := typeInfo(s.Type)
	if !ok {
		return fmt.Errorf("unknown type %q", s.Type)
	}
	if len(s.Streams) == 0 {
		return errors.New("select at least one stream (audit, traffic, security)")
	}
	for _, st := range s.Streams {
		if !slices.Contains(streams, st) {
			return fmt.Errorf("unknown stream %q", st)
		}
	}
	slices.Sort(s.Streams)
	s.Streams = slices.Compact(s.Streams)
	if s.Format == "" || !slices.Contains(ti.Formats, s.Format) {
		if s.Format != "" && len(ti.Formats) > 1 {
			return fmt.Errorf("format %q is not supported by %s (use %s)", s.Format, s.Type, strings.Join(ti.Formats, ", "))
		}
		s.Format = ti.Formats[0]
	}
	if s.TrafficFilter == "" {
		s.TrafficFilter = "all"
	}
	if !slices.Contains([]string{"all", "blocked", "security", "allowed"}, s.TrafficFilter) {
		return errors.New("traffic_filter must be all, blocked, security or allowed")
	}
	if s.MinSeverity == "" {
		s.MinSeverity = "low"
	}
	if _, ok := severityRank[s.MinSeverity]; !ok || s.MinSeverity == "info" {
		return errors.New("min_severity must be low, medium, high or critical")
	}
	s.Endpoint = strings.TrimSpace(s.Endpoint)
	switch s.Type {
	case "syslog":
		host, port, err := net.SplitHostPort(s.Endpoint)
		if err != nil || host == "" || hasCtl(s.Endpoint) {
			return errors.New("endpoint must be host:port (e.g. siem.corp.example:514)")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New("invalid syslog port")
		}
		if s.Transport == "" {
			s.Transport = "tcp"
		}
		if !slices.Contains([]string{"udp", "tcp", "tls"}, s.Transport) {
			return errors.New("transport must be udp, tcp or tls")
		}
		if s.SyslogProtocol == "" {
			s.SyslogProtocol = "rfc5424"
		}
		if !slices.Contains([]string{"rfc5424", "rfc3164"}, s.SyslogProtocol) {
			return errors.New("syslog_protocol must be rfc5424 or rfc3164")
		}
		if s.SyslogFacility == "" {
			s.SyslogFacility = "local0"
		}
		if _, ok := facilities[s.SyslogFacility]; !ok {
			return fmt.Errorf("unknown syslog facility %q", s.SyslogFacility)
		}
		if s.SyslogFraming == "" {
			s.SyslogFraming = "octet-counting"
		}
		if !slices.Contains([]string{"octet-counting", "newline"}, s.SyslogFraming) {
			return errors.New("syslog_framing must be octet-counting or newline")
		}
	case "file":
		if !fileNameRe.MatchString(s.Endpoint) || strings.Contains(s.Endpoint, "..") {
			return errors.New("endpoint must be a plain file name (written to the export directory)")
		}
	case "datadog":
		if s.Endpoint == "" {
			s.Endpoint = "https://http-intake.logs.datadoghq.com"
		}
		if err := httpURL("endpoint", s.Endpoint, true); err != nil {
			return err
		}
	case "sentinel":
		if err := httpURL("endpoint (data collection endpoint)", s.Endpoint, true); err != nil {
			return err
		}
		if s.AzureAuth == "" {
			s.AzureAuth = "client_secret"
		}
		if !slices.Contains([]string{"client_secret", "workload_identity", "managed_identity"}, s.AzureAuth) {
			return errors.New("azure_auth must be client_secret, workload_identity or managed_identity")
		}
		// Managed identity needs neither; workload identity falls back to AZURE_TENANT_ID / AZURE_CLIENT_ID,
		// which the AKS workload identity webhook injects into the pod.
		required := []struct{ n, v string }{{"dcr_immutable_id", s.DCRImmutableID}}
		if s.AzureAuth == "client_secret" {
			required = append(required, struct{ n, v string }{"tenant_id", s.TenantID}, struct{ n, v string }{"client_id", s.ClientID})
		}
		for _, f := range required {
			if strings.TrimSpace(f.v) == "" || len(f.v) > 128 || hasCtl(f.v) {
				return fmt.Errorf("%s is required", f.n)
			}
		}
		if len(s.ClientID) > 128 || hasCtl(s.ClientID) || len(s.TenantID) > 128 || hasCtl(s.TenantID) {
			return errors.New("invalid tenant_id or client_id")
		}
		if s.StreamName == "" {
			s.StreamName = "Custom-AegisProxy_CL"
		}
		if !strings.HasPrefix(s.StreamName, "Custom-") || len(s.StreamName) > 128 || hasCtl(s.StreamName) {
			return errors.New("stream_name must start with Custom- (the stream declared in the DCR)")
		}
		if s.AuthorityURL != "" {
			if err := httpURL("authority_url", s.AuthorityURL, true); err != nil {
				return err
			}
		}
	default:
		if err := httpURL("endpoint", s.Endpoint, false); err != nil {
			return err
		}
	}
	switch s.Type {
	case "splunk_hec", "datadog", "sentinel":
		if s.Type == "sentinel" && s.AzureAuth != "client_secret" {
			break
		}
		if s.Secret == "" {
			return fmt.Errorf("%s is required", strings.ToLower(ti.SecretLabel))
		}
	}
	if len(s.Index) > 200 || hasCtl(s.Index) || len(s.SourceType) > 100 || hasCtl(s.SourceType) || len(s.Username) > 200 || hasCtl(s.Username) {
		return errors.New("index, source_type or username too long or invalid")
	}
	if len(s.Labels) > 20 {
		return errors.New("at most 20 labels")
	}
	for k, v := range s.Labels {
		if !labelKeyRe.MatchString(k) || len(v) > 128 || hasCtl(v) {
			return fmt.Errorf("invalid label %q", k)
		}
	}
	if len(s.Headers) > 20 {
		return errors.New("at most 20 headers")
	}
	for k, v := range s.Headers {
		if !headerNameRe.MatchString(k) || slices.Contains(forbiddenHdr, strings.ToLower(k)) {
			return fmt.Errorf("header %q is not allowed", k)
		}
		if strings.ContainsAny(string(v), "\r\n\x00") || len(v) > 4096 {
			return fmt.Errorf("invalid value for header %q", k)
		}
	}
	if strings.ContainsAny(string(s.Secret), "\r\n\x00") || len(s.Secret) > 4096 {
		return errors.New("invalid secret")
	}
	if strings.TrimSpace(s.CACertPEM) != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(s.CACertPEM)) {
			return errors.New("ca_cert_pem contains no valid PEM certificate")
		}
	}
	if (strings.TrimSpace(s.ClientCertPEM) == "") != (strings.TrimSpace(string(s.ClientKeyPEM)) == "") {
		return errors.New("client certificate and client key must be set together")
	}
	if s.ClientCertPEM != "" {
		if b, _ := pem.Decode([]byte(s.ClientCertPEM)); b == nil {
			return errors.New("client_cert_pem is not PEM")
		}
		if _, err := tlsConfig(*s, ""); err != nil {
			return err
		}
	}
	if s.BatchSize == 0 {
		s.BatchSize = 500
	}
	if s.BatchSize < 1 || s.BatchSize > 5000 {
		return errors.New("batch_size must be between 1 and 5000")
	}
	if s.FlushSeconds == 0 {
		s.FlushSeconds = 2
	}
	if s.FlushSeconds < 1 || s.FlushSeconds > 300 {
		return errors.New("flush_seconds must be between 1 and 300")
	}
	if s.SpoolMB == 0 {
		s.SpoolMB = 256
	}
	if s.SpoolMB < 16 || s.SpoolMB > 102400 {
		return errors.New("spool_mb must be between 16 and 102400")
	}
	return nil
}
