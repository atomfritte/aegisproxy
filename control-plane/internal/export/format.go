package export

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// Event is one record handed to the exporter (spooled as JSON).
type Event struct {
	Stream   string                `json:"stream"`
	Time     time.Time             `json:"time"`
	ID       string                `json:"id"`
	Severity string                `json:"severity"` // info | low | medium | high | critical
	Audit    *models.AuditEvent    `json:"audit,omitempty"`
	Flow     *models.TrafficFlow   `json:"flow,omitempty"`
	Security *models.SecurityEvent `json:"security,omitempty"`
}

// AuditEvent, FlowEvent and SecurityEvent build exporter events from the domain models.
func AuditEvent(ev models.AuditEvent) Event {
	return Event{Stream: models.StreamAudit, Time: ev.Timestamp, ID: ev.ID, Severity: "info", Audit: &ev}
}

func FlowEvent(f models.TrafficFlow) Event {
	sev := "info"
	switch {
	case models.IsSecurityVerdict(f.Verdict):
		sev = "medium"
	case !models.IsAllowedVerdict(f.Verdict):
		sev = "low"
	}
	return Event{Stream: models.StreamTraffic, Time: f.Timestamp, ID: f.ID, Severity: sev, Flow: &f}
}

func SecurityEvent(ev models.SecurityEvent) Event {
	return Event{Stream: models.StreamSecurity, Time: ev.Timestamp, ID: fmt.Sprintf("%s-%d", ev.ID, ev.Count), Severity: ev.Severity, Security: &ev}
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// syslogSeverity maps to RFC 5424 severities.
func syslogSeverity(sev string) int {
	switch sev {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium":
		return 4
	case "low":
		return 5
	}
	return 6
}

// otelSeverity maps to OpenTelemetry severity numbers and texts.
func otelSeverity(sev string) (int, string) {
	switch sev {
	case "critical":
		return 21, "FATAL"
	case "high":
		return 17, "ERROR"
	case "medium":
		return 13, "WARN"
	case "low":
		return 10, "INFO2"
	}
	return 9, "INFO"
}

func cefSeverity(sev string) int {
	switch sev {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	}
	return 1
}

func stripQuery(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// redacted applies per-sink privacy options to an event (copy-on-write).
func redacted(ev Event, sink *models.ExportSink) Event {
	if ev.Flow != nil && sink.RedactQuery {
		f := *ev.Flow
		f.FullURL, f.Path = stripQuery(f.FullURL), stripQuery(f.Path)
		f.RedirectLocation, f.RedirectParentURL = stripQuery(f.RedirectLocation), stripQuery(f.RedirectParentURL)
		ev.Flow = &f
	}
	if ev.Security != nil && sink.RedactQuery {
		s := *ev.Security
		s.URL = stripQuery(s.URL)
		ev.Security = &s
	}
	return ev
}

// Message is a one-line human readable summary.
func Message(ev Event) string {
	switch {
	case ev.Flow != nil:
		f := ev.Flow
		reason := f.MatchedRuleName
		if reason == "" {
			reason = f.BlockReason
		}
		msg := fmt.Sprintf("%s %s %s from %s (%s)", f.Verdict, f.Method, f.FullURL, f.ServerHostname, f.ServerIP)
		if reason != "" {
			msg += ": " + reason
		}
		return msg
	case ev.Audit != nil:
		return fmt.Sprintf("%s by %s: %s", ev.Audit.Action, ev.Audit.Actor, ev.Audit.Summary)
	case ev.Security != nil:
		s := ev.Security
		return fmt.Sprintf("%s %s (%s) on %s (%s): %s", strings.ToUpper(s.Severity), s.Type, s.Action, s.ServerHostname, s.ServerIP, s.Detail)
	}
	return ev.Stream
}

func lower(s string) string { return strings.ToLower(s) }

// Fields returns the flat structured representation (Elastic Common Schema names, which largely match
// the OpenTelemetry semantic conventions; product-specific fields live under "aegisproxy.").
func Fields(ev Event, meta Meta) map[string]any {
	m := map[string]any{
		"@timestamp":       ev.Time.UTC().Format(time.RFC3339Nano),
		"message":          Message(ev),
		"ecs.version":      "8.11.0",
		"event.module":     "aegisproxy",
		"event.dataset":    "aegisproxy." + ev.Stream,
		"event.id":         ev.ID,
		"log.level":        ev.Severity,
		"observer.vendor":  "AegisProxy",
		"observer.product": "AegisProxy Egress Gateway",
		"observer.type":    "proxy",
		"observer.version": meta.Version,
		"observer.name":    meta.Node,
	}
	put := func(k string, v any) {
		switch x := v.(type) {
		case string:
			if x == "" {
				return
			}
		case int:
			if x == 0 {
				return
			}
		case int64:
			if x == 0 {
				return
			}
		case []string:
			if len(x) == 0 {
				return
			}
		}
		m[k] = v
	}
	switch {
	case ev.Flow != nil:
		f := ev.Flow
		allowed := models.IsAllowedVerdict(f.Verdict)
		m["event.kind"] = "event"
		m["event.category"] = []string{"network", "web"}
		if allowed {
			m["event.type"], m["event.outcome"] = []string{"allowed", "connection"}, "success"
		} else {
			m["event.type"], m["event.outcome"] = []string{"denied", "connection"}, "failure"
		}
		m["event.action"] = lower(f.Verdict)
		put("event.reason", f.BlockReason)
		if f.LatencyMs > 0 {
			m["event.duration"] = f.LatencyMs * int64(time.Millisecond)
		}
		put("source.ip", strings.TrimPrefix(f.ServerIP, "::ffff:"))
		put("source.domain", f.ServerHostname)
		put("destination.domain", f.Host)
		put("destination.port", f.Port)
		put("destination.ip", f.ResolvedIP)
		put("url.full", f.FullURL)
		put("url.domain", f.Host)
		put("url.scheme", f.Scheme)
		if u, err := url.Parse(f.FullURL); err == nil {
			put("url.path", u.Path)
			put("url.query", u.RawQuery)
		}
		put("http.request.method", f.Method)
		put("http.response.status_code", f.StatusCode)
		put("http.request.bytes", f.BytesSent)
		put("http.response.bytes", f.BytesReceived)
		put("http.response.mime_type", f.ContentType)
		put("user_agent.original", f.UserAgent)
		put("rule.id", f.MatchedRuleID)
		put("rule.name", f.MatchedRuleName)
		put("file.hash.sha256", f.ContentSHA256)
		put("threat.indicator.name", f.ThreatIndicator)
		put("threat.indicator.provider", f.ThreatSource)
		put("aegisproxy.verdict", f.Verdict)
		put("aegisproxy.server.id", f.ServerID)
		put("aegisproxy.server.hostname", f.ServerHostname)
		put("aegisproxy.server.groups", f.GroupIDs)
		put("aegisproxy.threat.category", f.ThreatCategory)
		put("aegisproxy.file_type", f.FileType)
		put("aegisproxy.av.result", f.AVResult)
		put("aegisproxy.av.signature", f.AVSignature)
		put("aegisproxy.dlp.findings", f.DLPFindings)
		put("aegisproxy.security_flags", f.SecurityFlags)
		put("aegisproxy.redirect.parent_url", f.RedirectParentURL)
		put("aegisproxy.redirect.location", f.RedirectLocation)
		put("aegisproxy.session_id", f.SessionID)
		put("aegisproxy.data_plane_id", f.DataPlaneID)
		m["aegisproxy.tls_intercepted"] = f.TLSIntercepted
	case ev.Audit != nil:
		a := ev.Audit
		cat := "configuration"
		if a.Category == "IDENTITY" {
			cat = "iam"
		}
		m["event.kind"] = "event"
		m["event.category"] = []string{cat}
		m["event.type"] = []string{"change"}
		m["event.action"] = lower(a.Action)
		m["event.outcome"] = "success"
		put("user.name", a.Actor)
		put("user.roles", []string{a.ActorRole})
		put("aegisproxy.audit.category", a.Category)
		put("aegisproxy.audit.entity.type", a.EntityType)
		put("aegisproxy.audit.entity.id", a.EntityID)
		put("aegisproxy.audit.entity.name", a.EntityName)
		put("aegisproxy.audit.scope_groups", a.ScopeGroups)
		put("aegisproxy.audit.revision", int64(a.Revision))
		put("aegisproxy.audit.hash", a.EventHash)
		put("aegisproxy.audit.prev_hash", a.PrevHash)
		put("aegisproxy.audit.before", a.BeforeState)
		put("aegisproxy.audit.after", a.AfterState)
	case ev.Security != nil:
		s := ev.Security
		m["event.kind"] = "alert"
		cat := "intrusion_detection"
		switch s.Type {
		case models.SecurityEventMalware:
			cat = "malware"
		case models.SecurityEventThreat:
			cat = "threat"
		}
		m["event.category"] = []string{cat}
		m["event.type"] = []string{"indicator"}
		if s.Action == "blocked" {
			m["event.type"] = []string{"indicator", "denied"}
		}
		m["event.action"] = lower(s.Type)
		m["event.severity"] = severityRank[s.Severity] * 25
		put("event.reason", s.Detail)
		put("source.ip", strings.TrimPrefix(s.ServerIP, "::ffff:"))
		put("source.domain", s.ServerHostname)
		put("destination.domain", s.Host)
		put("url.full", s.URL)
		put("http.request.method", s.Method)
		put("threat.indicator.name", s.Indicator)
		put("threat.indicator.provider", s.Source)
		put("aegisproxy.verdict", s.Verdict)
		put("aegisproxy.server.id", s.ServerID)
		put("aegisproxy.server.groups", s.GroupIDs)
		put("aegisproxy.security.type", s.Type)
		put("aegisproxy.security.action", s.Action)
		put("aegisproxy.security.count", s.Count)
		put("aegisproxy.security.flow_id", s.FlowID)
	}
	return m
}

// Meta describes the emitting node.
type Meta struct {
	Node    string // cluster node / instance id
	Host    string // host name
	Version string
}

// NativeJSON is the product's own JSON document: envelope + the unmodified domain record.
func NativeJSON(ev Event, meta Meta) map[string]any {
	var data any
	switch {
	case ev.Flow != nil:
		data = ev.Flow
	case ev.Audit != nil:
		data = ev.Audit
	case ev.Security != nil:
		data = ev.Security
	}
	return map[string]any{
		"timestamp": ev.Time.UTC().Format(time.RFC3339Nano),
		"stream":    ev.Stream,
		"severity":  ev.Severity,
		"product":   "aegisproxy",
		"version":   meta.Version,
		"node":      meta.Node,
		"message":   Message(ev),
		"data":      data,
	}
}

// ---------------------------------------------------------------------------
// CEF (ArcSight) and LEEF (QRadar)
// ---------------------------------------------------------------------------

type escaper struct{ r *strings.Replacer }

// Replace escapes the format's delimiters and replaces every other control character (ESC, DEL,
// C1 controls, Unicode line/paragraph separators), which SIEM parsers and terminals would interpret.
func (e escaper) Replace(v string) string {
	v = strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, v)
	return e.r.Replace(v)
}

var (
	cefHeaderEsc = escaper{strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ", "\t", " ")}
	cefValueEsc  = escaper{strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`, "\t", " ")}
	leefValueEsc = escaper{strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")}
)

type kv struct{ k, v string }

func eventKVs(ev Event) (sigID, name string, kvs []kv) {
	add := func(k, v string) {
		if v != "" {
			kvs = append(kvs, kv{k, v})
		}
	}
	add("rt", strconv.FormatInt(ev.Time.UnixMilli(), 10))
	switch {
	case ev.Flow != nil:
		f := ev.Flow
		sigID, name = f.Verdict, "Egress "+strings.ToLower(strings.ReplaceAll(f.Verdict, "_", " "))
		add("src", strings.TrimPrefix(f.ServerIP, "::ffff:"))
		add("shost", f.ServerHostname)
		add("dhost", f.Host)
		if f.Port > 0 {
			add("dpt", strconv.Itoa(f.Port))
		}
		add("dst", f.ResolvedIP)
		add("request", f.FullURL)
		add("requestMethod", f.Method)
		add("requestClientApplication", f.UserAgent)
		add("act", f.Verdict)
		add("reason", f.BlockReason)
		add("cs1Label", "Rule")
		add("cs1", f.MatchedRuleName)
		add("cs2Label", "ServerGroups")
		add("cs2", strings.Join(f.GroupIDs, ","))
		if f.ThreatCategory != "" {
			add("cs3Label", "ThreatCategory")
			add("cs3", f.ThreatCategory)
			add("cs4Label", "ThreatSource")
			add("cs4", f.ThreatSource)
		}
		if f.StatusCode > 0 {
			add("cn1Label", "HTTPStatus")
			add("cn1", strconv.Itoa(f.StatusCode))
		}
		add("in", strconv.FormatInt(f.BytesReceived, 10))
		add("out", strconv.FormatInt(f.BytesSent, 10))
		add("fileHash", f.ContentSHA256)
		add("externalId", f.ID)
	case ev.Audit != nil:
		a := ev.Audit
		sigID, name = a.Action, a.Action
		add("suser", a.Actor)
		add("cs1Label", "Role")
		add("cs1", a.ActorRole)
		add("cat", a.Category)
		add("act", a.Action)
		add("cs2Label", "Entity")
		add("cs2", a.EntityType+"/"+a.EntityID)
		add("cs3Label", "EventHash")
		add("cs3", a.EventHash)
		add("msg", a.Summary)
		add("externalId", a.ID)
	case ev.Security != nil:
		s := ev.Security
		sigID, name = s.Type, s.Detail
		add("src", strings.TrimPrefix(s.ServerIP, "::ffff:"))
		add("shost", s.ServerHostname)
		add("dhost", s.Host)
		add("request", s.URL)
		add("act", s.Action)
		add("cat", s.Type)
		add("cs1Label", "Indicator")
		add("cs1", s.Indicator)
		add("cs2Label", "Source")
		add("cs2", s.Source)
		add("cnt", strconv.Itoa(s.Count))
		add("msg", s.Detail)
		add("externalId", s.ID)
	}
	return sigID, name, kvs
}

// CEF renders ArcSight Common Event Format.
func CEF(ev Event, meta Meta) string {
	sig, name, kvs := eventKVs(ev)
	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|AegisProxy|Egress Gateway|%s|%s|%s|%d|", cefHeaderEsc.Replace(meta.Version),
		cefHeaderEsc.Replace(sig), cefHeaderEsc.Replace(truncate(name, 512)), cefSeverity(ev.Severity))
	fmt.Fprintf(&b, "dvchost=%s", cefValueEsc.Replace(meta.Node))
	for _, p := range kvs {
		fmt.Fprintf(&b, " %s=%s", p.k, cefValueEsc.Replace(p.v))
	}
	return b.String()
}

// LEEF renders IBM QRadar LEEF 2.0 (tab delimited).
func LEEF(ev Event, meta Meta) string {
	sig, _, kvs := eventKVs(ev)
	var b strings.Builder
	fmt.Fprintf(&b, "LEEF:2.0|AegisProxy|Egress Gateway|%s|%s|x09|", leefValueEsc.Replace(meta.Version), leefValueEsc.Replace(strings.ReplaceAll(sig, "|", "_")))
	parts := []string{"devTime=" + ev.Time.UTC().Format("Jan 02 2006 15:04:05.000 UTC"), "devTimeFormat=MMM dd yyyy HH:mm:ss.SSS z",
		"sev=" + strconv.Itoa(cefSeverity(ev.Severity)), "identHostName=" + leefValueEsc.Replace(meta.Node)}
	rename := map[string]string{"shost": "srcHostName", "dhost": "dstHostName", "dpt": "dstPort", "suser": "usrName",
		"request": "url", "requestMethod": "method", "requestClientApplication": "userAgent", "in": "dstBytes", "out": "srcBytes",
		"act": "action"}
	for _, p := range kvs {
		if p.k == "rt" || strings.HasSuffix(p.k, "Label") {
			continue
		}
		k := p.k
		if r, ok := rename[k]; ok {
			k = r
		}
		parts = append(parts, k+"="+leefValueEsc.Replace(p.v))
	}
	b.WriteString(strings.Join(parts, "\t"))
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Payload renders an event in one of the record formats (json | ecs | cef | leef).
func Payload(ev Event, format string, meta Meta) ([]byte, error) {
	switch format {
	case "cef":
		return []byte(CEF(ev, meta)), nil
	case "leef":
		return []byte(LEEF(ev, meta)), nil
	case "ecs":
		return json.Marshal(Fields(ev, meta))
	default:
		return json.Marshal(NativeJSON(ev, meta))
	}
}
