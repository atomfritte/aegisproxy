package store

import (
	"net/url"
	"regexp"
	"strings"
)

// Query redaction of recorded URLs (security policy telemetry_query_redaction). The data-plane redacts before
// telemetry, its access log and block pages (data-plane/aegis_dp/redact.py); the control-plane applies the same
// function again on ingest, so flows from older workers or other sources are covered too. Both implementations are
// tested against testdata/redaction_vectors.json.
const (
	RedactNone      = "none"
	RedactSensitive = "sensitive"
	RedactAll       = "all"
	redactedValue   = "REDACTED"
)

var (
	// sensitiveParamNames: parameter names (lowercased, percent-decoded) whose value is always redacted.
	sensitiveParamNames = setOf("token", "access_token", "id_token", "refresh_token", "code", "sig", "signature", "key", "apikey",
		"api_key", "password", "passwd", "pwd", "secret", "client_secret", "session", "sessionid", "session_id", "auth",
		"x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-goog-signature", "x-goog-credential", "assertion", "jwt")
	// sensitiveParamWords: a name made of several words (snake_case, kebab-case, camelCase) is redacted when one word is one of these.
	sensitiveParamWords = setOf("token", "key", "apikey", "secret", "password", "passwd", "signature", "sig", "auth", "session",
		"sessionid", "credential", "credentials")
	// Redacted only next to the parameter that makes them part of a signed URL: Azure SAS (sig), CloudFront (Signature, Key-Pair-Id).
	sasParamNames        = setOf("sv", "se", "sig")
	cloudFrontParamNames = setOf("expires", "key-pair-id", "keypair-id", "policy", "signature")
	badEscape            = regexp.MustCompile(`%([^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|[0-9A-Fa-f]?$)`)
)

func setOf(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// NormalizeRedactionMode maps an empty or unknown setting to the default (sensitive).
func NormalizeRedactionMode(mode string) string {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case RedactNone, RedactSensitive, RedactAll:
		return m
	}
	return RedactSensitive
}

// decodeParamName mirrors url.QueryUnescape; a malformed escape leaves the name undecoded.
func decodeParamName(raw string) string {
	if badEscape.MatchString(raw) {
		return raw
	}
	if d, err := url.QueryUnescape(raw); err == nil {
		return d
	}
	return raw
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// paramWords splits a name into ASCII words at every non-alphanumeric byte and at lower→upper case changes.
func paramWords(name string) []string {
	var out []string
	var cur []byte
	prevLower := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		isUpper, isLower, isDigit := c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9'
		if !isUpper && !isLower && !isDigit {
			if len(cur) > 0 {
				out = append(out, string(cur))
			}
			cur, prevLower = nil, false
			continue
		}
		if isUpper && prevLower && len(cur) > 0 {
			out = append(out, string(cur))
			cur = nil
		}
		if isUpper {
			c += 32
		}
		cur = append(cur, c)
		prevLower = isLower || isDigit
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func sensitiveParam(rawName string, present map[string]bool) bool {
	decoded := decodeParamName(rawName)
	name := lowerASCII(decoded)
	if sensitiveParamNames[name] {
		return true
	}
	if sasParamNames[name] && present["sig"] {
		return true
	}
	if cloudFrontParamNames[name] && (present["signature"] || present["key-pair-id"] || present["keypair-id"]) {
		return true
	}
	words := paramWords(decoded)
	if len(words) > 1 {
		for _, w := range words {
			if sensitiveParamWords[w] {
				return true
			}
		}
	}
	return false
}

func stripUserinfo(base string) string {
	scheme, rest, ok := strings.Cut(base, "://")
	if !ok {
		return base
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return base
	}
	out := scheme + "://" + redactedValue + "@" + authority[at+1:]
	if hasPath {
		out += "/" + path
	}
	return out
}

// RedactURL returns raw with its query redacted per mode (and user:password@ credentials removed).
func RedactURL(raw, mode string) string {
	mode = NormalizeRedactionMode(mode)
	if mode == RedactNone || raw == "" {
		return raw
	}
	base, query, hasQuery := strings.Cut(raw, "?")
	base = stripUserinfo(base)
	if !hasQuery || mode == RedactAll {
		return base
	}
	parts := strings.Split(query, "&")
	present := make(map[string]bool, len(parts))
	for _, p := range parts {
		name, _, _ := strings.Cut(p, "=")
		present[lowerASCII(decodeParamName(name))] = true
	}
	for i, p := range parts {
		name, _, hasValue := strings.Cut(p, "=")
		if hasValue && sensitiveParam(name, present) {
			parts[i] = name + "=" + redactedValue
		}
	}
	return base + "?" + strings.Join(parts, "&")
}
