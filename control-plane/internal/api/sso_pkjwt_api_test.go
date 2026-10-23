package api

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc/oidctest"
	"aegisproxy/control-plane/internal/sealed"
)

type clientKeysResp struct {
	Keys    []models.SSOClientKey `json:"keys"`
	JWKSURI string                `json:"jwks_uri"`
	CanEdit bool                  `json:"can_edit"`
}

func (h *harness) jwks(t *testing.T) []map[string]any {
	t.Helper()
	r := h.do(t, "GET", "/api/auth/sso/jwks.json", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Cache-Control"), "public") {
		t.Fatalf("JWKS: %d %q", r.StatusCode, r.Header.Get("Cache-Control"))
	}
	return decode[struct {
		Keys []map[string]any `json:"keys"`
	}](t, r.Body).Keys
}

func TestSSOPrivateKeyJWT(t *testing.T) {
	key, _ := sealed.DeriveKey(strings.Repeat("k", 40))
	if err := sealed.Configure(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	h := newHarness(t)
	idp := oidctest.New("aegis-console", "")
	defer idp.Close()
	h.cfg.PublicURL, h.cfg.DashboardURL = h.srv.URL, h.srv.URL
	idp.AuthMethods = []string{"private_key_jwt"}
	idp.ClientJWKSURL = h.srv.URL + "/api/auth/sso/jwks.json" // like Keycloak "Use JWKS URL"
	idp.User = map[string]any{"preferred_username": "kim", "name": "Kim", "groups": []string{"aegis-infosec"}}
	h.login(t)

	if keys := h.jwks(t); len(keys) != 0 {
		t.Fatalf("JWKS before any key: %v", keys)
	}
	cfg := map[string]any{"enabled": true, "provider": "oidc", "issuer_url": idp.Server.URL, "client_id": "aegis-console",
		"token_auth_method": "private_key_jwt", "allow_local_login": true, "group_role_map": map[string]string{"aegis-infosec": "INFOSEC_APPROVER"}}
	if r := h.do(t, "POST", "/api/settings/entra", cfg, ui); r.StatusCode != 400 {
		t.Fatalf("private_key_jwt without a key accepted: %d", r.StatusCode)
	}

	// RBAC: InfoSec and anonymous callers cannot manage keys.
	if err := func() error { _, err := h.st.GenerateSSOClientKey("ES256", false, infosecFor()); return err }(); err == nil {
		t.Error("InfoSec generated a client key")
	}
	saved := h.jar
	h.jar = nil
	if r := h.do(t, "POST", "/api/settings/sso/client-keys", map[string]any{}, ui); r.StatusCode != 401 {
		t.Errorf("anonymous key generation: %d", r.StatusCode)
	}
	h.jar = saved

	r := h.do(t, "POST", "/api/settings/sso/client-keys", map[string]any{"alg": "ES256"}, ui)
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("generate: %d %s", r.StatusCode, b)
	}
	first := decode[struct {
		Key     models.SSOClientKey `json:"key"`
		JWKSURI string              `json:"jwks_uri"`
	}](t, r.Body)
	if first.Key.Status != models.ClientKeyActive || first.Key.PrivateKey != "" || first.JWKSURI != h.srv.URL+"/api/auth/sso/jwks.json" {
		t.Fatalf("first key: %+v", first)
	}
	if r := h.do(t, "POST", "/api/settings/entra", cfg, ui); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("configure private_key_jwt: %d %s", r.StatusCode, b)
	}
	if test := decode[map[string]any](t, h.do(t, "POST", "/api/settings/sso/test", map[string]any{}, ui).Body); test["ok"] != true || test["warnings"] != nil {
		t.Errorf("connection test: %v", test)
	}

	// Sign-in: the IdP verifies the assertion with the key from the control-plane JWKS.
	resp, _ := h.ssoLogin(t)
	if resp.StatusCode != 302 || strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatalf("SSO with private_key_jwt: %s", resp.Header.Get("Location"))
	}
	if idp.LastAssertion.Header["kid"] != first.Key.KID || idp.LastAssertion.Header["x5t"] != first.Key.X5t || idp.LastAssertion.Header["alg"] != "ES256" {
		t.Errorf("assertion header %v", idp.LastAssertion.Header)
	}

	// Certificate download (PEM and DER) matches the published thumbprint.
	r = h.do(t, "GET", "/api/settings/sso/client-certificate", nil, nil)
	pemBody, _ := io.ReadAll(r.Body)
	blk, _ := pem.Decode(pemBody)
	if r.StatusCode != 200 || blk == nil || !strings.Contains(r.Header.Get("Content-Disposition"), ".pem") {
		t.Fatalf("certificate download: %d %q", r.StatusCode, r.Header.Get("Content-Disposition"))
	}
	sum := sha1.Sum(blk.Bytes)
	if base64.RawURLEncoding.EncodeToString(sum[:]) != first.Key.X5t {
		t.Error("x5t is not the SHA-1 thumbprint of the downloaded certificate")
	}
	r = h.do(t, "GET", "/api/settings/sso/client-certificate?format=cer", nil, nil)
	der, _ := io.ReadAll(r.Body)
	if c, err := x509.ParseCertificate(der); err != nil || r.Header.Get("Content-Type") != "application/pkix-cert" || c.Subject.CommonName == "" {
		t.Errorf("DER certificate: %v %q", err, r.Header.Get("Content-Type"))
	}

	// Rotation: stage an RSA key (published at once), activate it, the old one stays published.
	r = h.do(t, "POST", "/api/settings/sso/client-keys", map[string]any{"alg": "RS256"}, ui)
	next := decode[struct {
		Key models.SSOClientKey `json:"key"`
	}](t, r.Body).Key
	if next.Status != models.ClientKeyNext {
		t.Fatalf("second key should be staged: %+v", next)
	}
	if r := h.do(t, "POST", "/api/settings/sso/client-keys", map[string]any{"alg": "RS256"}, ui); r.StatusCode != 409 {
		t.Errorf("second staged key: %d", r.StatusCode)
	}
	if keys := h.jwks(t); len(keys) != 2 {
		t.Fatalf("JWKS during rotation: %d keys", len(keys))
	}
	h.ssoLogin(t)
	if idp.LastAssertion.Header["kid"] != first.Key.KID {
		t.Error("staged key used before activation")
	}
	if r := h.do(t, "POST", "/api/settings/sso/client-keys/"+next.KID+"/activate", nil, ui); r.StatusCode != 200 {
		t.Fatalf("activate: %d", r.StatusCode)
	}
	resp, _ = h.ssoLogin(t)
	if strings.Contains(resp.Header.Get("Location"), "sso_error") || idp.LastAssertion.Header["kid"] != next.KID || idp.LastAssertion.Header["alg"] != "RS256" {
		t.Fatalf("after rotation: %s %v", resp.Header.Get("Location"), idp.LastAssertion.Header)
	}
	list := decode[clientKeysResp](t, h.do(t, "GET", "/api/settings/sso/client-keys", nil, nil).Body)
	if len(list.Keys) != 2 || list.Keys[0].KID != next.KID || list.Keys[1].Status != models.ClientKeyRetired || list.Keys[1].PublishedUntil == nil || !list.CanEdit {
		t.Fatalf("keys after rotation: %+v", list)
	}
	jwks := h.jwks(t)
	for _, k := range jwks {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := k[private]; ok {
				t.Fatalf("private member %q in JWKS", private)
			}
		}
		if k["use"] != "sig" || k["x5c"] == nil || k["x5t#S256"] == nil {
			t.Errorf("JWK %v", k)
		}
	}
	// The retired key's private key was erased; the active one cannot be deleted while in use.
	if r := h.do(t, "DELETE", "/api/settings/sso/client-keys/"+next.KID, nil, ui); r.StatusCode != 400 {
		t.Errorf("delete active key in use: %d", r.StatusCode)
	}
	if r := h.do(t, "DELETE", "/api/settings/sso/client-keys/"+first.Key.KID, nil, ui); r.StatusCode != 200 {
		t.Errorf("delete retired key: %d", r.StatusCode)
	}
	if keys := h.jwks(t); len(keys) != 1 || keys[0]["kid"] != next.KID {
		t.Errorf("JWKS after deleting the retired key: %v", keys)
	}

	// An IdP that does not know the key refuses the token request.
	idp.ClientJWKSURL = h.srv.URL + "/api/public/meta"
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=token") {
		t.Errorf("unknown key accepted: %s", resp.Header.Get("Location"))
	}

	// Secrets never leave the store: not in API responses, sealed in the state file.
	state, _ := io.ReadAll(h.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body)
	if strings.Contains(string(state), "PRIVATE KEY") {
		t.Error("private key in /api/state")
	}
	h.st.Close()
	raw, _ := os.ReadFile(filepath.Join(h.dir, "aegis_state.json"))
	var doc struct {
		Keys []struct {
			PrivateKey string `json:"private_key"`
		} `json:"sso_client_keys"`
	}
	_ = json.Unmarshal(raw, &doc)
	if len(doc.Keys) != 1 || !sealed.IsSealed(doc.Keys[0].PrivateKey) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatalf("persisted client key is not sealed: %+v", doc.Keys)
	}
	actions := map[string]bool{}
	for _, ev := range h.st.GetSnapshot().AuditEvents {
		actions[ev.Action] = true
	}
	for _, a := range []string{"SSO_CLIENT_KEY_GENERATED", "SSO_CLIENT_KEY_ACTIVATED", "SSO_CLIENT_KEY_DELETED"} {
		if !actions[a] {
			t.Errorf("audit event %s missing", a)
		}
	}
}
