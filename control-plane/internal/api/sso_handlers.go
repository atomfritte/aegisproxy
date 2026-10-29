package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc"
	"aegisproxy/control-plane/internal/store"
)

const ssoCookie = "aegis_sso"

type ssoState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

// ssoProviders caches one OIDC provider per configuration.
type ssoProviders struct {
	mu  sync.Mutex
	key string
	p   *oidc.Provider
}

func (s *Server) ssoRoutes() {
	s.mux.HandleFunc("GET /api/auth/sso/login", s.handleSSOLogin)
	s.mux.HandleFunc("GET /api/auth/sso/callback", s.handleSSOCallback)
	s.mux.HandleFunc("GET /api/auth/sso/jwks.json", s.handleSSOJWKS)
	s.mux.HandleFunc("POST /api/settings/sso/test", s.authed(s.handleSSOTest))
	s.mux.HandleFunc("GET /api/settings/sso/client-keys", s.authed(s.handleListSSOClientKeys))
	s.mux.HandleFunc("POST /api/settings/sso/client-keys", s.authed(s.handleGenerateSSOClientKey))
	s.mux.HandleFunc("POST /api/settings/sso/client-keys/{kid}/activate", s.authed(s.handleActivateSSOClientKey))
	s.mux.HandleFunc("DELETE /api/settings/sso/client-keys/{kid}", s.authed(s.handleDeleteSSOClientKey))
	s.mux.HandleFunc("GET /api/settings/sso/client-certificate", s.authed(s.handleSSOClientCertificate))
}

func (s *Server) ssoKey() []byte {
	mac := hmac.New(sha256.New, s.cfg.JWTSecret)
	mac.Write([]byte("aegis-sso-state-v1"))
	return mac.Sum(nil)
}

func (s *Server) ssoProvider(cfg models.EntraIDConfig) (*oidc.Provider, error) {
	cacheKey := func(kid string) string {
		return strings.Join([]string{cfg.IssuerURL, cfg.ClientID, string(cfg.ClientSecret), cfg.RedirectURI, strings.Join(cfg.Scopes, " "), cfg.TokenAuthMethod, kid}, "\x00")
	}
	kid := ""
	if cfg.TokenAuthMethod == oidc.TokenAuthPrivateKeyJWT {
		if k, ok := s.store.SSOClientKey(""); ok {
			kid = k.KID
		}
	}
	key := cacheKey(kid)
	s.sso.mu.Lock()
	defer s.sso.mu.Unlock()
	if s.sso.p != nil && s.sso.key == key {
		return s.sso.p, nil
	}
	var clientKey *oidc.ClientKey
	if cfg.TokenAuthMethod == oidc.TokenAuthPrivateKeyJWT { // the private key is parsed once per active key
		k, err := s.store.SSOSigningKey()
		if err != nil {
			return nil, err
		}
		clientKey, key = k, cacheKey(k.KID)
	}
	p, err := oidc.New(oidc.Config{Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, ClientSecret: string(cfg.ClientSecret), TokenAuthMethod: cfg.TokenAuthMethod,
		ClientKey: clientKey, RedirectURI: cfg.RedirectURI, Scopes: cfg.Scopes}, nil)
	if err != nil {
		return nil, err
	}
	s.sso.key, s.sso.p = key, p
	return p, nil
}

// safeNext accepts only local console paths (prevents open redirects).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

func (s *Server) consoleURL(path string) string {
	base := strings.TrimRight(s.cfg.DashboardURL, "/")
	if base == "" {
		base = strings.TrimRight(s.cfg.PublicURL, "/")
	}
	return base + path
}

func (s *Server) ssoFail(w http.ResponseWriter, r *http.Request, code, detail string) {
	s.metrics.Inc("aegis_login_total", "result", "sso_failure")
	s.log.Warn("single sign-on failed", "reason", code, "detail", detail, "client_ip", s.clientIP(r))
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/auth/sso", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, s.consoleURL("/login?sso_error="+url.QueryEscape(code)), http.StatusFound)
}

func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.SSOSettings(s.cfg.PublicURL)
	if !cfg.Enabled {
		writeError(w, http.StatusNotFound, "single sign-on is not enabled")
		return
	}
	p, err := s.ssoProvider(cfg)
	if err != nil {
		s.ssoFail(w, r, "configuration", err.Error())
		return
	}
	st := ssoState{State: oidc.RandomString(24), Nonce: oidc.RandomString(24), Next: safeNext(r.URL.Query().Get("next")),
		Exp: time.Now().Add(10 * time.Minute).Unix()}
	var challenge string
	st.Verifier, challenge = oidc.NewPKCE()
	extra := url.Values{}
	if hint := r.URL.Query().Get("login_hint"); hint != "" && len(hint) < 256 {
		extra.Set("login_hint", hint)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	target, err := p.AuthCodeURL(ctx, st.State, st.Nonce, challenge, extra)
	if err != nil {
		s.ssoFail(w, r, "provider_unreachable", err.Error())
		return
	}
	raw, _ := json.Marshal(st)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.ssoKey())
	mac.Write([]byte(payload))
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
		Path: "/api/auth/sso", MaxAge: 600, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) readSSOState(r *http.Request) (*ssoState, error) {
	c, err := r.Cookie(ssoCookie)
	if err != nil {
		return nil, errors.New("login session missing or expired")
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, errors.New("malformed login session")
	}
	mac := hmac.New(sha256.New, s.ssoKey())
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, errors.New("login session signature invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("malformed login session")
	}
	var st ssoState
	if err := json.Unmarshal(raw, &st); err != nil || time.Now().Unix() > st.Exp {
		return nil, errors.New("login session expired")
	}
	return &st, nil
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.ssoFail(w, r, "idp_"+truncateForLog(e), q.Get("error_description"))
		return
	}
	st, err := s.readSSOState(r)
	if err != nil {
		s.ssoFail(w, r, "session", err.Error())
		return
	}
	if q.Get("state") == "" || !hmac.Equal([]byte(q.Get("state")), []byte(st.State)) {
		s.ssoFail(w, r, "state", "state mismatch (possible CSRF)")
		return
	}
	cfg := s.store.SSOSettings(s.cfg.PublicURL)
	if !cfg.Enabled {
		s.ssoFail(w, r, "disabled", "single sign-on disabled")
		return
	}
	p, err := s.ssoProvider(cfg)
	if err != nil {
		s.ssoFail(w, r, "configuration", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	idToken, err := p.Exchange(ctx, q.Get("code"), st.Verifier)
	if err != nil {
		s.ssoFail(w, r, "token", err.Error())
		return
	}
	claims, err := p.Verify(ctx, idToken, st.Nonce)
	if err != nil {
		s.ssoFail(w, r, "id_token", err.Error())
		return
	}
	if names, ok := claims["_claim_names"].(map[string]any); ok && names[cfg.GroupsClaim] != nil {
		s.ssoFail(w, r, "group_overage", "the IdP omitted the groups claim (too many groups); assign groups to the application or use app roles")
		return
	}
	id := store.SSOIdentity{Issuer: cfg.IssuerURL, Subject: claims.String("sub"), Username: claims.String(cfg.UsernameClaim),
		Email: claims.String("email"), DisplayName: claims.String("name"), Groups: claims.Strings(cfg.GroupsClaim)}
	id.LoginName = firstNonEmptyStr(id.Username, claims.String("upn"))
	if cfg.Provider == "entra" && claims.String("oid") != "" {
		id.Subject = claims.String("oid") // stable across applications of the tenant
	}
	if id.Username == "" {
		id.Username = firstNonEmptyStr(claims.String("upn"), id.Email, claims.String("sub"))
	}
	if i := strings.IndexByte(id.Username, '@'); i > 0 && cfg.UsernameClaim != "email" {
		// keep UPNs readable but valid as console usernames
		id.Username = strings.ReplaceAll(id.Username, "@", ".")
	}
	user, err := s.store.ProvisionSSOUser(id)
	if err != nil {
		code := "provisioning"
		if errors.Is(err, store.ErrSSONotAuthorized) {
			code = "not_authorized"
		} else if errors.Is(err, store.ErrSSOUserDisabled) {
			code = "account_disabled"
		} else if errors.Is(err, store.ErrSSOLinkConflict) {
			code = "account_link"
		}
		s.ssoFail(w, r, code, err.Error())
		return
	}
	token, tc, err := s.authMgr.IssueToken(user)
	if err != nil {
		s.ssoFail(w, r, "session", "token signing failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/auth/sso", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	s.setSessionCookie(w, token, time.Unix(tc.Exp, 0))
	s.metrics.Inc("aegis_login_total", "result", "sso_success")
	s.log.Info("single sign-on succeeded", "username", user.Username, "role", user.Role, "client_ip", s.clientIP(r))
	http.Redirect(w, r, s.consoleURL(st.Next), http.StatusFound)
}

// handleSSOTest checks discovery and JWKS reachability for the stored (or submitted) issuer.
func (s *Server) handleSSOTest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !auth.CanManageUsers(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only Super Admins can configure single sign-on")
		return
	}
	var in models.EntraIDConfig
	if err := decodeOptionalJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if in.TenantID != "" && !store.ValidEntraTenantID(in.TenantID) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "tenant_id must be the Directory (tenant) ID (a GUID)"})
		return
	}
	cfg := s.store.SSOSettings(s.cfg.PublicURL)
	if in.IssuerURL != "" || in.TenantID != "" {
		// Discovery only: the stored client secret is never sent to a submitted issuer.
		in.ClientSecret = ""
		if in.ClientID == "" {
			in.ClientID = cfg.ClientID
		}
		cfg = in
		if cfg.Provider == "" {
			cfg.Provider = "entra"
		}
		if cfg.Provider == "entra" && cfg.IssuerURL == "" {
			cfg.IssuerURL = "https://login.microsoftonline.com/" + cfg.TenantID + "/v2.0"
		}
		if cfg.RedirectURI == "" {
			cfg.RedirectURI = strings.TrimRight(s.cfg.PublicURL, "/") + "/api/auth/sso/callback"
		}
		if cfg.ClientID == "" {
			cfg.ClientID = "connectivity-test"
		}
	}
	p, err := oidc.New(oidc.Config{Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI}, nil)
	keys := 0
	var methods []string
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if keys, err = p.CheckSigningKeys(ctx); err == nil {
			methods, _ = p.TokenAuthMethods(ctx)
		}
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "issuer": cfg.IssuerURL})
		return
	}
	resp := map[string]any{"ok": true, "issuer": cfg.IssuerURL, "redirect_uri": cfg.RedirectURI, "signing_keys": keys,
		"token_endpoint_auth_methods": nonNil(methods),
		"note":                        fmt.Sprintf("Register %s as redirect URI (web platform) in the IdP application.", cfg.RedirectURI)}
	if in.TokenAuthMethod != "" {
		cfg.TokenAuthMethod = in.TokenAuthMethod
	}
	if cfg.TokenAuthMethod == oidc.TokenAuthPrivateKeyJWT {
		var warnings []string
		if len(methods) > 0 && !slices.Contains(methods, oidc.TokenAuthPrivateKeyJWT) {
			warnings = append(warnings, "the provider does not advertise private_key_jwt in token_endpoint_auth_methods_supported")
		}
		if _, err := s.store.SSOSigningKey(); err != nil {
			warnings = append(warnings, "no active client key: generate one and register its certificate or the JWKS URL in the IdP")
		}
		resp["jwks_uri"] = s.ssoJWKSURL()
		if len(warnings) > 0 {
			resp["warnings"] = warnings
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) ssoJWKSURL() string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/api/auth/sso/jwks.json"
}

// handleSSOJWKS publishes the public client keys for IdPs that verify private_key_jwt assertions
// against a JWKS URL (Keycloak "Use JWKS URL", Okta, Ping). Active, staged and retired keys within
// their grace period are listed; private keys never leave the store.
func (s *Server) handleSSOJWKS(w http.ResponseWriter, r *http.Request) {
	keys := []map[string]any{}
	for _, k := range s.store.SSOClientKeys() {
		ck, err := oidc.ParseCertificateKey(k.CertificatePEM)
		if err != nil {
			s.log.Error("SSO client key certificate unreadable", "kid", k.KID, "error", err)
			continue
		}
		j, err := oidc.PublicJWK(k.KID, k.Alg, ck.PublicKey, ck.Raw)
		if err != nil {
			continue
		}
		keys = append(keys, j)
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleListSSOClientKeys(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": s.store.SSOClientKeys(), "jwks_uri": s.ssoJWKSURL(),
		"grace_period_hours": int(store.SSOClientKeyGrace.Hours()), "can_edit": claims.Role == models.RoleSuperAdmin && !claims.ServiceAccount})
}

func (s *Server) handleGenerateSSOClientKey(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in struct {
		Alg      string `json:"alg"`
		Activate bool   `json:"activate"`
	}
	if err := decodeOptionalJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	k, err := s.store.GenerateSSOClientKey(in.Alg, in.Activate, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "jwks_uri": s.ssoJWKSURL()})
}

func (s *Server) handleActivateSSOClientKey(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	k, err := s.store.ActivateSSOClientKey(r.PathValue("kid"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": k})
}

func (s *Server) handleDeleteSSOClientKey(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteSSOClientKey(r.PathValue("kid"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSSOClientCertificate downloads the self-signed certificate of a client key (default: the
// active one) for IdPs that require a certificate upload (Entra ID: Certificates & secrets →
// Certificates accepts .cer, .pem and .crt).
func (s *Server) handleSSOClientCertificate(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	k, ok := s.store.SSOClientKey(r.URL.Query().Get("kid"))
	if !ok {
		writeError(w, http.StatusNotFound, "client key not found; generate one first")
		return
	}
	name := "aegisproxy-sso-" + k.KID[:min(12, len(k.KID))]
	body, ctype := []byte(k.CertificatePEM), "application/x-pem-file"
	switch r.URL.Query().Get("format") {
	case "", "pem":
		name += ".pem"
	case "cer", "der":
		c, err := oidc.ParseCertificateKey(k.CertificatePEM)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "certificate unreadable")
			return
		}
		body, ctype, name = c.Raw, "application/pkix-cert", name+".cer"
	default:
		writeError(w, http.StatusBadRequest, "format must be pem or cer")
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Certificate-Thumbprint-SHA1", k.X5t)
	_, _ = w.Write(body)
}
