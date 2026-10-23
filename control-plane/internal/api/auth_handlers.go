package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/store"
)

const sessionCookie = "aegis_session"

type authedHandler func(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims)

// getClaims authenticates a request via "Authorization: Bearer" (API clients) or the HttpOnly
// session cookie (web console) and re-validates role/group membership against the live user record.
func (s *Server) getClaims(r *http.Request) (*auth.TokenClaims, bool, error) {
	var raw string
	viaCookie := false
	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
		raw = strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	} else if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		raw = c.Value
		viaCookie = true
	}
	if raw == "" {
		return nil, false, errors.New("authentication required")
	}
	if !viaCookie && store.IsServiceKey(raw) {
		claims, err := s.store.AuthenticateServiceKey(raw, s.clientIP(r))
		return claims, false, err
	}
	claims, err := s.authMgr.VerifyToken(raw)
	if err != nil {
		return nil, viaCookie, err
	}
	live, err := s.store.SessionValidFor(claims.UserID, claims.IssuedAt)
	if err != nil {
		return nil, viaCookie, err
	}
	claims.Role = live.Role
	claims.AllowedGroups = live.AllowedGroups
	claims.Username = live.Username
	claims.DisplayName = live.DisplayName
	return claims, viaCookie, nil
}

// csrfOK protects cookie-authenticated state-changing requests. Browsers cannot attach the
// custom X-Requested-With header cross-origin without a CORS preflight (which we deny), and the
// session cookie is SameSite=Strict.
func (s *Server) csrfOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get("X-Requested-With") == "" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		if u.Host == r.Host {
			return true
		}
		if pu, err := url.Parse(s.cfg.PublicURL); err == nil && pu.Host == u.Host {
			return true
		}
		for _, o := range s.cfg.CORSOrigins {
			if o == origin {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, viaCookie, err := s.getClaims(r)
		if err != nil {
			if viaCookie {
				s.clearSessionCookie(w)
			}
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		if viaCookie && !s.csrfOK(r) {
			writeError(w, http.StatusForbidden, "CSRF protection: missing X-Requested-With header or cross-site origin")
			return
		}
		h(w, r, claims)
	}
}

func (s *Server) requireSystem(w http.ResponseWriter, claims *auth.TokenClaims) bool {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only InfoSec Approvers and Super Admins can perform this action")
		return false
	}
	return true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: s.cfg.CookieSameSite,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", Domain: s.cfg.CookieDomain, MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: s.cfg.CookieSameSite,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ip := s.clientIP(r)
	// The lockout key is the canonical username (at most 64 ASCII characters): oversized or exotic
	// input can neither grow the limiter without bound nor dodge the lockout with an alias.
	acctKey := "u:" + strings.ToLower(strings.TrimSpace(body.Username))
	if len(acctKey) > 70 || strings.IndexFunc(acctKey, func(r rune) bool { return r > 0x7e || r < 0x21 }) >= 0 {
		acctKey = "u:invalid"
	}
	ipKey := "ip:" + ip
	if wait := s.loginLimiter.Check(acctKey, ipKey); wait > 0 {
		secs := int(math.Ceil(wait.Seconds()))
		w.Header().Set("Retry-After", fmt.Sprint(secs))
		s.metrics.Inc("aegis_login_total", "result", "throttled")
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many failed sign-in attempts. Try again in %d seconds.", secs))
		return
	}
	user, err := s.store.AuthenticateLocal(body.Username, body.Password)
	if err != nil {
		s.loginLimiter.Fail(acctKey, ipKey)
		s.metrics.Inc("aegis_login_total", "result", "failure")
		s.log.Warn("login failed", "username", truncateForLog(body.Username), "client_ip", ip)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.loginLimiter.Success(acctKey)
	token, claims, err := s.authMgr.IssueToken(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token signing error")
		return
	}
	s.metrics.Inc("aegis_login_total", "result", "success")
	s.log.Info("login succeeded", "username", user.Username, "role", user.Role, "client_ip", ip)
	exp := time.Unix(claims.Exp, 0)
	s.setSessionCookie(w, token, exp)
	resp := map[string]any{"user": user, "expires_at": exp.UTC()}
	// Browser sessions rely solely on the HttpOnly cookie; API clients receive a bearer token.
	if r.Header.Get("X-Requested-With") == "" {
		resp["token"] = token
	}
	writeJSON(w, http.StatusOK, resp)
}

func truncateForLog(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if claims, viaCookie, err := s.getClaims(r); err == nil && !claims.ServiceAccount {
		if !viaCookie || s.csrfOK(r) {
			s.store.RevokeToken(claims.JTI, time.Unix(claims.Exp, 0))
		}
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if claims.ServiceAccount {
		writeJSON(w, http.StatusOK, map[string]any{"service_account": map[string]any{
			"id": strings.TrimPrefix(claims.UserID, "sa:"), "name": claims.DisplayName, "role": claims.Role, "allowed_groups": claims.AllowedGroups}})
		return
	}
	u, ok := s.store.GetUserByID(claims.UserID)
	if !ok {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       u.Public(),
		"expires_at": time.Unix(claims.Exp, 0).UTC(),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.store.ChangeOwnPassword(claims.UserID, body.CurrentPassword, body.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Issue a fresh session for the current browser; all other sessions are revoked.
	if u, ok := s.store.GetUserByID(claims.UserID); ok {
		pub := u.Public()
		if token, c, err := s.authMgr.IssueToken(&pub); err == nil {
			s.setSessionCookie(w, token, time.Unix(c.Exp, 0))
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}
