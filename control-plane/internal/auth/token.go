package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

const tokenIssuer = "aegisproxy-control-plane"

// jwtHeader is the only header accepted (HS256). Fixing it rules out "alg":"none" and
// algorithm-confusion attacks.
var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type TokenClaims struct {
	UserID        string      `json:"sub"`
	Username      string      `json:"usr"`
	DisplayName   string      `json:"name"`
	Role          models.Role `json:"role"`
	AllowedGroups []string    `json:"grp"`
	Issuer        string      `json:"iss"`
	IssuedAt      int64       `json:"iat"`
	Exp           int64       `json:"exp"`
	JTI           string      `json:"jti"`
	// ServiceAccount is set for API-key authentication (never part of a signed session token).
	ServiceAccount bool `json:"-"`
}

// RevocationChecker reports whether a token ID was revoked (logout).
type RevocationChecker interface {
	IsTokenRevoked(jti string) bool
}

type AuthManager struct {
	jwtSecret []byte
	ttl       time.Duration
	revoked   RevocationChecker
}

func NewAuthManager(secret []byte, ttl time.Duration) *AuthManager {
	if len(secret) < 32 {
		panic("auth: JWT secret must be at least 32 bytes")
	}
	return &AuthManager{jwtSecret: secret, ttl: ttl}
}

func (m *AuthManager) SetRevocationChecker(rc RevocationChecker) { m.revoked = rc }

func (m *AuthManager) TTL() time.Duration { return m.ttl }

func newJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (m *AuthManager) IssueToken(u *models.User) (string, *TokenClaims, error) {
	now := time.Now()
	claims := &TokenClaims{
		UserID:        u.ID,
		Username:      u.Username,
		DisplayName:   u.DisplayName,
		Role:          u.Role,
		AllowedGroups: append([]string(nil), u.AllowedGroups...),
		Issuer:        tokenIssuer,
		IssuedAt:      now.Unix(),
		Exp:           now.Add(m.ttl).Unix(),
		JTI:           newJTI(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	signingInput := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + m.sign(signingInput), claims, nil
}

func (m *AuthManager) VerifyToken(token string) (*TokenClaims, error) {
	if len(token) > 4096 {
		return nil, errors.New("invalid token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != jwtHeader {
		return nil, errors.New("invalid token format")
	}
	signingInput := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign(signingInput))) {
		return nil, errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid token payload")
	}
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid token payload")
	}
	now := time.Now().Unix()
	if claims.Issuer != tokenIssuer || claims.JTI == "" || claims.UserID == "" {
		return nil, errors.New("invalid token claims")
	}
	if now >= claims.Exp {
		return nil, errors.New("session expired")
	}
	if claims.IssuedAt > now+60 {
		return nil, errors.New("token issued in the future")
	}
	if m.revoked != nil && m.revoked.IsTokenRevoked(claims.JTI) {
		return nil, errors.New("session has been signed out")
	}
	return &claims, nil
}

func (m *AuthManager) sign(data string) string {
	mac := hmac.New(sha256.New, m.jwtSecret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
