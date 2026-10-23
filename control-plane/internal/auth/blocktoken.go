package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Block tokens are minted by data-plane workers when they block a request and embedded in the
// block page / CLI one-liner. The control-plane only trusts the server identity and URL of an
// unauthenticated access request if it carries a valid token, which prevents anyone on the
// network from filing requests in the name of another server.
//
// Format: "v1.<base64url(json claims)>.<base64url(HMAC-SHA256(subkey, "v1." + claims))>"
// subkey = HMAC-SHA256(dataPlaneKey, "aegis-block-token-v1") (domain separation from other uses
// of the data-plane key). The Python data-plane implements the identical construction.

const blockTokenPrefix = "v1."

type BlockClaims struct {
	ServerIP string `json:"ip"`
	ServerID string `json:"sid,omitempty"`
	URL      string `json:"url"`
	Method   string `json:"m"`
	TraceID  string `json:"tid"`
	Verdict  string `json:"v,omitempty"`
	Exp      int64  `json:"exp"`
}

func blockSubkey(key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("aegis-block-token-v1"))
	return mac.Sum(nil)
}

func SignBlockToken(key string, c BlockClaims) (string, error) {
	if c.Exp == 0 {
		c.Exp = time.Now().Add(24 * time.Hour).Unix()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := blockTokenPrefix + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, blockSubkey(key))
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyBlockToken(key, token string) (*BlockClaims, error) {
	token = strings.TrimSpace(token)
	if len(token) > 8192 || !strings.HasPrefix(token, blockTokenPrefix) {
		return nil, errors.New("invalid block token")
	}
	idx := strings.LastIndexByte(token, '.')
	if idx <= len(blockTokenPrefix) {
		return nil, errors.New("invalid block token")
	}
	body, sig := token[:idx], token[idx+1:]
	mac := hmac.New(sha256.New, blockSubkey(key))
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return nil, errors.New("block token signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(body, blockTokenPrefix))
	if err != nil {
		return nil, errors.New("invalid block token payload")
	}
	var c BlockClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("invalid block token payload")
	}
	if time.Now().Unix() > c.Exp {
		return nil, errors.New("block token expired")
	}
	if c.ServerIP == "" || c.URL == "" {
		return nil, errors.New("incomplete block token")
	}
	return &c, nil
}
