package models

import (
	"time"

	"aegisproxy/control-plane/internal/sealed"
)

// SSO client key states (private_key_jwt).
const (
	ClientKeyActive  = "active"  // signs client assertions
	ClientKeyNext    = "next"    // published, waiting for activation (upload the certificate to the IdP first)
	ClientKeyRetired = "retired" // replaced; still published until RetireAt + grace, private key erased
)

// SSOClientKey is a key pair the control-plane uses to authenticate to the IdP's token endpoint
// with private_key_jwt. The private key is sealed at rest and never returned by the API.
type SSOClientKey struct {
	KID            string        `json:"kid"`
	Alg            string        `json:"alg"` // RS256 (RSA-3072) | ES256 (P-256)
	Status         string        `json:"status"`
	PrivateKey     sealed.String `json:"private_key,omitempty"` // PKCS#8 PEM, write-only
	CertificatePEM string        `json:"certificate_pem"`
	X5t            string        `json:"x5t"`
	X5tS256        string        `json:"x5t_s256"`
	NotAfter       time.Time     `json:"not_after"`
	CreatedAt      time.Time     `json:"created_at"`
	CreatedBy      string        `json:"created_by"`
	ActivatedAt    *time.Time    `json:"activated_at,omitempty"`
	RetiredAt      *time.Time    `json:"retired_at,omitempty"`
	// PublishedUntil ends the grace period of a retired key in the JWKS.
	PublishedUntil *time.Time `json:"published_until,omitempty"`
}

// Public strips the private key.
func (k SSOClientKey) Public() SSOClientKey {
	k.PrivateKey = ""
	return k
}

// SCIMConfig configures inbound user and group provisioning (SCIM 2.0, RFC 7643/7644).
type SCIMConfig struct {
	Enabled bool        `json:"enabled"`
	Tokens  []SCIMToken `json:"tokens"`
	// LastSyncAt is the time of the last provisioning change (create, update, delete).
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	// Changes counts provisioning changes since SCIM was set up.
	Changes int64 `json:"changes,omitempty"`
}

// SCIMToken is a bearer credential of the SCIM client (Entra ID or Okta provisioning agent).
// Only its SHA-256 digest is stored.
type SCIMToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
}

// Public strips the digest.
func (t SCIMToken) Public() SCIMToken {
	t.Hash = ""
	return t
}

// SCIMUser holds the provisioning attributes of a user created or claimed by the SCIM client. The
// console account (models.User) derives username, display name, e-mail and department from it.
type SCIMUser struct {
	UserName    string      `json:"user_name"`
	ExternalID  string      `json:"external_id,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	DisplayName string      `json:"display_name,omitempty"`
	GivenName   string      `json:"given_name,omitempty"`
	FamilyName  string      `json:"family_name,omitempty"`
	Formatted   string      `json:"formatted,omitempty"`
	Title       string      `json:"title,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Department  string      `json:"department,omitempty"`
	// Deleted marks a user the SCIM client deleted: the account stays (disabled) for the audit
	// trail but is no longer a SCIM resource; provisioning the same user again revives it.
	Deleted      bool      `json:"deleted,omitempty"`
	Version      int64     `json:"version"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"last_modified"`
}

// IsActive reports whether the SCIM client wants the account enabled (absent "active" = true).
func (u *SCIMUser) IsActive() bool { return u != nil && !u.Deleted && (u.Active == nil || *u.Active) }

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroup is a group pushed by the SCIM client. Its display name and external ID (Entra: group
// object ID) are matched against the SSO group_role_map / group_scope_map keys.
type SCIMGroup struct {
	ID           string       `json:"id"`
	DisplayName  string       `json:"display_name"`
	ExternalID   string       `json:"external_id,omitempty"`
	Members      []SCIMMember `json:"members"`
	Version      int64        `json:"version"`
	Created      time.Time    `json:"created"`
	LastModified time.Time    `json:"last_modified"`
}

// SCIMMember references a console user (SCIM id = user ID).
type SCIMMember struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}
