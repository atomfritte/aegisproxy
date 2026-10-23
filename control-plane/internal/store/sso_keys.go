package store

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc"
	"aegisproxy/control-plane/internal/sealed"
)

const (
	// SSOClientKeyGrace keeps a replaced key in the JWKS so that IdPs with cached keys and
	// in-flight sign-ins keep working during a rotation.
	SSOClientKeyGrace = 7 * 24 * time.Hour
	ssoClientKeyValid = 730 * 24 * time.Hour
	maxSSOClientKeys  = 8
)

// requirePersonSuperAdmin allows identity configuration only to Super Admins signed in as people.
func requirePersonSuperAdmin(actor *auth.TokenClaims, what string) error {
	if actor == nil || actor.Role != models.RoleSuperAdmin || actor.ServiceAccount {
		return fmt.Errorf("RBAC Policy: only Super Admins can %s", what)
	}
	return nil
}

// pruneSSOClientKeysLocked drops retired keys whose grace period is over.
func (s *Store) pruneSSOClientKeysLocked(now time.Time) {
	s.state.SSOClientKeys = slices.DeleteFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool {
		return k.Status == models.ClientKeyRetired && k.PublishedUntil != nil && now.After(*k.PublishedUntil)
	})
}

// SSOClientKeys lists the client keys (active first) without private keys. Retired keys past their
// grace period are omitted.
func (s *Store) SSOClientKeys() []models.SSOClientKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := []models.SSOClientKey{}
	for _, k := range s.state.SSOClientKeys {
		if k.Status == models.ClientKeyRetired && k.PublishedUntil != nil && now.After(*k.PublishedUntil) {
			continue
		}
		out = append(out, k.Public())
	}
	order := map[string]int{models.ClientKeyActive: 0, models.ClientKeyNext: 1, models.ClientKeyRetired: 2}
	slices.SortStableFunc(out, func(a, b models.SSOClientKey) int {
		if order[a.Status] != order[b.Status] {
			return order[a.Status] - order[b.Status]
		}
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return out
}

// SSOClientKey returns one key (public part) by kid; an empty kid selects the active key.
func (s *Store) SSOClientKey(kid string) (models.SSOClientKey, bool) {
	for _, k := range s.SSOClientKeys() {
		if (kid == "" && k.Status == models.ClientKeyActive) || (kid != "" && k.KID == kid) {
			return k, true
		}
	}
	return models.SSOClientKey{}, false
}

// SSOSigningKey loads the active private key for client assertions.
func (s *Store) SSOSigningKey() (*oidc.ClientKey, error) {
	s.mu.RLock()
	i := slices.IndexFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.Status == models.ClientKeyActive })
	var k models.SSOClientKey
	if i >= 0 {
		k = s.state.SSOClientKeys[i]
	}
	s.mu.RUnlock()
	if i < 0 || k.PrivateKey == "" {
		return nil, errors.New("private_key_jwt: no active client key; generate one in the single sign-on settings")
	}
	return oidc.ParseClientKey(k.KID, k.Alg, string(k.PrivateKey), k.CertificatePEM)
}

// GenerateSSOClientKey creates a key pair with a self-signed certificate. The first key becomes
// active; later keys are staged as "next" (published in the JWKS, certificate downloadable) until
// activated, unless activate is set (immediate rotation).
func (s *Store) GenerateSSOClientKey(alg string, activate bool, actor *auth.TokenClaims) (models.SSOClientKey, error) {
	if err := requirePersonSuperAdmin(actor, "manage single sign-on client keys"); err != nil {
		return models.SSOClientKey{}, err
	}
	if alg == "" {
		alg = oidc.AlgRS256
	}
	if alg != oidc.AlgRS256 && alg != oidc.AlgES256 {
		return models.SSOClientKey{}, errors.New("alg must be RS256 (RSA-3072) or ES256 (P-256)")
	}
	s.mu.RLock()
	cn := "AegisProxy console SSO client"
	if id := s.state.EntraConfig.ClientID; id != "" && len(id) <= 64 && !hasCtl(id) {
		cn += " " + id
	}
	s.mu.RUnlock()
	now := time.Now().UTC()
	g, err := oidc.GenerateClientKey(alg, cn, now, ssoClientKeyValid)
	if err != nil {
		return models.SSOClientKey{}, err
	}
	var out models.SSOClientKey
	err = s.withWrite(func() error {
		s.pruneSSOClientKeysLocked(now)
		if len(s.state.SSOClientKeys) >= maxSSOClientKeys {
			return fmt.Errorf("at most %d client keys; delete retired keys first", maxSSOClientKeys)
		}
		hasActive := slices.ContainsFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.Status == models.ClientKeyActive })
		if !activate && hasActive && slices.ContainsFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.Status == models.ClientKeyNext }) {
			return errors.New("a staged key already exists; activate or delete it first")
		}
		k := models.SSOClientKey{KID: g.KID, Alg: g.Alg, Status: models.ClientKeyNext, PrivateKey: sealed.String(g.PrivateKeyPEM),
			CertificatePEM: g.CertificatePEM, X5t: g.X5t, X5tS256: g.X5tS256, NotAfter: g.NotAfter, CreatedAt: now, CreatedBy: actor.Username}
		s.state.SSOClientKeys = append(s.state.SSOClientKeys, k)
		summary := fmt.Sprintf("Generated SSO client key %s (%s, certificate valid until %s, x5t %s) as staged key", k.KID, k.Alg, k.NotAfter.Format("2006-01-02"), k.X5t)
		if activate || !hasActive {
			s.activateSSOClientKeyLocked(k.KID, now)
			summary = fmt.Sprintf("Generated and activated SSO client key %s (%s, certificate valid until %s, x5t %s)", k.KID, k.Alg, k.NotAfter.Format("2006-01-02"), k.X5t)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SSO_CLIENT_KEY_GENERATED", Category: "IDENTITY",
			EntityType: "sso_client_key", EntityID: k.KID, EntityName: "SSO client key " + k.Alg, Summary: summary,
		})
		s.markDirtyLocked()
		i := slices.IndexFunc(s.state.SSOClientKeys, func(x models.SSOClientKey) bool { return x.KID == k.KID })
		out = s.state.SSOClientKeys[i].Public()
		return nil
	})
	return out, err
}

// activateSSOClientKeyLocked makes kid the signing key and retires the previous one: its private
// key is erased, its public key stays in the JWKS for the grace period.
func (s *Store) activateSSOClientKeyLocked(kid string, now time.Time) (previous string) {
	until := now.Add(SSOClientKeyGrace)
	for i := range s.state.SSOClientKeys {
		k := &s.state.SSOClientKeys[i]
		switch {
		case k.KID == kid:
			k.Status, k.ActivatedAt, k.RetiredAt, k.PublishedUntil = models.ClientKeyActive, &now, nil, nil
		case k.Status == models.ClientKeyActive:
			previous = k.KID
			k.Status, k.RetiredAt, k.PublishedUntil, k.PrivateKey = models.ClientKeyRetired, &now, &until, ""
		}
	}
	return previous
}

// ActivateSSOClientKey promotes a staged key (rotation step 2, after the certificate was uploaded to
// the IdP or the IdP refreshed the JWKS).
func (s *Store) ActivateSSOClientKey(kid string, actor *auth.TokenClaims) (models.SSOClientKey, error) {
	if err := requirePersonSuperAdmin(actor, "manage single sign-on client keys"); err != nil {
		return models.SSOClientKey{}, err
	}
	var out models.SSOClientKey
	err := s.withWrite(func() error {
		now := time.Now().UTC()
		s.pruneSSOClientKeysLocked(now)
		i := slices.IndexFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.KID == kid })
		if i < 0 {
			return errors.New("client key not found")
		}
		if s.state.SSOClientKeys[i].Status != models.ClientKeyNext {
			return errors.New("only a staged key can be activated")
		}
		prev := s.activateSSOClientKeyLocked(kid, now)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SSO_CLIENT_KEY_ACTIVATED", Category: "IDENTITY",
			EntityType: "sso_client_key", EntityID: kid, EntityName: "SSO client key " + s.state.SSOClientKeys[i].Alg,
			Summary: fmt.Sprintf("Activated SSO client key %s; previous key %s retired (published until %s, private key erased)",
				kid, firstNonEmpty(prev, "none"), now.Add(SSOClientKeyGrace).Format(time.RFC3339)),
		})
		s.markDirtyLocked()
		out = s.state.SSOClientKeys[i].Public()
		return nil
	})
	return out, err
}

// DeleteSSOClientKey removes a staged or retired key immediately (for example after a compromise).
// The active key can only be deleted while private_key_jwt is not in use.
func (s *Store) DeleteSSOClientKey(kid string, actor *auth.TokenClaims) error {
	if err := requirePersonSuperAdmin(actor, "manage single sign-on client keys"); err != nil {
		return err
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.KID == kid })
		if i < 0 {
			return errors.New("client key not found")
		}
		k := s.state.SSOClientKeys[i]
		if k.Status == models.ClientKeyActive && s.state.EntraConfig.TokenAuthMethod == oidc.TokenAuthPrivateKeyJWT {
			return errors.New("the active key signs the private_key_jwt client assertions: activate another key or switch the client authentication first")
		}
		s.state.SSOClientKeys = slices.Delete(s.state.SSOClientKeys, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SSO_CLIENT_KEY_DELETED", Category: "IDENTITY",
			EntityType: "sso_client_key", EntityID: kid, EntityName: "SSO client key " + k.Alg,
			Summary: fmt.Sprintf("Deleted %s SSO client key %s; it is no longer published", k.Status, kid),
		})
		s.markDirtyLocked()
		return nil
	})
}
