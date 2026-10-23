package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const (
	serviceKeyPrefix     = "aegis_sa_"
	maxServiceAccounts   = 200
	maxServiceKeyDays    = 730
	saTouchPersistPeriod = 10 * time.Minute
)

// IsServiceKey reports whether a bearer credential is a service-account API key.
func IsServiceKey(raw string) bool { return strings.HasPrefix(raw, serviceKeyPrefix) }

func hashServiceKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func newServiceKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return serviceKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ServiceAccountInput is the editable part of a service account.
type ServiceAccountInput struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Role          models.Role `json:"role"`
	AllowedGroups []string    `json:"allowed_groups"`
	AllowedCIDRs  []string    `json:"allowed_cidrs"`
	Disabled      bool        `json:"disabled"`
	ExpiresAt     time.Time   `json:"expires_at"`
}

func (s *Store) validateServiceAccountLocked(in *ServiceAccountInput, selfID string) error {
	in.Name = strings.TrimSpace(in.Name)
	if !usernameRe.MatchString(strings.ToLower(in.Name)) {
		return errors.New("name must be 2-64 characters: letters, digits, '.', '_' or '-'")
	}
	for _, sa := range s.state.ServiceAccounts {
		if sa.ID != selfID && strings.EqualFold(sa.Name, in.Name) {
			return fmt.Errorf("a service account named %q already exists", sa.Name)
		}
	}
	if err := checkText("description", in.Description, 500, false); err != nil {
		return err
	}
	switch in.Role {
	case models.RoleInfoSecApprover, models.RoleTeamLead, models.RoleAuditorOperator:
	case models.RoleSuperAdmin:
		return errors.New("service accounts cannot be Super Admins (user, key and export management stay with people)")
	default:
		return errors.New("role must be INFOSEC_APPROVER, TEAM_LEAD_APPROVER or OPERATOR_AUDITOR")
	}
	if in.AllowedGroups == nil {
		in.AllowedGroups = []string{}
	}
	if in.Role == models.RoleTeamLead {
		if len(in.AllowedGroups) == 0 || slices.Contains(in.AllowedGroups, "*") {
			return errors.New("Team Lead service accounts need concrete allowed groups")
		}
		if err := s.validateScopeLocked(in.AllowedGroups, nil); err != nil {
			return err
		}
	} else if in.Role == models.RoleInfoSecApprover {
		in.AllowedGroups = []string{"*"}
	}
	if len(in.AllowedCIDRs) > 50 {
		return errors.New("at most 50 allowed CIDRs")
	}
	cidrs := make([]string, 0, len(in.AllowedCIDRs))
	for _, c := range in.AllowedCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if a, err := netip.ParseAddr(c); err == nil {
				c = netip.PrefixFrom(a, a.BitLen()).String()
			}
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", c)
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	in.AllowedCIDRs = cidrs
	now := time.Now()
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = now.Add(365 * 24 * time.Hour)
	}
	if in.ExpiresAt.Before(now.Add(time.Hour)) || in.ExpiresAt.After(now.Add(maxServiceKeyDays*24*time.Hour)) {
		return fmt.Errorf("expires_at must be between 1 hour and %d days from now", maxServiceKeyDays)
	}
	in.ExpiresAt = in.ExpiresAt.UTC()
	return nil
}

func requireSuperAdmin(actor *auth.TokenClaims) error {
	if actor == nil || actor.Role != models.RoleSuperAdmin || actor.ServiceAccount {
		return errors.New("RBAC Policy: only Super Admins (people) can manage service accounts")
	}
	return nil
}

func (s *Store) ServiceAccounts() []models.ServiceAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.ServiceAccount, len(s.state.ServiceAccounts))
	for i, sa := range s.state.ServiceAccounts {
		out[i] = sa.Public()
	}
	return out
}

// CreateServiceAccount returns the account and its API key (shown once).
func (s *Store) CreateServiceAccount(in ServiceAccountInput, actor *auth.TokenClaims) (models.ServiceAccount, string, error) {
	if err := requireSuperAdmin(actor); err != nil {
		return models.ServiceAccount{}, "", err
	}
	key, err := newServiceKey()
	if err != nil {
		return models.ServiceAccount{}, "", err
	}
	var out models.ServiceAccount
	err = s.withWrite(func() error {
		if len(s.state.ServiceAccounts) >= maxServiceAccounts {
			return fmt.Errorf("at most %d service accounts", maxServiceAccounts)
		}
		if err := s.validateServiceAccountLocked(&in, ""); err != nil {
			return err
		}
		now := time.Now().UTC()
		sa := models.ServiceAccount{ID: newRandomID("sa"), Name: in.Name, Description: in.Description, Role: in.Role,
			AllowedGroups: in.AllowedGroups, AllowedCIDRs: in.AllowedCIDRs, Disabled: in.Disabled, ExpiresAt: in.ExpiresAt,
			KeyPrefix: key[:len(serviceKeyPrefix)+6], KeyHash: hashServiceKey(key), CreatedAt: now, CreatedBy: actor.Username}
		s.state.ServiceAccounts = append(s.state.ServiceAccounts, sa)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVICE_ACCOUNT_CREATED", Category: "IDENTITY",
			EntityType: "service_account", EntityID: sa.ID, EntityName: sa.Name,
			Summary: fmt.Sprintf("Created service account %q (role %s, groups %v, CIDRs %v, expires %s)", sa.Name, sa.Role, sa.AllowedGroups, sa.AllowedCIDRs, sa.ExpiresAt.Format("2006-01-02")),
		})
		s.saveLocked()
		out = sa.Public()
		return nil
	})
	if err != nil {
		return models.ServiceAccount{}, "", err
	}
	return out, key, nil
}

func (s *Store) UpdateServiceAccount(id string, in ServiceAccountInput, actor *auth.TokenClaims) (models.ServiceAccount, error) {
	if err := requireSuperAdmin(actor); err != nil {
		return models.ServiceAccount{}, err
	}
	var out models.ServiceAccount
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ServiceAccounts, func(x models.ServiceAccount) bool { return x.ID == id })
		if i < 0 {
			return errors.New("service account not found")
		}
		if err := s.validateServiceAccountLocked(&in, id); err != nil {
			return err
		}
		sa := &s.state.ServiceAccounts[i]
		before := fmt.Sprintf("role=%s groups=%v cidrs=%v disabled=%v expires=%s", sa.Role, sa.AllowedGroups, sa.AllowedCIDRs, sa.Disabled, sa.ExpiresAt.Format("2006-01-02"))
		sa.Name, sa.Description, sa.Role, sa.AllowedGroups, sa.AllowedCIDRs, sa.Disabled, sa.ExpiresAt =
			in.Name, in.Description, in.Role, in.AllowedGroups, in.AllowedCIDRs, in.Disabled, in.ExpiresAt
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVICE_ACCOUNT_UPDATED", Category: "IDENTITY",
			EntityType: "service_account", EntityID: sa.ID, EntityName: sa.Name,
			Summary:     fmt.Sprintf("Updated service account %q", sa.Name),
			BeforeState: before,
			AfterState:  fmt.Sprintf("role=%s groups=%v cidrs=%v disabled=%v expires=%s", sa.Role, sa.AllowedGroups, sa.AllowedCIDRs, sa.Disabled, sa.ExpiresAt.Format("2006-01-02")),
		})
		s.saveLocked()
		out = sa.Public()
		return nil
	})
	return out, err
}

// RotateServiceAccountKey replaces the key; the old key stops working immediately.
func (s *Store) RotateServiceAccountKey(id string, actor *auth.TokenClaims) (models.ServiceAccount, string, error) {
	if err := requireSuperAdmin(actor); err != nil {
		return models.ServiceAccount{}, "", err
	}
	key, err := newServiceKey()
	if err != nil {
		return models.ServiceAccount{}, "", err
	}
	var out models.ServiceAccount
	err = s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ServiceAccounts, func(x models.ServiceAccount) bool { return x.ID == id })
		if i < 0 {
			return errors.New("service account not found")
		}
		sa := &s.state.ServiceAccounts[i]
		now := time.Now().UTC()
		sa.KeyHash, sa.KeyPrefix, sa.KeyRotatedAt = hashServiceKey(key), key[:len(serviceKeyPrefix)+6], &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVICE_ACCOUNT_KEY_ROTATED", Category: "IDENTITY",
			EntityType: "service_account", EntityID: sa.ID, EntityName: sa.Name, Summary: fmt.Sprintf("Rotated API key of %q; the previous key is revoked", sa.Name),
		})
		s.saveLocked()
		out = sa.Public()
		return nil
	})
	if err != nil {
		return models.ServiceAccount{}, "", err
	}
	return out, key, nil
}

func (s *Store) DeleteServiceAccount(id string, actor *auth.TokenClaims) error {
	if err := requireSuperAdmin(actor); err != nil {
		return err
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ServiceAccounts, func(x models.ServiceAccount) bool { return x.ID == id })
		if i < 0 {
			return errors.New("service account not found")
		}
		sa := s.state.ServiceAccounts[i]
		s.state.ServiceAccounts = slices.Delete(s.state.ServiceAccounts, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVICE_ACCOUNT_DELETED", Category: "IDENTITY",
			EntityType: "service_account", EntityID: sa.ID, EntityName: sa.Name, Summary: fmt.Sprintf("Deleted service account %q; its key is revoked", sa.Name),
		})
		s.saveLocked()
		return nil
	})
}

// AuthenticateServiceKey validates an API key and returns claims for the request.
func (s *Store) AuthenticateServiceKey(key, clientIP string) (*auth.TokenClaims, error) {
	h := hashServiceKey(key)
	s.mu.RLock()
	i, ok := s.saByHash[h]
	var sa models.ServiceAccount
	if ok && i < len(s.state.ServiceAccounts) && s.state.ServiceAccounts[i].KeyHash == h {
		sa = s.state.ServiceAccounts[i]
	} else {
		ok = false
	}
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("invalid API key")
	}
	if sa.Disabled {
		return nil, errors.New("service account is disabled")
	}
	if time.Now().After(sa.ExpiresAt) {
		return nil, errors.New("API key expired")
	}
	if len(sa.AllowedCIDRs) > 0 {
		addr, err := netip.ParseAddr(clientIP)
		allowed := false
		if err == nil {
			for _, c := range sa.AllowedCIDRs {
				if p, err := netip.ParsePrefix(c); err == nil && p.Contains(addr.Unmap()) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return nil, fmt.Errorf("API key not allowed from %s", clientIP)
		}
	}
	s.touchServiceAccount(sa.ID, clientIP)
	return &auth.TokenClaims{UserID: "sa:" + sa.ID, Username: "sa:" + sa.Name, DisplayName: sa.Name, Role: sa.Role,
		AllowedGroups: append([]string(nil), sa.AllowedGroups...), ServiceAccount: true}, nil
}

// touchServiceAccount records last use (persisted at most every 10 minutes per account).
func (s *Store) touchServiceAccount(id, ip string) {
	s.saTouchMu.Lock()
	if s.saTouched == nil {
		s.saTouched = map[string]time.Time{}
	}
	last, seen := s.saTouched[id]
	if seen && time.Since(last) < saTouchPersistPeriod {
		s.saTouchMu.Unlock()
		return
	}
	s.saTouched[id] = time.Now()
	s.saTouchMu.Unlock()
	go func() {
		_ = s.withWrite(func() error {
			i := slices.IndexFunc(s.state.ServiceAccounts, func(x models.ServiceAccount) bool { return x.ID == id })
			if i < 0 {
				return nil
			}
			now := time.Now().UTC()
			s.state.ServiceAccounts[i].LastUsedAt, s.state.ServiceAccounts[i].LastUsedIP = &now, ip
			s.markDirtyLocked()
			return nil
		})
	}()
}
