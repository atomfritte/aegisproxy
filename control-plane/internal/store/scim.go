package store

// SCIM 2.0 provisioning (RFC 7643/7644) for Microsoft Entra ID and Okta: the IdP creates, updates,
// deactivates and deletes console accounts and pushes groups. SCIM is authoritative for the accounts
// it manages: role and Team Lead scope come from the SCIM group memberships through the SSO
// group_role_map / group_scope_map (keys: group display name or external ID). Local and
// break-glass accounts are never SCIM resources and cannot be modified through SCIM.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const (
	scimTokenPrefix    = "aegis_scim_"
	maxSCIMTokens      = 5
	maxSCIMTokenDays   = 730
	maxSCIMUsers       = 20_000
	maxSCIMGroups      = 5_000
	maxSCIMMembers     = 50_000
	scimTouchPeriod    = 10 * time.Minute
	scimActorRole      = "SCIM"
	maxSCIMAttrLen     = 256
	maxSCIMEmails      = 10
	scimDefaultTokenTT = 365 * 24 * time.Hour
)

// SCIM error kinds (RFC 7644 section 3.12 scimType, plus notFound/forbidden/tooMany for the status).
const (
	SCIMUniqueness   = "uniqueness"
	SCIMInvalidValue = "invalidValue"
	SCIMMutability   = "mutability"
	SCIMNotFound     = "notFound"
	SCIMTooMany      = "tooMany"
	SCIMPrecondition = "precondition"
)

// SCIMError is a provisioning error reported to the SCIM client.
type SCIMError struct {
	Kind   string
	Detail string
}

func (e *SCIMError) Error() string { return e.Detail }

func scimErr(kind, format string, a ...any) error {
	return &SCIMError{Kind: kind, Detail: fmt.Sprintf(format, a...)}
}

// ---------------------------------------------------------------------------
// Configuration and tokens (Super Admins)
// ---------------------------------------------------------------------------

// SCIMStatus is the provisioning overview for the console.
type SCIMStatus struct {
	Enabled     bool               `json:"enabled"`
	Tokens      []models.SCIMToken `json:"tokens"`
	Users       int                `json:"users"`
	ActiveUsers int                `json:"active_users"`
	Groups      int                `json:"groups"`
	Changes     int64              `json:"changes"`
	LastSyncAt  *time.Time         `json:"last_sync_at,omitempty"`
	LastRequest *time.Time         `json:"last_request_at,omitempty"`
}

func (s *Store) SCIMStatus() SCIMStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.state.SCIM
	st := SCIMStatus{Enabled: c.Enabled, Tokens: []models.SCIMToken{}, Groups: len(s.state.SCIMGroups), Changes: c.Changes, LastSyncAt: c.LastSyncAt}
	for _, t := range c.Tokens {
		st.Tokens = append(st.Tokens, t.Public())
		if t.LastUsedAt != nil && (st.LastRequest == nil || t.LastUsedAt.After(*st.LastRequest)) {
			lu := *t.LastUsedAt
			st.LastRequest = &lu
		}
	}
	for _, u := range s.state.Users {
		if u.SCIM != nil && !u.SCIM.Deleted {
			st.Users++
			if !u.Disabled {
				st.ActiveUsers++
			}
		}
	}
	return st
}

// IsSCIMToken reports whether a bearer credential is a SCIM provisioning token.
func IsSCIMToken(raw string) bool { return strings.HasPrefix(raw, scimTokenPrefix) }

func newSCIMToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return scimTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hashSCIMToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// UpdateSCIMConfig enables or disables provisioning. Enabling applies the current group mapping to
// every SCIM-managed account.
func (s *Store) UpdateSCIMConfig(enabled bool, actor *auth.TokenClaims) (SCIMStatus, error) {
	if err := requirePersonSuperAdmin(actor, "configure SCIM provisioning"); err != nil {
		return SCIMStatus{}, err
	}
	err := s.withWrite(func() error {
		if s.state.SCIM.Enabled == enabled {
			return nil
		}
		s.state.SCIM.Enabled = enabled
		summary := "Disabled SCIM provisioning: the SCIM endpoints refuse every request; provisioned accounts keep their state"
		if enabled {
			summary = "Enabled SCIM provisioning"
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SCIM_CONFIG_UPDATED", Category: "IDENTITY",
			EntityType: "scim_config", EntityID: "scim", EntityName: "SCIM provisioning", Summary: summary,
		})
		if enabled {
			s.syncAllSCIMUsersLocked("system", time.Now().UTC())
		}
		s.markDirtyLocked()
		return nil
	})
	if err != nil {
		return SCIMStatus{}, err
	}
	return s.SCIMStatus(), nil
}

// CreateSCIMToken issues a provisioning token (returned once; only its digest is stored).
func (s *Store) CreateSCIMToken(name string, expiresAt time.Time, actor *auth.TokenClaims) (models.SCIMToken, string, error) {
	if err := requirePersonSuperAdmin(actor, "manage SCIM tokens"); err != nil {
		return models.SCIMToken{}, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "scim"
	}
	if err := checkText("name", name, 64, true); err != nil {
		return models.SCIMToken{}, "", err
	}
	now := time.Now().UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(scimDefaultTokenTT)
	}
	if expiresAt.Before(now.Add(time.Hour)) || expiresAt.After(now.Add(maxSCIMTokenDays*24*time.Hour)) {
		return models.SCIMToken{}, "", fmt.Errorf("expires_at must be between 1 hour and %d days from now", maxSCIMTokenDays)
	}
	raw, err := newSCIMToken()
	if err != nil {
		return models.SCIMToken{}, "", err
	}
	var out models.SCIMToken
	err = s.withWrite(func() error {
		if len(s.state.SCIM.Tokens) >= maxSCIMTokens {
			return fmt.Errorf("at most %d SCIM tokens; revoke an old one first", maxSCIMTokens)
		}
		for _, t := range s.state.SCIM.Tokens {
			if strings.EqualFold(t.Name, name) {
				return fmt.Errorf("a SCIM token named %q already exists", t.Name)
			}
		}
		t := models.SCIMToken{ID: newRandomID("scimtok"), Name: name, Prefix: raw[:len(scimTokenPrefix)+6], Hash: hashSCIMToken(raw),
			CreatedAt: now, CreatedBy: actor.Username, ExpiresAt: expiresAt.UTC()}
		s.state.SCIM.Tokens = append(s.state.SCIM.Tokens, t)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SCIM_TOKEN_CREATED", Category: "IDENTITY",
			EntityType: "scim_token", EntityID: t.ID, EntityName: t.Name,
			Summary: fmt.Sprintf("Created SCIM provisioning token %q (%s…, expires %s)", t.Name, t.Prefix, t.ExpiresAt.Format("2006-01-02")),
		})
		s.markDirtyLocked()
		out = t.Public()
		return nil
	})
	if err != nil {
		return models.SCIMToken{}, "", err
	}
	return out, raw, nil
}

// RotateSCIMToken replaces the secret of a token; the previous value stops working immediately.
func (s *Store) RotateSCIMToken(id string, actor *auth.TokenClaims) (models.SCIMToken, string, error) {
	if err := requirePersonSuperAdmin(actor, "manage SCIM tokens"); err != nil {
		return models.SCIMToken{}, "", err
	}
	raw, err := newSCIMToken()
	if err != nil {
		return models.SCIMToken{}, "", err
	}
	var out models.SCIMToken
	err = s.withWrite(func() error {
		i := slices.IndexFunc(s.state.SCIM.Tokens, func(t models.SCIMToken) bool { return t.ID == id })
		if i < 0 {
			return errors.New("SCIM token not found")
		}
		now := time.Now().UTC()
		t := &s.state.SCIM.Tokens[i]
		t.Hash, t.Prefix, t.RotatedAt = hashSCIMToken(raw), raw[:len(scimTokenPrefix)+6], &now
		if t.ExpiresAt.Before(now.Add(30 * 24 * time.Hour)) {
			t.ExpiresAt = now.Add(scimDefaultTokenTT)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SCIM_TOKEN_ROTATED", Category: "IDENTITY",
			EntityType: "scim_token", EntityID: t.ID, EntityName: t.Name,
			Summary: fmt.Sprintf("Rotated SCIM provisioning token %q; the previous value is revoked", t.Name),
		})
		s.markDirtyLocked()
		out = t.Public()
		return nil
	})
	if err != nil {
		return models.SCIMToken{}, "", err
	}
	return out, raw, nil
}

func (s *Store) RevokeSCIMToken(id string, actor *auth.TokenClaims) error {
	if err := requirePersonSuperAdmin(actor, "manage SCIM tokens"); err != nil {
		return err
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.SCIM.Tokens, func(t models.SCIMToken) bool { return t.ID == id })
		if i < 0 {
			return errors.New("SCIM token not found")
		}
		t := s.state.SCIM.Tokens[i]
		s.state.SCIM.Tokens = slices.Delete(s.state.SCIM.Tokens, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SCIM_TOKEN_REVOKED", Category: "IDENTITY",
			EntityType: "scim_token", EntityID: t.ID, EntityName: t.Name, Summary: fmt.Sprintf("Revoked SCIM provisioning token %q", t.Name),
		})
		s.markDirtyLocked()
		return nil
	})
}

// ErrSCIMDisabled is returned for SCIM requests while provisioning is switched off.
var ErrSCIMDisabled = errors.New("SCIM provisioning is disabled")

// AuthenticateSCIM validates a provisioning token and returns the audit actor ("scim:<name>").
func (s *Store) AuthenticateSCIM(raw, clientIP string) (string, error) {
	if !IsSCIMToken(raw) {
		return "", errors.New("invalid SCIM token")
	}
	h := hashSCIMToken(raw)
	s.mu.RLock()
	enabled := s.state.SCIM.Enabled
	var tok models.SCIMToken
	found := false
	for _, t := range s.state.SCIM.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) == 1 {
			tok, found = t, true
		}
	}
	s.mu.RUnlock()
	if !found {
		return "", errors.New("invalid SCIM token")
	}
	if time.Now().After(tok.ExpiresAt) {
		return "", errors.New("SCIM token expired")
	}
	if !enabled {
		return "", ErrSCIMDisabled
	}
	s.touchSCIMToken(tok.ID, clientIP)
	return "scim:" + tok.Name, nil
}

func (s *Store) touchSCIMToken(id, ip string) {
	s.saTouchMu.Lock()
	if s.saTouched == nil {
		s.saTouched = map[string]time.Time{}
	}
	key := "scim:" + id
	if last, ok := s.saTouched[key]; ok && time.Since(last) < scimTouchPeriod {
		s.saTouchMu.Unlock()
		return
	}
	s.saTouched[key] = time.Now()
	s.saTouchMu.Unlock()
	go func() {
		_ = s.withWrite(func() error {
			i := slices.IndexFunc(s.state.SCIM.Tokens, func(t models.SCIMToken) bool { return t.ID == id })
			if i < 0 {
				return nil
			}
			now := time.Now().UTC()
			s.state.SCIM.Tokens[i].LastUsedAt, s.state.SCIM.Tokens[i].LastUsedIP = &now, ip
			s.markDirtyLocked()
			return nil
		})
	}()
}

// ---------------------------------------------------------------------------
// Role synchronization
// ---------------------------------------------------------------------------

// scimMembershipsLocked maps user IDs to the membership keys of their SCIM groups (scimGroupKeys:
// external ID as identifier, display name only for "name:" mappings).
func (s *Store) scimMembershipsLocked() map[string][]string {
	out := map[string][]string{}
	for _, g := range s.state.SCIMGroups {
		keys := scimGroupKeys(g)
		for _, m := range g.Members {
			out[m.Value] = append(out[m.Value], keys...)
		}
	}
	return out
}

func (s *Store) syncAllSCIMUsersLocked(actor string, now time.Time) {
	if !s.state.SCIM.Enabled {
		return
	}
	mem := s.scimMembershipsLocked()
	for i := range s.state.Users {
		if s.state.Users[i].SCIM != nil {
			s.syncSCIMUserLocked(i, mem, actor, now, false)
		}
	}
}

// syncSCIMUserLocked derives role, scope and enablement of a SCIM-managed account. A deactivated or
// deleted account, or one without a mapped group, is disabled and its sessions are revoked at once.
func (s *Store) syncSCIMUserLocked(i int, mem map[string][]string, actor string, now time.Time, quietDeprovision bool) {
	u := &s.state.Users[i]
	if u.SCIM == nil {
		return
	}
	role, groups := mapIdPGroups(s.state.EntraConfig, mem[u.ID])
	reason := ""
	switch {
	case u.SCIM.Deleted:
		reason = "deleted by the SCIM client"
	case !u.SCIM.IsActive():
		reason = "deactivated by the SCIM client (active=false)"
	case role == "":
		reason = "none of its SCIM groups is mapped to a role"
	}
	prevDisabled, prevRole, prevGroups := u.Disabled, u.Role, u.AllowedGroups
	u.Role, u.AllowedGroups = role, groups
	u.Disabled = u.DisabledByAdmin || reason != ""
	switch {
	case !prevDisabled && u.Disabled:
		u.SessionsNotBefore = &now
		if !quietDeprovision {
			s.appendAuditLocked(models.AuditEvent{
				Actor: actor, ActorRole: scimActorRole, Action: "USER_DEPROVISIONED_SCIM", Category: "IDENTITY",
				EntityType: "user", EntityID: u.ID, EntityName: u.Username,
				Summary:     fmt.Sprintf("Disabled %s and revoked all sessions: %s", u.Username, reason),
				BeforeState: fmt.Sprintf("role=%s groups=%v disabled=false", prevRole, prevGroups),
			})
		}
	case prevDisabled && !u.Disabled:
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "USER_REACTIVATED_SCIM", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: fmt.Sprintf("Re-enabled %s through SCIM with role %s %v", u.Username, role, groups),
		})
	case !u.Disabled && (prevRole != role || !slices.Equal(prevGroups, groups)):
		u.SessionsNotBefore = &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "USER_ROLE_SYNCED", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary:     fmt.Sprintf("Role of %s synchronized from SCIM groups: %s %v -> %s %v (sessions revoked)", u.Username, prevRole, prevGroups, role, groups),
			BeforeState: fmt.Sprintf("role=%s groups=%v", prevRole, prevGroups),
			AfterState:  fmt.Sprintf("role=%s groups=%v", role, groups),
		})
	}
}

func (s *Store) noteSCIMChangeLocked(now time.Time) {
	s.state.SCIM.LastSyncAt = &now
	s.state.SCIM.Changes++
	s.markDirtyLocked()
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// SCIMUserView is a SCIM-managed account with its group memberships.
type SCIMUserView struct {
	User   models.User
	Groups []models.SCIMGroup // ID and DisplayName only
}

func (s *Store) scimUserViewLocked(u models.User) SCIMUserView {
	v := SCIMUserView{User: u.Public()}
	for _, g := range s.state.SCIMGroups {
		if slices.ContainsFunc(g.Members, func(m models.SCIMMember) bool { return m.Value == u.ID }) {
			v.Groups = append(v.Groups, models.SCIMGroup{ID: g.ID, DisplayName: g.DisplayName})
		}
	}
	return v
}

// SCIMUsers returns every SCIM-managed account that was not deleted by the SCIM client.
func (s *Store) SCIMUsers() []SCIMUserView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groupsOf := map[string][]models.SCIMGroup{}
	for _, g := range s.state.SCIMGroups {
		for _, m := range g.Members {
			groupsOf[m.Value] = append(groupsOf[m.Value], models.SCIMGroup{ID: g.ID, DisplayName: g.DisplayName})
		}
	}
	out := []SCIMUserView{}
	for _, u := range s.state.Users {
		if u.SCIM != nil && !u.SCIM.Deleted {
			out = append(out, SCIMUserView{User: u.Public(), Groups: groupsOf[u.ID]})
		}
	}
	return out
}

func (s *Store) SCIMUser(id string) (SCIMUserView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := s.scimUserIndexLocked(id)
	if i < 0 {
		return SCIMUserView{}, false
	}
	return s.scimUserViewLocked(s.state.Users[i]), true
}

func (s *Store) scimUserIndexLocked(id string) int {
	return slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ID == id && u.SCIM != nil && !u.SCIM.Deleted })
}

// normalizeSCIMUser validates the client-supplied attributes.
func normalizeSCIMUser(in *models.SCIMUser) error {
	in.UserName = strings.TrimSpace(in.UserName)
	if in.UserName == "" {
		return scimErr(SCIMInvalidValue, "userName is required")
	}
	for _, f := range []struct{ n, v string }{{"userName", in.UserName}, {"externalId", in.ExternalID}, {"displayName", in.DisplayName},
		{"name.givenName", in.GivenName}, {"name.familyName", in.FamilyName}, {"name.formatted", in.Formatted}, {"title", in.Title}, {"department", in.Department}} {
		if len(f.v) > maxSCIMAttrLen || hasCtl(f.v) {
			return scimErr(SCIMInvalidValue, "%s must be at most %d characters without control characters", f.n, maxSCIMAttrLen)
		}
	}
	if len(in.Emails) > maxSCIMEmails {
		return scimErr(SCIMInvalidValue, "at most %d e-mail addresses", maxSCIMEmails)
	}
	primaries := 0
	for _, e := range in.Emails {
		if e.Value == "" || len(e.Value) > 254 || len(e.Type) > 64 || hasCtl(e.Value+e.Type) {
			return scimErr(SCIMInvalidValue, "invalid e-mail address %q", clip(e.Value, 80))
		}
		if e.Primary {
			primaries++
		}
	}
	if primaries > 1 {
		return scimErr(SCIMInvalidValue, "at most one e-mail address can be primary")
	}
	return nil
}

// consoleUsernameLocked derives a unique, valid console username from the SCIM userName (UPNs
// become user.name like single sign-on does).
func (s *Store) consoleUsernameLocked(userName, selfID string) string {
	name := s.plainUsernameLocked(userName)
	sum := sha256.Sum256([]byte(strings.ToLower(userName)))
	tag := hex.EncodeToString(sum[:])
	if !usernameRe.MatchString(name) {
		name = "scim-" + tag[:12]
	}
	taken := func(n string) bool {
		return slices.ContainsFunc(s.state.Users, func(u models.User) bool { return u.ID != selfID && strings.EqualFold(u.Username, n) })
	}
	if taken(name) {
		// Never take over another account (local, break-glass or another IdP user) by name.
		name = clip(name, 56) + "-" + tag[:6]
		if taken(name) {
			name = "scim-" + tag[:16]
		}
	}
	return name
}

// plainUsernameLocked is the console username single sign-on would derive from the same value.
func (s *Store) plainUsernameLocked(userName string) string {
	name := strings.ToLower(userName)
	if strings.Contains(name, "@") && s.state.EntraConfig.UsernameClaim != "email" {
		name = strings.ReplaceAll(name, "@", ".")
	}
	return name
}

func primaryEmail(emails []models.SCIMEmail) string {
	for _, e := range emails {
		if e.Primary {
			return e.Value
		}
	}
	for _, e := range emails {
		if strings.EqualFold(e.Type, "work") {
			return e.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

// applySCIMProfileLocked copies the SCIM attributes onto the console account (copy-on-write: the
// SCIM struct is replaced, never modified in place, because readers hold copies of the pointer).
func (s *Store) applySCIMProfileLocked(u *models.User, in models.SCIMUser, now time.Time) {
	prev := u.SCIM
	sc := in
	sc.Emails = append([]models.SCIMEmail(nil), in.Emails...)
	sc.Deleted, sc.LastModified = false, now
	if prev != nil && !prev.Deleted {
		sc.Created, sc.Version = prev.Created, prev.Version+1
	} else {
		sc.Created, sc.Version = now, 1
	}
	u.SCIM = &sc
	if prev == nil || !strings.EqualFold(prev.UserName, sc.UserName) {
		u.Username = s.consoleUsernameLocked(sc.UserName, u.ID)
	}
	u.DisplayName = clip(firstNonEmpty(sc.DisplayName, sc.Formatted, strings.TrimSpace(sc.GivenName+" "+sc.FamilyName), sc.UserName), 120)
	u.Email = ""
	if e := primaryEmail(sc.Emails); e != "" {
		if _, err := mail.ParseAddress(e); err == nil {
			u.Email = clip(e, 254)
		}
	}
	u.Department = clip(sc.Department, 120)
}

func scimUserUnchanged(a, b *models.SCIMUser) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.Version, y.Version, x.Created, y.Created, x.LastModified, y.LastModified = 0, 0, time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if (x.Active == nil) != (y.Active == nil) || (x.Active != nil && *x.Active != *y.Active) {
		return false
	}
	x.Active, y.Active = nil, nil
	return fmt.Sprint(x) == fmt.Sprint(y)
}

func (s *Store) scimUserNameTakenLocked(userName, selfID string) bool {
	return slices.ContainsFunc(s.state.Users, func(u models.User) bool {
		return u.ID != selfID && u.SCIM != nil && !u.SCIM.Deleted && strings.EqualFold(u.SCIM.UserName, userName)
	})
}

// SCIMCreateUser provisions an account. A single-sign-on account that signed in before SCIM was set
// up (same subject or username) is claimed instead of duplicated, and a user the SCIM client deleted
// earlier is revived, so that the person keeps one account and one audit trail.
func (s *Store) SCIMCreateUser(in models.SCIMUser, actor string) (SCIMUserView, error) {
	if err := normalizeSCIMUser(&in); err != nil {
		return SCIMUserView{}, err
	}
	var out SCIMUserView
	err := s.withWrite(func() error {
		if s.scimUserNameTakenLocked(in.UserName, "") {
			return scimErr(SCIMUniqueness, "userName %q already exists", in.UserName)
		}
		now := time.Now().UTC()
		issuer := normalizeSSO(s.state.EntraConfig, "").IssuerURL
		action, how := "USER_PROVISIONED_SCIM", "Provisioned"
		// 1. revive a tombstone of the same person
		i := slices.IndexFunc(s.state.Users, func(u models.User) bool {
			return u.SCIM != nil && u.SCIM.Deleted && (strings.EqualFold(u.SCIM.UserName, in.UserName) || (in.ExternalID != "" && u.SCIM.ExternalID == in.ExternalID))
		})
		if i >= 0 {
			how = "Re-provisioned (previously deleted)"
		} else {
			// 2. claim a just-in-time single-sign-on account (never a local one)
			claimable := func(u models.User) bool { return u.AuthProvider == "oidc" && u.SCIM == nil }
			if in.ExternalID != "" && issuer != "" {
				ext := externalID(issuer, in.ExternalID)
				i = slices.IndexFunc(s.state.Users, func(u models.User) bool { return claimable(u) && u.ExternalID == ext })
			}
			if i < 0 {
				plain := s.plainUsernameLocked(in.UserName)
				i = slices.IndexFunc(s.state.Users, func(u models.User) bool { return claimable(u) && u.Username == plain })
			}
			if i >= 0 {
				action, how = "USER_LINKED_SCIM", "Took over the single sign-on account"
			}
		}
		if i < 0 {
			if n := s.countSCIMUsersLocked(); n >= maxSCIMUsers {
				return scimErr(SCIMTooMany, "at most %d SCIM-provisioned users", maxSCIMUsers)
			}
			s.state.Users = append(s.state.Users, models.User{ID: newRandomID("usr"), AuthProvider: "oidc", AllowedGroups: []string{}, CreatedAt: now})
			i = len(s.state.Users) - 1
		}
		s.applySCIMProfileLocked(&s.state.Users[i], in, now)
		s.syncSCIMUserLocked(i, s.scimMembershipsLocked(), actor, now, true)
		u := &s.state.Users[i]
		state := "enabled"
		if u.Disabled {
			state = "disabled until a SCIM group mapped to a role includes it"
			if !u.SCIM.IsActive() {
				state = "inactive"
			}
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: action, Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: fmt.Sprintf("%s %s via SCIM (userName %s, externalId %q, role %s, %s)", how, u.Username, in.UserName, in.ExternalID, firstNonEmpty(string(u.Role), "none"), state),
		})
		s.noteSCIMChangeLocked(now)
		out = s.scimUserViewLocked(*u)
		return nil
	})
	return out, err
}

func (s *Store) countSCIMUsersLocked() int {
	n := 0
	for _, u := range s.state.Users {
		if u.SCIM != nil {
			n++
		}
	}
	return n
}

// SCIMUpdateUser replaces the attributes of an account (PUT, and PATCH after the patch was applied
// to the current representation by update). update runs under the write lock and receives the
// current state, so concurrent PATCH requests cannot lose changes. ifMatch (meta.version) is
// checked when not zero.
func (s *Store) SCIMUpdateUser(id string, ifMatch int64, update func(cur SCIMUserView) (models.SCIMUser, error), actor string) (SCIMUserView, error) {
	var out SCIMUserView
	err := s.withWrite(func() error {
		i := s.scimUserIndexLocked(id)
		if i < 0 {
			return scimErr(SCIMNotFound, "user %s not found", id)
		}
		if ifMatch != 0 && s.state.Users[i].SCIM.Version != ifMatch {
			return scimErr(SCIMPrecondition, "the user was modified (version %d)", s.state.Users[i].SCIM.Version)
		}
		in, err := update(s.scimUserViewLocked(s.state.Users[i]))
		if err != nil {
			return err
		}
		if err := normalizeSCIMUser(&in); err != nil {
			return err
		}
		if s.scimUserNameTakenLocked(in.UserName, id) {
			return scimErr(SCIMUniqueness, "userName %q already exists", in.UserName)
		}
		u := &s.state.Users[i]
		before := u.SCIM
		in.Created, in.Version = before.Created, before.Version
		if scimUserUnchanged(before, &in) {
			out = s.scimUserViewLocked(*u)
			return nil
		}
		now := time.Now().UTC()
		s.applySCIMProfileLocked(u, in, now)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "USER_UPDATED_SCIM", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary:     fmt.Sprintf("Updated %s via SCIM (userName %s, active %v)", u.Username, in.UserName, in.IsActive()),
			BeforeState: fmt.Sprintf("userName=%s externalId=%s active=%v", before.UserName, before.ExternalID, before.IsActive()),
			AfterState:  fmt.Sprintf("userName=%s externalId=%s active=%v", in.UserName, in.ExternalID, in.IsActive()),
		})
		s.syncSCIMUserLocked(i, s.scimMembershipsLocked(), actor, now, false)
		s.noteSCIMChangeLocked(now)
		out = s.scimUserViewLocked(s.state.Users[i])
		return nil
	})
	return out, err
}

// SCIMDeleteUser deprovisions an account: it is disabled, its sessions are revoked, it leaves every
// SCIM group and is no longer a SCIM resource. The record stays for the audit trail.
func (s *Store) SCIMDeleteUser(id string, actor string) error {
	return s.withWrite(func() error {
		i := s.scimUserIndexLocked(id)
		if i < 0 {
			return scimErr(SCIMNotFound, "user %s not found", id)
		}
		now := time.Now().UTC()
		u := &s.state.Users[i]
		sc := *u.SCIM
		sc.Deleted, sc.Version, sc.LastModified = true, sc.Version+1, now
		u.SCIM = &sc
		left := 0
		for gi := range s.state.SCIMGroups {
			g := &s.state.SCIMGroups[gi]
			n := len(g.Members)
			g.Members = slices.DeleteFunc(slices.Clone(g.Members), func(m models.SCIMMember) bool { return m.Value == id })
			if len(g.Members) != n {
				left++
				g.Version, g.LastModified = g.Version+1, now
			}
		}
		s.syncSCIMUserLocked(i, s.scimMembershipsLocked(), actor, now, true)
		u = &s.state.Users[i]
		u.SessionsNotBefore = &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "USER_DEPROVISIONED_SCIM", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: fmt.Sprintf("Deleted by the SCIM client: %s disabled, all sessions revoked, removed from %d SCIM groups", u.Username, left),
		})
		s.noteSCIMChangeLocked(now)
		return nil
	})
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

// SCIMGroupInput is the writable part of a SCIM group.
type SCIMGroupInput struct {
	DisplayName string
	ExternalID  string
	Members     []models.SCIMMember
}

func cloneSCIMGroup(g models.SCIMGroup) models.SCIMGroup {
	g.Members = append([]models.SCIMMember{}, g.Members...)
	return g
}

func (s *Store) SCIMGroups() []models.SCIMGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.SCIMGroup, len(s.state.SCIMGroups))
	for i, g := range s.state.SCIMGroups {
		out[i] = cloneSCIMGroup(g)
	}
	return out
}

func (s *Store) SCIMGroup(id string) (models.SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.state.SCIMGroups {
		if g.ID == id {
			return cloneSCIMGroup(g), true
		}
	}
	return models.SCIMGroup{}, false
}

// normalizeSCIMGroupLocked validates a group and keeps only members that are SCIM-managed accounts
// (local accounts and nested groups are ignored); dropped reports how many references were ignored.
func (s *Store) normalizeSCIMGroupLocked(in *SCIMGroupInput, selfID string) (dropped int, err error) {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" {
		return 0, scimErr(SCIMInvalidValue, "displayName is required")
	}
	for _, f := range []struct{ n, v string }{{"displayName", in.DisplayName}, {"externalId", in.ExternalID}} {
		if len(f.v) > maxSCIMAttrLen || hasCtl(f.v) {
			return 0, scimErr(SCIMInvalidValue, "%s must be at most %d characters without control characters", f.n, maxSCIMAttrLen)
		}
	}
	for _, g := range s.state.SCIMGroups {
		if g.ID != selfID && strings.EqualFold(g.DisplayName, in.DisplayName) {
			return 0, scimErr(SCIMUniqueness, "a group named %q already exists", in.DisplayName)
		}
	}
	managed := map[string]bool{}
	for _, u := range s.state.Users {
		if u.SCIM != nil && !u.SCIM.Deleted {
			managed[u.ID] = true
		}
	}
	seen := map[string]bool{}
	members := make([]models.SCIMMember, 0, len(in.Members))
	for _, m := range in.Members {
		if len(m.Type) > 64 || hasCtl(m.Type) {
			return 0, scimErr(SCIMInvalidValue, "invalid member type")
		}
		if !managed[m.Value] || strings.EqualFold(m.Type, "Group") {
			dropped++
			continue
		}
		if !seen[m.Value] {
			seen[m.Value] = true
			members = append(members, m)
		}
	}
	if len(members) > maxSCIMMembers {
		return 0, scimErr(SCIMTooMany, "at most %d members per group", maxSCIMMembers)
	}
	in.Members = members
	return dropped, nil
}

func memberIDs(ms []models.SCIMMember) map[string]bool {
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		out[m.Value] = true
	}
	return out
}

// resyncMembersLocked re-applies the role mapping to the given accounts.
func (s *Store) resyncMembersLocked(ids map[string]bool, actor string, now time.Time) {
	if len(ids) == 0 {
		return
	}
	mem := s.scimMembershipsLocked()
	for i := range s.state.Users {
		if u := s.state.Users[i]; ids[u.ID] && u.SCIM != nil {
			sc := *u.SCIM
			sc.Version, sc.LastModified = sc.Version+1, now // the "groups" attribute changed
			s.state.Users[i].SCIM = &sc
			s.syncSCIMUserLocked(i, mem, actor, now, false)
		}
	}
}

func (s *Store) SCIMCreateGroup(in SCIMGroupInput, actor string) (models.SCIMGroup, error) {
	var out models.SCIMGroup
	err := s.withWrite(func() error {
		if len(s.state.SCIMGroups) >= maxSCIMGroups {
			return scimErr(SCIMTooMany, "at most %d SCIM groups", maxSCIMGroups)
		}
		dropped, err := s.normalizeSCIMGroupLocked(&in, "")
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		g := models.SCIMGroup{ID: newRandomID("scg"), DisplayName: in.DisplayName, ExternalID: in.ExternalID, Members: in.Members,
			Version: 1, Created: now, LastModified: now}
		s.state.SCIMGroups = append(s.state.SCIMGroups, g)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "GROUP_PROVISIONED_SCIM", Category: "IDENTITY",
			EntityType: "scim_group", EntityID: g.ID, EntityName: g.DisplayName,
			Summary: fmt.Sprintf("Provisioned group %q via SCIM (externalId %q, %d members%s, mapped role %s)", g.DisplayName, g.ExternalID, len(g.Members),
				droppedNote(dropped), firstNonEmpty(string(s.groupRoleLocked(g)), "none")),
		})
		s.resyncMembersLocked(memberIDs(g.Members), actor, now)
		s.noteSCIMChangeLocked(now)
		out = cloneSCIMGroup(g)
		return nil
	})
	return out, err
}

func droppedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; %d references to unknown, local or nested members ignored", n)
}

func (s *Store) groupRoleLocked(g models.SCIMGroup) models.Role {
	r, _ := mapIdPGroups(s.state.EntraConfig, scimGroupKeys(g))
	return r
}

// SCIMUpdateGroup replaces a group (PUT, or PATCH applied by update under the write lock).
func (s *Store) SCIMUpdateGroup(id string, ifMatch int64, update func(cur models.SCIMGroup) (SCIMGroupInput, error), actor string) (models.SCIMGroup, error) {
	var out models.SCIMGroup
	err := s.withWrite(func() error {
		gi := slices.IndexFunc(s.state.SCIMGroups, func(g models.SCIMGroup) bool { return g.ID == id })
		if gi < 0 {
			return scimErr(SCIMNotFound, "group %s not found", id)
		}
		cur := cloneSCIMGroup(s.state.SCIMGroups[gi])
		if ifMatch != 0 && cur.Version != ifMatch {
			return scimErr(SCIMPrecondition, "the group was modified (version %d)", cur.Version)
		}
		in, err := update(cur)
		if err != nil {
			return err
		}
		dropped, err := s.normalizeSCIMGroupLocked(&in, id)
		if err != nil {
			return err
		}
		before, after := memberIDs(cur.Members), memberIDs(in.Members)
		added, removed := 0, 0
		affected := map[string]bool{}
		for m := range after {
			if !before[m] {
				added++
				affected[m] = true
			}
		}
		for m := range before {
			if !after[m] {
				removed++
				affected[m] = true
			}
		}
		renamed := cur.DisplayName != in.DisplayName || cur.ExternalID != in.ExternalID
		if !renamed && added == 0 && removed == 0 && slices.Equal(cur.Members, in.Members) {
			out = cur
			return nil
		}
		if renamed { // the mapping keys changed for everybody
			for m := range after {
				affected[m] = true
			}
			for m := range before {
				affected[m] = true
			}
		}
		now := time.Now().UTC()
		g := &s.state.SCIMGroups[gi]
		g.DisplayName, g.ExternalID, g.Members = in.DisplayName, in.ExternalID, in.Members
		g.Version, g.LastModified = g.Version+1, now
		summary := fmt.Sprintf("Updated group %q via SCIM: +%d/-%d members (%d total%s)", g.DisplayName, added, removed, len(g.Members), droppedNote(dropped))
		if renamed {
			summary += fmt.Sprintf("; renamed from %q (externalId %q -> %q)", cur.DisplayName, cur.ExternalID, in.ExternalID)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "GROUP_UPDATED_SCIM", Category: "IDENTITY",
			EntityType: "scim_group", EntityID: g.ID, EntityName: g.DisplayName, Summary: summary,
		})
		s.resyncMembersLocked(affected, actor, now)
		s.noteSCIMChangeLocked(now)
		out = cloneSCIMGroup(*g)
		return nil
	})
	return out, err
}

func (s *Store) SCIMDeleteGroup(id string, actor string) error {
	return s.withWrite(func() error {
		gi := slices.IndexFunc(s.state.SCIMGroups, func(g models.SCIMGroup) bool { return g.ID == id })
		if gi < 0 {
			return scimErr(SCIMNotFound, "group %s not found", id)
		}
		g := s.state.SCIMGroups[gi]
		s.state.SCIMGroups = slices.Delete(s.state.SCIMGroups, gi, gi+1)
		now := time.Now().UTC()
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: scimActorRole, Action: "GROUP_DELETED_SCIM", Category: "IDENTITY",
			EntityType: "scim_group", EntityID: g.ID, EntityName: g.DisplayName,
			Summary: fmt.Sprintf("Deleted group %q via SCIM (%d members re-evaluated)", g.DisplayName, len(g.Members)),
		})
		s.resyncMembersLocked(memberIDs(g.Members), actor, now)
		s.noteSCIMChangeLocked(now)
		return nil
	})
}
