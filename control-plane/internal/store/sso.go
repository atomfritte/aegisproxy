package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc"
)

var (
	claimNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	tenantRe    = regexp.MustCompile(`^[A-Za-z0-9.-]{3,128}$`)
	guidRe      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// rolePriority orders roles for mapping (highest privilege wins).
var rolePriority = map[models.Role]int{models.RoleSuperAdmin: 4, models.RoleInfoSecApprover: 3, models.RoleTeamLead: 2, models.RoleAuditorOperator: 1}

// SSOSettings returns the effective (normalized) SSO configuration including the client secret.
func (s *Store) SSOSettings(publicURL string) models.EntraIDConfig {
	s.mu.RLock()
	cfg := s.state.EntraConfig
	s.mu.RUnlock()
	return normalizeSSO(cfg, publicURL)
}

func normalizeSSO(cfg models.EntraIDConfig, publicURL string) models.EntraIDConfig {
	if cfg.Provider == "" {
		cfg.Provider = "entra"
	}
	if cfg.Provider == "entra" && cfg.TenantID != "" && cfg.IssuerURL == "" {
		cfg.IssuerURL = "https://login.microsoftonline.com/" + cfg.TenantID + "/v2.0"
	}
	if cfg.RedirectURI == "" && publicURL != "" {
		cfg.RedirectURI = strings.TrimRight(publicURL, "/") + "/api/auth/sso/callback"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.DisplayName == "" {
		if cfg.Provider == "entra" {
			cfg.DisplayName = "Microsoft Entra ID"
		} else {
			cfg.DisplayName = "Single sign-on"
		}
	}
	return cfg
}

func (s *Store) breakGlassAvailableLocked() bool {
	for _, u := range s.state.Users {
		if u.BreakGlass && !u.Disabled && u.PasswordHash != "" && u.Role == models.RoleSuperAdmin {
			return true
		}
	}
	return false
}

// UpdateEntraConfig stores the SSO configuration. Only Super Admins may change it: whoever controls
// the identity provider mapping controls who becomes administrator.
func (s *Store) UpdateEntraConfig(cfg models.EntraIDConfig, actor *auth.TokenClaims) error {
	if !auth.CanManageUsers(actor) || actor.ServiceAccount {
		return errors.New("RBAC Policy: only Super Admins can configure single sign-on")
	}
	if cfg.Provider == "" {
		cfg.Provider = "entra"
	}
	if cfg.Provider != "entra" && cfg.Provider != "oidc" {
		return errors.New("provider must be entra or oidc")
	}
	for _, f := range []struct{ n, v string }{{"client_id", cfg.ClientID}, {"issuer_url", cfg.IssuerURL}, {"redirect_uri", cfg.RedirectURI}, {"display_name", cfg.DisplayName}} {
		if err := checkText(f.n, f.v, 512, false); err != nil {
			return err
		}
	}
	if cfg.TenantID != "" && !guidRe.MatchString(cfg.TenantID) {
		// A domain name would work for discovery, but Entra issues tokens for the GUID issuer.
		return errors.New("tenant_id must be the Directory (tenant) ID, a GUID such as 72f988bf-86f1-41af-91ab-2d7cd011db47")
	}
	switch cfg.TokenAuthMethod {
	case "", "client_secret_post", "client_secret_basic", oidc.TokenAuthPrivateKeyJWT:
	default:
		return errors.New("token_auth_method must be empty (auto), client_secret_post, client_secret_basic or private_key_jwt")
	}
	if cfg.IssuerURL != "" {
		if err := oidc.ValidateIssuer(cfg.IssuerURL); err != nil {
			return fmt.Errorf("issuer_url: %w", err)
		}
	}
	if cfg.RedirectURI != "" {
		u, err := url.Parse(cfg.RedirectURI)
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && oidc.IsLoopback(cfg.RedirectURI))) || !strings.HasSuffix(u.Path, "/api/auth/sso/callback") {
			return errors.New("redirect_uri must be https://<control-plane>/api/auth/sso/callback")
		}
	}
	for _, c := range []string{cfg.UsernameClaim, cfg.GroupsClaim} {
		if c != "" && !claimNameRe.MatchString(c) {
			return fmt.Errorf("invalid claim name %q", c)
		}
	}
	if len(cfg.Scopes) > 20 {
		return errors.New("at most 20 scopes")
	}
	for _, sc := range cfg.Scopes {
		if !claimNameRe.MatchString(sc) {
			return fmt.Errorf("invalid scope %q", sc)
		}
	}
	if len(cfg.GroupRoleMap) > 200 || len(cfg.GroupScopeMap) > 200 {
		return errors.New("too many group mappings")
	}
	for g, r := range cfg.GroupRoleMap {
		if !r.Valid() || !validMappingKey(g) {
			return fmt.Errorf("invalid group role mapping %q -> %q", g, r)
		}
	}
	if strings.ContainsAny(string(cfg.ClientSecret), "\r\n") || len(cfg.ClientSecret) > 1024 {
		return errors.New("invalid client secret")
	}
	return s.withWrite(func() error {
		cur := s.state.EntraConfig
		if cfg.ClientSecret == "" || strings.Contains(string(cfg.ClientSecret), models.MaskedSecretMarker) {
			// The stored secret belongs to one client at one IdP: it never follows a changed issuer or
			// client ID to a new token endpoint.
			newIssuer := normalizeSSO(cfg, "").IssuerURL
			if cur.ClientSecret != "" && (newIssuer != normalizeSSO(cur, "").IssuerURL || cfg.ClientID != cur.ClientID) {
				// Without an issuer or client the secret has nowhere to go: dropping it is the clean-up case.
				if cfg.TokenAuthMethod != oidc.TokenAuthPrivateKeyJWT && newIssuer != "" && cfg.ClientID != "" {
					return errors.New("the issuer or client ID changed: re-enter the client secret for the new identity provider")
				}
				cfg.ClientSecret = ""
			} else {
				cfg.ClientSecret = cur.ClientSecret
			}
		}
		cfg.HasClientSecret = false
		for g, groups := range cfg.GroupScopeMap {
			if !validMappingKey(g) {
				return fmt.Errorf("invalid group scope mapping %q", g)
			}
			if err := s.validateScopeLocked(groups, nil); err != nil {
				return fmt.Errorf("group scope mapping %q: %w", g, err)
			}
		}
		if cfg.Enabled {
			eff := normalizeSSO(cfg, "")
			if cfg.ClientID == "" || eff.IssuerURL == "" {
				return errors.New("enabling single sign-on requires a client ID and the tenant ID (Entra) or issuer URL")
			}
			if len(cfg.GroupRoleMap) == 0 {
				return errors.New("map at least one IdP group to a role; users without a mapped group cannot sign in")
			}
			if cfg.TokenAuthMethod == oidc.TokenAuthPrivateKeyJWT {
				i := slices.IndexFunc(s.state.SSOClientKeys, func(k models.SSOClientKey) bool { return k.Status == models.ClientKeyActive && k.PrivateKey != "" })
				if i < 0 {
					return errors.New("private_key_jwt needs an active client key: generate one and register its certificate or JWKS URL in the IdP first")
				}
				if cfg.Provider == "entra" && s.state.SSOClientKeys[i].Alg != oidc.AlgRS256 {
					// Entra ID accepts only RSA certificate credentials for client assertions.
					return errors.New("Microsoft Entra ID accepts only RSA certificates: activate an RS256 client key")
				}
			}
		}
		if !cfg.AllowLocalLogin && (!cfg.Enabled || !s.breakGlassAvailableLocked()) {
			return errors.New("password login can only be disabled when single sign-on is enabled and at least one active break-glass Super Admin with a password exists")
		}
		s.state.EntraConfig = cfg
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "AUTH_CONFIG_UPDATED", Category: "IDENTITY",
			EntityType: "sso_config", EntityID: cfg.Provider, EntityName: "Single sign-on (" + cfg.Provider + ")",
			Summary: fmt.Sprintf("Updated single sign-on (enabled=%v, provider=%s, issuer=%s, client=%s, client auth=%s, %d role mappings, local login=%v)",
				cfg.Enabled, cfg.Provider, normalizeSSO(cfg, "").IssuerURL, cfg.ClientID, firstNonEmpty(cfg.TokenAuthMethod, "auto"), len(cfg.GroupRoleMap), cfg.AllowLocalLogin),
		})
		// SCIM-managed accounts have no sign-in that would re-apply a changed mapping: apply it now.
		s.syncAllSCIMUsersLocked("system", time.Now().UTC())
		s.saveLocked()
		return nil
	})
}

// SSOIdentity is what the callback extracted from a validated ID token.
type SSOIdentity struct {
	Issuer  string
	Subject string
	// LoginName is the raw username claim (preferred_username / upn). It never links an account (users can
	// choose or change it in some IdPs); an unlinked SCIM account with this userName refuses the sign-in.
	LoginName   string
	Username    string
	Email       string
	DisplayName string
	Groups      []string
}

// Group mapping keys. A group_role_map / group_scope_map key matches an immutable group identifier
// (a value of the ID token's groups claim, a SCIM group's externalId) unless it carries the prefix
// "name:", which also matches a SCIM group's displayName. Group owners can rename their groups in
// some IdPs (Entra ID), so a display name never matches an unprefixed key such as an object ID;
// "id:" is the explicit form of the default.
const (
	groupKeyID   = "id:"
	groupKeyName = "name:"
)

// mappingKey is the membership key that a group_role_map / group_scope_map key matches.
func mappingKey(k string) string {
	if strings.HasPrefix(k, groupKeyID) || strings.HasPrefix(k, groupKeyName) {
		return k
	}
	return groupKeyID + k
}

func validMappingKey(k string) bool {
	v := strings.TrimPrefix(strings.TrimPrefix(mappingKey(k), groupKeyID), groupKeyName)
	return v != "" && len(k) <= 256 && !hasCtl(k)
}

// claimGroupKeys are the membership keys of an ID token's groups claim. Claim values are what the
// IdP was configured to send (object IDs, app role values or names), so they match both forms.
func claimGroupKeys(groups []string) []string {
	out := make([]string, 0, 2*len(groups))
	for _, g := range groups {
		out = append(out, groupKeyID+g, groupKeyName+g)
	}
	return out
}

// scimGroupKeys are the membership keys of a SCIM group: its externalId as identifier, its
// displayName only for "name:" mappings.
func scimGroupKeys(g models.SCIMGroup) []string {
	keys := []string{groupKeyName + g.DisplayName}
	if g.ExternalID != "" {
		keys = append(keys, groupKeyID+g.ExternalID)
	}
	return keys
}

// migrateGroupMappingKeysLocked runs once when a pre-2.1 state is loaded: unprefixed mapping keys
// that matched a SCIM group only by its display name become explicit "name:" keys, so name-based
// mappings (Okta pushes groups without an externalId) keep working. Keys shaped like object IDs are
// never converted: they were meant as identifiers, and matching them against display names let a
// group owner take over a mapped role by renaming the group.
func (s *Store) migrateGroupMappingKeysLocked() {
	if s.state.GroupMapKeysTyped {
		return
	}
	s.state.GroupMapKeysTyped = true
	names, ids := map[string]bool{}, map[string]bool{}
	for _, g := range s.state.SCIMGroups {
		names[g.DisplayName] = true
		if g.ExternalID != "" {
			ids[g.ExternalID] = true
		}
	}
	byName := func(k string) bool {
		return mappingKey(k) == groupKeyID+k && names[k] && !ids[k] && !guidRe.MatchString(k)
	}
	var converted []string
	cfg := &s.state.EntraConfig
	for k, r := range cfg.GroupRoleMap {
		if byName(k) {
			delete(cfg.GroupRoleMap, k)
			cfg.GroupRoleMap[groupKeyName+k] = r
			converted = append(converted, k)
		}
	}
	for k, sgs := range cfg.GroupScopeMap {
		if byName(k) {
			delete(cfg.GroupScopeMap, k)
			cfg.GroupScopeMap[groupKeyName+k] = sgs
			if !slices.Contains(converted, k) {
				converted = append(converted, k)
			}
		}
	}
	if len(converted) == 0 {
		return
	}
	slices.Sort(converted)
	s.log.Warn("group mappings now match SCIM display names explicitly (name:); group owners may be able to rename groups in the IdP — prefer group object IDs", "keys", converted)
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "SSO_GROUP_MAPPING_MIGRATED", Category: "IDENTITY",
		EntityType: "sso_config", EntityID: firstNonEmpty(cfg.Provider, "entra"), EntityName: "Single sign-on group mapping",
		Summary: fmt.Sprintf("Group mappings %s matched SCIM groups by display name and were converted to explicit name: mappings; display names can be changed in the IdP, prefer group object IDs", strings.Join(converted, ", ")),
	})
}

// mapIdPGroups applies group_role_map and group_scope_map to membership keys (claimGroupKeys,
// scimGroupKeys): the most privileged role wins, Team Leads get the union of the mapped server groups.
func mapIdPGroups(cfg models.EntraIDConfig, memberKeys []string) (models.Role, []string) {
	var role models.Role
	allowed := map[string]bool{}
	have := make(map[string]bool, len(memberKeys))
	for _, k := range memberKeys {
		have[k] = true
	}
	for k, r := range cfg.GroupRoleMap {
		if have[mappingKey(k)] && rolePriority[r] > rolePriority[role] {
			role = r
		}
	}
	for k, sgs := range cfg.GroupScopeMap {
		if have[mappingKey(k)] {
			for _, sg := range sgs {
				allowed[sg] = true
			}
		}
	}
	groups := slices.Sorted(maps.Keys(allowed))
	switch role {
	case models.RoleSuperAdmin, models.RoleInfoSecApprover:
		groups = []string{"*"}
	case models.RoleAuditorOperator, "":
		groups = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return role, groups
}

// scimLinkCandidateLocked finds the account SCIM provisioned for a person whose subject is not linked
// to any account: SCIM externalId = token subject (Entra: objectId = oid, Okta: user id = sub), compared
// exactly — OIDC subjects are case-sensitive, and case or Unicode folding (U+212A KELVIN SIGN folds to
// "k") would let a different subject link. Only this immutable identifier links. Usernames and e-mail
// addresses never do: users can choose or change them in some IdPs (OIDC Core: preferred_username is
// neither unique nor stable), so whoever obtains a token with a provisioned userName would take over
// that account. Records the SCIM client deleted never link (the subject is refused as deprovisioned).
// A candidate still linked to another subject (a link left by an earlier version, or one made through
// a previous issuer) is linked anew: SCIM, which is authoritative, says it belongs to this subject.
// refused explains why the sign-in is refused instead: several accounts carry the subject, or an
// unlinked SCIM account has the username claim as userName — a second account next to it would hide a
// wrong externalId mapping in the IdP (case-insensitive: this only refuses, it never links).
func (s *Store) scimLinkCandidateLocked(id SSOIdentity) (index int, refused string) {
	found := -1
	if id.Subject != "" {
		for i, u := range s.state.Users {
			if u.SCIM == nil || u.SCIM.Deleted || u.AuthProvider != "oidc" || u.SCIM.ExternalID == "" || u.SCIM.ExternalID != id.Subject {
				continue
			}
			if found >= 0 {
				return -1, "several SCIM-provisioned accounts carry the token subject as externalId (accounts are linked by a unique immutable user ID only)"
			}
			found = i
		}
	}
	if found >= 0 {
		return found, ""
	}
	if id.LoginName != "" && slices.ContainsFunc(s.state.Users, func(u models.User) bool {
		return u.SCIM != nil && u.ExternalID == "" && u.AuthProvider == "oidc" && !u.SCIM.Deleted && strings.EqualFold(u.SCIM.UserName, id.LoginName)
	}) {
		return -1, "a SCIM-provisioned account has this userName but its externalId does not match the token subject " +
			"(accounts are linked by the immutable user ID only; map the SCIM externalId to it)"
	}
	return -1, ""
}

// staleSCIMLink reports why the account linked to the subject of id must not be used: SCIM is
// authoritative for the immutable user ID of the accounts it manages, so a SCIM-managed account with an
// externalId accepts only a token subject exactly equal to it. Links of other subjects are left by
// earlier builds, which revived deleted records by userName and kept their link when the externalId
// changed (both now remove it, see unlinkSSOLocked); the owner's next sign-in replaces them
// (scimLinkCandidateLocked).
func staleSCIMLink(u models.User, id SSOIdentity) string {
	if u.SCIM == nil || u.SCIM.ExternalID == "" || u.SCIM.ExternalID == id.Subject {
		return ""
	}
	return fmt.Sprintf("the account %s is linked to this subject, but its SCIM externalId is a different immutable user ID "+
		"(stale link; the sign-in of the subject equal to the externalId replaces it)", u.Username)
}

// ErrSSONotAuthorized is returned when none of the user's IdP groups is mapped to a role.
var (
	ErrSSONotAuthorized = errors.New("your account is not assigned to an AegisProxy role")
	ErrSSOUserDisabled  = errors.New("your account was disabled by an administrator")
	ErrSSOLinkConflict  = errors.New("an account provisioned for you exists, but its SCIM externalId (your immutable user ID) does not match your sign-in")
)

// ProvisionSSOUser maps IdP groups to a role and creates or updates the local user record.
func (s *Store) ProvisionSSOUser(id SSOIdentity) (*models.User, error) {
	var out models.User
	denied, disabled, conflict := false, false, false
	err := s.withWrite(func() error {
		cfg := s.state.EntraConfig
		if !cfg.Enabled {
			return errors.New("single sign-on is disabled")
		}
		ext := externalID(id.Issuer, id.Subject)
		i := slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ExternalID == ext })
		refused, entityID, entityName := "", ext, id.Username
		linkedAt := time.Now().UTC()
		if i >= 0 {
			if refused = staleSCIMLink(s.state.Users[i], id); refused != "" {
				// Sessions obtained through the stale link end now; the link stays until the owner replaces it.
				u := &s.state.Users[i]
				entityID, entityName, u.SessionsNotBefore = u.ID, u.Username, &linkedAt
			}
		} else if i, refused = s.scimLinkCandidateLocked(id); i >= 0 {
			u := &s.state.Users[i]
			summary := fmt.Sprintf("First single sign-on of %s linked to the SCIM-provisioned account (userName %s, externalId = token subject)", u.Username, u.SCIM.UserName)
			if u.ExternalID != "" {
				summary = fmt.Sprintf("Single sign-on of %s linked to the SCIM-provisioned account (userName %s, externalId = token subject); "+
					"it replaces a link to another subject, whose sessions are revoked", u.Username, u.SCIM.UserName)
				u.SessionsNotBefore = &linkedAt
			}
			s.appendAuditLocked(models.AuditEvent{
				Actor: "system", ActorRole: "SSO", Action: "USER_LINKED_SSO", Category: "IDENTITY",
				EntityType: "user", EntityID: u.ID, EntityName: u.Username, Summary: summary,
				BeforeState: "sso_link=" + u.ExternalID, AfterState: "sso_link=" + ext,
			})
			u.ExternalID = ext
			s.markDirtyLocked()
		} else if refused == "" && id.Subject != "" {
			// A subject the SCIM client deleted is refused as deprovisioned (below), without linking the record:
			// it no longer belongs to anybody, and only the same externalId revives it.
			i = slices.IndexFunc(s.state.Users, func(u models.User) bool {
				return u.SCIM != nil && u.SCIM.Deleted && u.SCIM.ExternalID == id.Subject
			})
		}
		if refused != "" {
			s.appendAuditLocked(models.AuditEvent{
				Actor: id.Username, ActorRole: "SSO", Action: "LOGIN_SSO_DENIED", Category: "IDENTITY",
				EntityType: "user", EntityID: entityID, EntityName: entityName,
				Summary: fmt.Sprintf("Single sign-on denied for %s: %s", id.Username, refused),
			})
			s.markDirtyLocked()
			conflict = true
			return nil
		}
		// SCIM is authoritative for the accounts it manages: their role comes from the SCIM group
		// memberships, not from the groups claim of the ID token.
		scimManaged := i >= 0 && s.state.Users[i].SCIM != nil && s.state.SCIM.Enabled
		roleGroups := claimGroupKeys(id.Groups)
		if scimManaged {
			roleGroups = s.scimMembershipsLocked()[s.state.Users[i].ID]
		}
		role, groups := mapIdPGroups(cfg, roleGroups)
		if i >= 0 && s.state.Users[i].SCIM != nil && !s.state.Users[i].SCIM.IsActive() {
			u := s.state.Users[i]
			s.appendAuditLocked(models.AuditEvent{
				Actor: u.Username, ActorRole: "SSO", Action: "LOGIN_SSO_DENIED", Category: "IDENTITY",
				EntityType: "user", EntityID: u.ID, EntityName: u.Username,
				Summary: fmt.Sprintf("Single sign-on denied for %s: the account was deprovisioned by SCIM", u.Username),
			})
			s.markDirtyLocked()
			disabled = true
			return nil
		}
		if role == "" {
			s.appendAuditLocked(models.AuditEvent{
				Actor: id.Username, ActorRole: "SSO", Action: "LOGIN_SSO_DENIED", Category: "IDENTITY",
				EntityType: "user", EntityID: ext, EntityName: id.Username,
				Summary: fmt.Sprintf("Single sign-on denied for %s: none of %d IdP groups is mapped to a role", id.Username, len(id.Groups)),
			})
			if i >= 0 && !s.state.Users[i].Disabled {
				// Group membership was removed in the IdP: revoke console access immediately.
				now := time.Now().UTC()
				s.state.Users[i].Disabled, s.state.Users[i].SessionsNotBefore = true, &now
				s.appendAuditLocked(models.AuditEvent{
					Actor: "system", ActorRole: "SYSTEM", Action: "USER_DEPROVISIONED_SSO", Category: "IDENTITY",
					EntityType: "user", EntityID: s.state.Users[i].ID, EntityName: s.state.Users[i].Username,
					Summary: fmt.Sprintf("Disabled %s and revoked all sessions: the IdP no longer reports a mapped group", s.state.Users[i].Username),
				})
			}
			s.markDirtyLocked()
			denied = true // committed (audit + revocation), then reported
			return nil
		}
		username := strings.ToLower(id.Username)
		if !usernameRe.MatchString(username) {
			username = "sso-" + ext[:12]
		}
		now := time.Now().UTC()
		if i < 0 {
			for _, u := range s.state.Users {
				if strings.EqualFold(u.Username, username) {
					username = username + "-" + ext[:6] // never take over a local account by name
					break
				}
			}
			u := models.User{ID: newRandomID("usr"), Username: username, DisplayName: clip(id.DisplayName, 120), Email: clip(id.Email, 254),
				Role: role, AuthProvider: "oidc", AllowedGroups: groups, ExternalID: ext, CreatedAt: now, LastLoginAt: &now}
			if u.DisplayName == "" {
				u.DisplayName = username
			}
			s.state.Users = append(s.state.Users, u)
			s.appendAuditLocked(models.AuditEvent{
				Actor: username, ActorRole: string(role), Action: "USER_PROVISIONED_SSO", Category: "IDENTITY",
				EntityType: "user", EntityID: u.ID, EntityName: username,
				Summary: fmt.Sprintf("Provisioned %s via single sign-on with role %s (groups %v)", username, role, groups),
			})
			out = u.Public()
		} else {
			u := &s.state.Users[i]
			if u.Disabled && (u.AuthProvider != "oidc" || u.DisabledByAdmin) {
				s.appendAuditLocked(models.AuditEvent{
					Actor: u.Username, ActorRole: "SSO", Action: "LOGIN_SSO_DENIED", Category: "IDENTITY",
					EntityType: "user", EntityID: u.ID, EntityName: u.Username,
					Summary: fmt.Sprintf("Single sign-on denied for %s: the account is disabled by an administrator", u.Username),
				})
				s.markDirtyLocked()
				disabled = true
				return nil
			}
			if u.Role != role || !slices.Equal(u.AllowedGroups, groups) || u.Disabled {
				s.appendAuditLocked(models.AuditEvent{
					Actor: "system", ActorRole: "SSO", Action: "USER_ROLE_SYNCED", Category: "IDENTITY",
					EntityType: "user", EntityID: u.ID, EntityName: u.Username,
					Summary:     fmt.Sprintf("Role of %s synchronized from IdP groups: %s %v -> %s %v", u.Username, u.Role, u.AllowedGroups, role, groups),
					BeforeState: fmt.Sprintf("role=%s groups=%v disabled=%v", u.Role, u.AllowedGroups, u.Disabled),
				})
				u.SessionsNotBefore = &now
			}
			u.Role, u.AllowedGroups, u.Disabled, u.LastLoginAt = role, groups, false, &now
			if id.DisplayName != "" && !scimManaged {
				u.DisplayName = clip(id.DisplayName, 120)
			}
			if id.Email != "" && !scimManaged {
				u.Email = clip(id.Email, 254)
			}
			out = u.Public()
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: out.Username, ActorRole: string(out.Role), Action: "LOGIN_SSO", Category: "IDENTITY",
			EntityType: "user", EntityID: out.ID, EntityName: out.Username,
			Summary: fmt.Sprintf("Signed in via single sign-on (%s) as %s", cfg.Provider, out.Role),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, ErrSSOLinkConflict
	}
	if denied {
		return nil, ErrSSONotAuthorized
	}
	if disabled {
		return nil, ErrSSOUserDisabled
	}
	return &out, nil
}

func externalID(issuer, subject string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(issuer, "/") + "|" + subject))
	return hex.EncodeToString(sum[:16])
}

// ValidEntraTenantID reports whether s is an Entra directory (tenant) ID.
func ValidEntraTenantID(s string) bool { return guidRe.MatchString(s) }
