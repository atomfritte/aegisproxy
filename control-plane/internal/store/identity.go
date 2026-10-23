package store

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/notify"
)

// ErrLocalLoginDisabled is returned for password logins when single sign-on is mandatory.
// ErrLocalLoginDisabled is returned for every failed password sign-in while password login is
// limited to break-glass accounts, so the response reveals neither valid passwords nor account types.
var errSSOUserPassword = errors.New("single sign-on users sign in through the identity provider: they cannot have a password or be break-glass accounts")

var ErrLocalLoginDisabled = errors.New("invalid credentials, or password sign-in is limited to break-glass accounts: use single sign-on")

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	usernameRe            = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
)

// AuthenticateLocal verifies local credentials in constant time with respect to account
// existence and transparently upgrades outdated password hashes.
func (s *Store) AuthenticateLocal(username, password string) (*models.User, error) {
	// Usernames are ASCII; exact matching avoids Unicode case-folding aliases (e.g. "ſ" == "s").
	username = strings.ToLower(strings.TrimSpace(username))
	s.mu.RLock()
	localAllowed := s.state.EntraConfig.AllowLocalLogin || !s.state.EntraConfig.Enabled
	idx := -1
	if usernameRe.MatchString(username) {
		idx = slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.Username == username })
	}
	var u models.User
	if idx >= 0 {
		u = s.state.Users[idx]
	}
	s.mu.RUnlock()
	fail := ErrInvalidCredentials
	if !localAllowed {
		fail = ErrLocalLoginDisabled
	}
	if idx < 0 || u.PasswordHash == "" || u.AuthProvider == "oidc" || password == "" || len(password) > 256 {
		auth.EqualizeTiming(password)
		return nil, fail
	}
	ok, needsRehash := auth.VerifyPassword(password, u.PasswordHash)
	if !ok || u.Disabled || (!localAllowed && !u.BreakGlass) {
		return nil, fail
	}
	if !localAllowed && u.BreakGlass {
		s.alertBreakGlass(u)
	}

	now := time.Now().UTC()
	var newHash string
	if needsRehash {
		newHash = auth.HashPassword(password)
	}
	// Recording the login is best effort: a storage hiccup must not lock operators out.
	if err := s.withWrite(func() error {
		for i := range s.state.Users {
			if s.state.Users[i].ID == u.ID {
				if newHash != "" {
					s.state.Users[i].PasswordHash = newHash
				}
				s.state.Users[i].LastLoginAt = &now
				u = s.state.Users[i]
				break
			}
		}
		s.markDirtyLocked()
		return nil
	}); err != nil {
		s.log.Warn("could not record login timestamp", "user", u.Username, "error", err)
	}
	pub := u.Public()
	return &pub, nil
}

// SessionValidFor reports whether a token issued at issuedAt is still acceptable for the user.
func (s *Store) SessionValidFor(userID string, issuedAt int64) (*models.User, error) {
	u, ok := s.GetUserByID(userID)
	if !ok {
		return nil, fmt.Errorf("user account %s no longer exists", userID)
	}
	if u.Disabled {
		return nil, errors.New("user account is disabled")
	}
	if u.SessionsNotBefore != nil && issuedAt < u.SessionsNotBefore.Unix() {
		return nil, errors.New("session was revoked; please sign in again")
	}
	return u, nil
}

func (s *Store) ChangeOwnPassword(userID, current, next string) error {
	s.mu.RLock()
	idx := slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ID == userID })
	var u models.User
	if idx >= 0 {
		u = s.state.Users[idx]
	}
	s.mu.RUnlock()
	if idx < 0 {
		return errors.New("user not found")
	}
	if ok, _ := auth.VerifyPassword(current, u.PasswordHash); !ok {
		return errors.New("current password is incorrect")
	}
	if err := auth.ValidatePasswordStrength(next, u.Username); err != nil {
		return err
	}
	if current == next {
		return errors.New("new password must differ from the current password")
	}
	hash := auth.HashPassword(next)
	now := time.Now().UTC()
	return s.withWrite(func() error {
		for i := range s.state.Users {
			if s.state.Users[i].ID == userID {
				s.state.Users[i].PasswordHash = hash
				s.state.Users[i].PasswordSetAt = &now
				notBefore := now.Add(-time.Second)
				s.state.Users[i].SessionsNotBefore = &notBefore
				s.appendAuditLocked(models.AuditEvent{
					Actor: u.Username, ActorRole: string(u.Role), Action: "PASSWORD_CHANGED", Category: "IDENTITY",
					EntityType: "user", EntityID: u.ID, EntityName: u.Username,
					Summary: "User changed their own password (other sessions revoked)",
				})
				s.markDirtyLocked()
				return nil
			}
		}
		return errors.New("user not found")
	})
}

// UserInput is the writable subset of a user account.
type UserInput struct {
	ID            string      `json:"id"`
	Username      string      `json:"username"`
	DisplayName   string      `json:"display_name"`
	Email         string      `json:"email"`
	Role          models.Role `json:"role"`
	AllowedGroups []string    `json:"allowed_groups"`
	Department    string      `json:"department"`
	Disabled      bool        `json:"disabled"`
	BreakGlass    bool        `json:"break_glass"`
	Password      string      `json:"password,omitempty"`
}

func (s *Store) UpsertUser(in UserInput, actor *auth.TokenClaims) (models.User, string, error) {
	if !auth.CanManageUsers(actor) {
		return models.User{}, "", errors.New("RBAC Policy: only Super Admins can manage user accounts")
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !usernameRe.MatchString(in.Username) {
		return models.User{}, "", errors.New("username must be 2-64 characters: lowercase letters, digits, '.', '_' or '-'")
	}
	// SCIM-provisioned accounts without a mapped group have no role; they can still be edited (for
	// example locked by an administrator) as long as the role stays empty.
	if !in.Role.Valid() && (in.Role != "" || in.ID == "") {
		return models.User{}, "", errors.New("invalid role")
	}
	if err := checkText("display_name", in.DisplayName, 120, true); err != nil {
		return models.User{}, "", err
	}
	if err := checkText("department", in.Department, 120, false); err != nil {
		return models.User{}, "", err
	}
	if in.Email != "" {
		if _, err := mail.ParseAddress(in.Email); err != nil || len(in.Email) > 254 {
			return models.User{}, "", errors.New("invalid email address")
		}
	}
	if in.AllowedGroups == nil {
		in.AllowedGroups = []string{}
	}
	if in.BreakGlass && in.Role != models.RoleSuperAdmin {
		return models.User{}, "", errors.New("break-glass accounts must be Super Admins")
	}
	var generated string
	if in.Password != "" {
		if err := auth.ValidatePasswordStrength(in.Password, in.Username); err != nil {
			return models.User{}, "", err
		}
	}

	var out models.User
	err := s.withWrite(func() error {
		if err := s.validateScopeLocked(in.AllowedGroups, nil); err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, u := range s.state.Users {
			if strings.EqualFold(u.Username, in.Username) && u.ID != in.ID {
				return fmt.Errorf("username %q already exists", in.Username)
			}
		}

		if in.ID == "" {
			pw := in.Password
			if pw == "" {
				generated = auth.GeneratePassword()
				pw = generated
			}
			u := models.User{
				ID: newRandomID("usr"), Username: in.Username, DisplayName: in.DisplayName, Email: in.Email,
				Role: in.Role, AuthProvider: "local", AllowedGroups: in.AllowedGroups, Department: in.Department,
				Disabled: in.Disabled, DisabledByAdmin: in.Disabled, BreakGlass: in.BreakGlass, CreatedAt: now, PasswordHash: auth.HashPassword(pw), PasswordSetAt: &now,
			}
			s.state.Users = append(s.state.Users, u)
			s.appendAuditLocked(models.AuditEvent{
				Actor: actor.Username, ActorRole: string(actor.Role), Action: "USER_CREATED", Category: "IDENTITY",
				EntityType: "user", EntityID: u.ID, EntityName: u.Username,
				Summary: fmt.Sprintf("Created user %s with role %s (groups %v)", u.Username, u.Role, u.AllowedGroups),
			})
			s.saveLocked()
			out = u.Public()
			return nil
		}

		i := slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ID == in.ID })
		if i == -1 {
			return errors.New("user not found")
		}
		u := &s.state.Users[i]
		if in.Role == "" && (u.AuthProvider != "oidc" || u.Role != "") {
			return errors.New("invalid role")
		}
		before := fmt.Sprintf("role=%s groups=%v disabled=%v", u.Role, u.AllowedGroups, u.Disabled)
		if u.ID == actor.UserID && (in.Role != models.RoleSuperAdmin || in.Disabled) {
			return errors.New("you cannot demote or disable your own account")
		}
		if u.Role == models.RoleSuperAdmin && (in.Role != models.RoleSuperAdmin || in.Disabled) && s.countActiveSuperAdminsLocked() <= 1 {
			return errors.New("cannot demote or disable the last active Super Admin")
		}
		privChange := u.Role != in.Role || u.Disabled != in.Disabled || !slices.Equal(u.AllowedGroups, in.AllowedGroups)
		u.Username, u.DisplayName, u.Email, u.Role = in.Username, in.DisplayName, in.Email, in.Role
		if u.BreakGlass && !in.BreakGlass && !s.state.EntraConfig.AllowLocalLogin && s.state.EntraConfig.Enabled {
			others := 0
			for _, o := range s.state.Users {
				if o.ID != u.ID && o.BreakGlass && !o.Disabled && o.PasswordHash != "" {
					others++
				}
			}
			if others == 0 {
				return errors.New("this is the last break-glass account while password login is disabled")
			}
		}
		if u.AuthProvider == "oidc" && (in.Role != u.Role || !slices.Equal(in.AllowedGroups, u.AllowedGroups)) {
			return errors.New("roles of single sign-on users are managed through IdP group mappings")
		}
		if u.AuthProvider == "oidc" && (in.Password != "" || in.BreakGlass) {
			// A local password would let the account bypass the IdP (MFA, conditional access, offboarding).
			return errSSOUserPassword
		}
		if in.Disabled && !u.Disabled {
			u.DisabledByAdmin = true
		}
		if !in.Disabled {
			u.DisabledByAdmin = false
		}
		u.AllowedGroups, u.Department, u.Disabled, u.BreakGlass = in.AllowedGroups, in.Department, in.Disabled, in.BreakGlass
		if in.Password != "" {
			u.PasswordHash = auth.HashPassword(in.Password)
			u.PasswordSetAt = &now
			privChange = true
		}
		if privChange {
			u.SessionsNotBefore = &now
		}
		if u.SCIM != nil && s.state.SCIM.Enabled {
			// An administrator can lock a SCIM-managed account, but not enable one the IdP deactivated.
			s.syncSCIMUserLocked(i, s.scimMembershipsLocked(), actor.Username, now, true)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "USER_UPDATED", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary:     fmt.Sprintf("Updated user %s", u.Username),
			BeforeState: before,
			AfterState:  fmt.Sprintf("role=%s groups=%v disabled=%v", u.Role, u.AllowedGroups, u.Disabled),
		})
		s.saveLocked()
		out = u.Public()
		return nil
	})
	if err != nil {
		return models.User{}, "", err
	}
	return out, generated, nil
}

func (s *Store) countActiveSuperAdminsLocked() int {
	n := 0
	for _, u := range s.state.Users {
		if u.Role == models.RoleSuperAdmin && !u.Disabled && u.PasswordHash != "" {
			n++
		}
	}
	return n
}

func (s *Store) DeleteUser(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageUsers(actor) {
		return errors.New("RBAC Policy: only Super Admins can manage user accounts")
	}
	if id == actor.UserID {
		return errors.New("you cannot delete your own account")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ID == id })
		if i == -1 {
			return errors.New("user not found")
		}
		u := s.state.Users[i]
		if u.Role == models.RoleSuperAdmin && s.countActiveSuperAdminsLocked() <= 1 {
			return errors.New("cannot delete the last active Super Admin")
		}
		s.state.Users = slices.Delete(s.state.Users, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "USER_DELETED", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: fmt.Sprintf("Deleted user %s (%s)", u.Username, u.Role),
		})
		s.saveLocked()
		return nil
	})
}

// ResetUserPassword sets a random temporary password and revokes the user's sessions.
func (s *Store) ResetUserPassword(id string, actor *auth.TokenClaims) (string, error) {
	if !auth.CanManageUsers(actor) {
		return "", errors.New("RBAC Policy: only Super Admins can reset passwords")
	}
	pw := auth.GeneratePassword()
	hash := auth.HashPassword(pw)
	now := time.Now().UTC()
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Users, func(u models.User) bool { return u.ID == id })
		if i == -1 {
			return errors.New("user not found")
		}
		u := &s.state.Users[i]
		if u.AuthProvider == "oidc" {
			return errSSOUserPassword
		}
		u.PasswordHash, u.PasswordSetAt, u.SessionsNotBefore = hash, &now, &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PASSWORD_RESET", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: fmt.Sprintf("Reset password for %s and revoked all sessions", u.Username),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return "", err
	}
	return pw, nil
}

// ---------------------------------------------------------------------------
// Authentication & notification settings
// ---------------------------------------------------------------------------

func (s *Store) UpdateNotificationConfig(cfg models.NotificationConfig, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return fmt.Errorf("RBAC Policy: Insufficient permissions")
	}
	s.mu.RLock()
	cur := s.state.NotifyConfig
	s.mu.RUnlock()
	// Masked values (as returned by the API) keep the stored webhook URLs.
	if strings.Contains(string(cfg.TeamsWebhookURL), models.MaskedSecretMarker) {
		cfg.TeamsWebhookURL = cur.TeamsWebhookURL
	}
	if strings.Contains(string(cfg.SlackWebhookURL), models.MaskedSecretMarker) {
		cfg.SlackWebhookURL = cur.SlackWebhookURL
	}
	if err := notify.ValidateWebhookURL(string(cfg.TeamsWebhookURL)); err != nil {
		return fmt.Errorf("Teams Webhook rejected: %w", err)
	}
	if err := notify.ValidateWebhookURL(string(cfg.SlackWebhookURL)); err != nil {
		return fmt.Errorf("Slack Webhook rejected: %w", err)
	}
	if err := checkText("teams_channel", cfg.TeamsChannel, 200, false); err != nil {
		return err
	}
	if err := checkText("slack_channel", cfg.SlackChannel, 200, false); err != nil {
		return err
	}
	if cfg.DashboardBaseURL != "" && !strings.HasPrefix(cfg.DashboardBaseURL, "https://") && !strings.HasPrefix(cfg.DashboardBaseURL, "http://") {
		return errors.New("dashboard_base_url must be an http(s) URL")
	}
	err := s.withWrite(func() error {
		s.state.NotifyConfig = cfg
		s.appendAuditLocked(models.AuditEvent{
			Actor:      actor.Username,
			ActorRole:  string(actor.Role),
			Action:     "WEBHOOK_CONFIG_UPDATED",
			Category:   "SYSTEM",
			EntityType: "notify_config",
			EntityID:   "webhooks",
			EntityName: "MS Teams & Slack Alert Channels",
			Summary:    fmt.Sprintf("Updated webhook channels (Teams=%v, Slack=%v, security events=%v)", cfg.TeamsEnabled, cfg.SlackEnabled, cfg.NotifySecurityEvents),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return err
	}
	if s.notifier != nil {
		s.notifier.UpdateConfig(cfg)
	}
	return nil
}

// alertBreakGlass audits and announces an emergency password login while SSO is mandatory.
func (s *Store) alertBreakGlass(u models.User) {
	_ = s.withWrite(func() error {
		s.appendAuditLocked(models.AuditEvent{
			Actor: u.Username, ActorRole: string(u.Role), Action: "BREAK_GLASS_LOGIN", Category: "IDENTITY",
			EntityType: "user", EntityID: u.ID, EntityName: u.Username,
			Summary: "Emergency (break-glass) password login while single sign-on is mandatory",
		})
		s.markDirtyLocked()
		return nil
	})
	if s.notifier != nil {
		s.notifier.NotifySecurityEvent(models.SecurityEvent{Timestamp: time.Now().UTC(), Type: "BREAK_GLASS_LOGIN", Severity: "high",
			Action: "detected", Detail: fmt.Sprintf("Break-glass account %s signed in with a password", u.Username), Count: 1})
	}
}
