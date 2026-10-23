package auth

import (
	"errors"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"strings"

	"aegisproxy/control-plane/internal/models"
)

// AuthProvider defines the modular authentication contract.
// Currently active: local username/password (store.AuthenticateLocal).
// Prepared for future activation: EntraIDProvider (OIDC / OAuth2).
type AuthProvider interface {
	ProviderID() string
	Authenticate(identifier, secret string) (*models.User, error)
}

// CanApproveForGroups checks RBAC rules for whether a user can approve requests or rules for target server groups.
func CanApproveForGroups(claims *TokenClaims, targetGroups []string) bool {
	if claims == nil {
		return false
	}
	switch claims.Role {
	case models.RoleSuperAdmin, models.RoleInfoSecApprover:
		return true
	case models.RoleTeamLead:
		if len(targetGroups) == 0 {
			return false
		}
		allowedSet := make(map[string]bool, len(claims.AllowedGroups))
		for _, g := range claims.AllowedGroups {
			allowedSet[g] = true
		}
		if allowedSet["*"] {
			return true
		}
		for _, tg := range targetGroups {
			if tg == "*" || !allowedSet[tg] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// CanModifyRule enforces that TEAM_LEAD_APPROVER cannot create, alter, delete, or roll back explicit BLOCK guardrails,
// open broad wildcard destinations, or target servers outside their AllowedGroups via ServerIDs injection.
func CanModifyRule(claims *TokenClaims, rule models.PolicyRule, fleetServers ...[]models.Server) error {
	if claims == nil {
		return errors.New("unauthenticated")
	}
	if len(rule.GroupIDs) > 0 && !CanApproveForGroups(claims, rule.GroupIDs) {
		return fmt.Errorf("RBAC Policy: Role %s is not authorized for server groups %v", claims.Role, rule.GroupIDs)
	}
	if len(rule.GroupIDs) == 0 && claims.Role != models.RoleSuperAdmin && claims.Role != models.RoleInfoSecApprover {
		if claims.Role != models.RoleTeamLead || len(rule.ServerIDs) == 0 {
			return fmt.Errorf("RBAC Policy: Role %s is not authorized to manage rules without a server group scope", claims.Role)
		}
	}
	if claims.Role == models.RoleTeamLead {
		if strings.EqualFold(rule.Action, "BLOCK") {
			return errors.New("RBAC Policy: Only InfoSec Approvers and Super Admins can create, modify, or delete BLOCK guardrail rules")
		}
		if IsBroadHostPattern(rule.HostPattern) {
			return errors.New("RBAC Policy: Team Leads cannot whitelist catch-all or top-level-domain wildcard hosts")
		}
		for _, comp := range rule.CompanionRules {
			host := comp
			if i := strings.IndexByte(comp, '/'); i >= 0 {
				host = comp[:i]
			}
			if IsBroadHostPattern(host) {
				return errors.New("RBAC Policy: Team Leads cannot whitelist catch-all companion hosts")
			}
		}
		if len(rule.ServerIDs) > 0 {
			var srvMap map[string]models.Server
			if len(fleetServers) > 0 && len(fleetServers[0]) > 0 {
				srvMap = make(map[string]models.Server, len(fleetServers[0]))
				for _, s := range fleetServers[0] {
					srvMap[s.ID] = s
				}
			}
			for _, sid := range rule.ServerIDs {
				if sid == "*" {
					return errors.New("RBAC Policy: Team Leads cannot target wildcard (*) servers")
				}
				srv, exists := srvMap[sid]
				if !exists {
					return fmt.Errorf("RBAC Policy: Unknown target server ID %q", sid)
				}
				if !CanApproveForGroups(claims, srv.GroupIDs) {
					return fmt.Errorf("RBAC Policy: Team Lead is not authorized for target server %s (groups %v)", sid, srv.GroupIDs)
				}
			}
		}
	}
	return nil
}

// IsBroadHostPattern reports catch-all host patterns ("*", "*.com", "*.co.uk"-style two-label wildcards).
func IsBroadHostPattern(pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "*" || p == "" {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		domain := strings.TrimPrefix(p, "*.")
		if !strings.Contains(domain, ".") {
			return true
		}
		// A wildcard directly below a public suffix opens a namespace anyone can register in:
		// ICANN suffixes ("*.co.uk") and shared hosting/tunnel domains ("*.github.io", "*.ngrok-free.app").
		if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
			return true
		}
	}
	return false
}

// CanManageSystem checks if the user can modify TLS Bypass, CA config, threat protection, fleet or webhook settings.
func CanManageSystem(claims *TokenClaims) bool {
	if claims == nil {
		return false
	}
	return claims.Role == models.RoleSuperAdmin || claims.Role == models.RoleInfoSecApprover
}

// CanManageUsers restricts identity administration (users, roles, password resets) to Super Admins.
func CanManageUsers(claims *TokenClaims) bool {
	return claims != nil && claims.Role == models.RoleSuperAdmin
}

// EntraIDModularProvider is the modular OIDC adapter stub ready for later activation.
type EntraIDModularProvider struct {
	Config models.EntraIDConfig
}

func (p *EntraIDModularProvider) ProviderID() string {
	return "entra_id"
}

func (p *EntraIDModularProvider) Authenticate(oidToken, _ string) (*models.User, error) {
	if !p.Config.Enabled {
		return nil, fmt.Errorf("Microsoft Entra ID provider is currently disabled (modular stub mode)")
	}
	return nil, fmt.Errorf("Entra ID OIDC token validation requires active tenant connection (%s)", p.Config.TenantID)
}
