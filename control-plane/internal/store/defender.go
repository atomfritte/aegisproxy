package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/defender"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
	"aegisproxy/control-plane/internal/oidc"
	"aegisproxy/control-plane/internal/threatintel"
)

const (
	defenderFeedID = "microsoft-defender-indicators"
	defenderActor  = "microsoft-defender"
)

var riskRank = map[string]int{"none": 0, "informational": 1, "low": 2, "medium": 3, "high": 4}

func (s *Store) DefenderConfig() models.DefenderConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Defender
}

func defenderClient(cfg models.DefenderConfig) *defender.Client {
	return defender.New(defender.Config{TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: string(cfg.ClientSecret),
		APIBase: cfg.APIBaseURL, Authority: cfg.AuthorityURL}, nil)
}

func validateDefender(cfg *models.DefenderConfig) error {
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = defender.DefaultAPIBase
	}
	if cfg.AuthorityURL == "" {
		cfg.AuthorityURL = defender.DefaultAuthority
		if strings.Contains(strings.ToLower(cfg.APIBaseURL), "api-gov.securitycenter.microsoft.us") {
			cfg.AuthorityURL = "https://login.microsoftonline.us" // GCC High and DoD
		}
	}
	for _, u := range []string{cfg.APIBaseURL, cfg.AuthorityURL} {
		if err := oidc.ValidateIssuer(u); err != nil {
			return fmt.Errorf("%s: must be an https URL", u)
		}
		if !microsoftCloudHost(u) {
			return fmt.Errorf("%s: only Microsoft cloud endpoints are allowed (commercial, GCC/GCC High, China)", u)
		}
	}
	if cfg.Enabled {
		if !tenantRe.MatchString(cfg.TenantID) || cfg.ClientID == "" || len(cfg.ClientID) > 128 || hasCtl(cfg.ClientID) {
			return errors.New("tenant_id and client_id are required")
		}
		if cfg.ClientSecret == "" {
			return errors.New("client_secret is required")
		}
	}
	switch cfg.QuarantineOnRisk {
	case "":
		cfg.QuarantineOnRisk = "off"
	case "off", "high", "medium":
	default:
		return errors.New("quarantine_on_risk must be off, high or medium")
	}
	if cfg.SyncMinutes == 0 {
		cfg.SyncMinutes = 5
	}
	if cfg.SyncMinutes < 1 || cfg.SyncMinutes > 1440 {
		return errors.New("sync_minutes must be between 1 and 1440")
	}
	if len(cfg.IndicatorActions) == 0 {
		cfg.IndicatorActions = []string{"Block", "AlertAndBlock", "BlockAndRemediate"}
	}
	for _, a := range cfg.IndicatorActions {
		if !slices.Contains([]string{"Block", "AlertAndBlock", "BlockAndRemediate", "Alert", "Audit", "Warn"}, a) {
			return fmt.Errorf("unknown indicator action %q", a)
		}
	}
	return nil
}

// UpdateDefenderConfig stores the integration (Super Admin: it holds tenant credentials and can
// quarantine servers automatically).
func (s *Store) UpdateDefenderConfig(cfg models.DefenderConfig, actor *auth.TokenClaims) (models.DefenderConfig, error) {
	if err := requireSuperAdmin(actor); err != nil {
		return models.DefenderConfig{}, errors.New("RBAC Policy: only Super Admins can configure the Defender integration")
	}
	var out models.DefenderConfig
	err := s.withWrite(func() error {
		cur := s.state.Defender
		keep := cfg.ClientSecret == "" || strings.Contains(string(cfg.ClientSecret), models.MaskedSecretMarker)
		if keep {
			cfg.ClientSecret = cur.ClientSecret
		}
		if err := validateDefender(&cfg); err != nil {
			return err
		}
		// The stored secret belongs to one app registration at one authority, and its tokens to one API:
		// it never follows a changed tenant, client, authority or API endpoint (same rule as TestDefender).
		saved := cur
		_ = validateDefender(&saved) // fills endpoint defaults of older configurations
		if keep && cur.ClientSecret != "" && (cfg.TenantID != saved.TenantID || cfg.ClientID != saved.ClientID ||
			cfg.AuthorityURL != saved.AuthorityURL || cfg.APIBaseURL != saved.APIBaseURL) {
			if cfg.TenantID != "" && cfg.ClientID != "" {
				return errors.New("the tenant, client ID or endpoints changed: re-enter the client secret for the new destination")
			}
			cfg.ClientSecret = "" // cleared registration: the secret has nowhere to go
		}
		cfg.LastSyncAt, cfg.LastSyncError, cfg.LastSyncDevices, cfg.MatchedServers = cur.LastSyncAt, cur.LastSyncError, cur.LastSyncDevices, cur.MatchedServers
		now := time.Now().UTC()
		cfg.UpdatedAt, cfg.UpdatedBy, cfg.HasClientSecret = &now, actor.Username, false
		s.state.Defender = cfg
		s.syncDefenderFeedLocked()
		if !cfg.Enabled || !cfg.DeviceSync {
			for i := range s.state.Servers {
				s.state.Servers[i].Defender = nil
			}
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "DEFENDER_CONFIG_UPDATED", Category: "SECURITY",
			EntityType: "integration", EntityID: "microsoft-defender", EntityName: "Microsoft Defender for Endpoint",
			Summary: fmt.Sprintf("Defender integration enabled=%v (tenant %s): indicators=%v %v, device sync=%v, quarantine on risk=%s, on isolation=%v, auto release=%v",
				cfg.Enabled, cfg.TenantID, cfg.ImportIndicators, cfg.IndicatorActions, cfg.DeviceSync, cfg.QuarantineOnRisk, cfg.QuarantineOnIsolation, cfg.AutoRelease),
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		out = cfg.Public()
		return nil
	})
	return out, err
}

// syncDefenderFeedLocked maintains the built-in feed that imports Defender indicators.
func (s *Store) syncDefenderFeedLocked() {
	cfg := s.state.Defender
	want := cfg.Enabled && cfg.ImportIndicators
	i := slices.IndexFunc(s.state.ThreatFeeds, func(f models.ThreatFeed) bool { return f.ID == defenderFeedID })
	if i < 0 {
		if !want {
			return
		}
		s.state.ThreatFeeds = append(s.state.ThreatFeeds, models.ThreatFeed{ID: defenderFeedID, Builtin: true,
			Name: "Microsoft Defender for Endpoint indicators", Format: threatintel.FeedFormatMDE, Category: "microsoft_defender",
			Description: "Custom indicators (block actions) of your Defender tenant: what the SOC blocks on endpoints is blocked at the proxy too.",
			License:     "Your tenant", MatchSubdomains: true})
		i = len(s.state.ThreatFeeds) - 1
	}
	f := &s.state.ThreatFeeds[i]
	f.Enabled = want
	f.URL = strings.TrimRight(cfg.APIBaseURL, "/") + "/api/indicators"
	f.RefreshMinutes = max(cfg.SyncMinutes, 15)
}

// defenderCollector is registered with the threat-intel manager for the "mde" format.
func (s *Store) defenderCollector(ctx context.Context, _ models.ThreatFeed) ([]byte, error) {
	cfg := s.DefenderConfig()
	if !cfg.Enabled || !cfg.ImportIndicators {
		return nil, errors.New("Defender indicator import is disabled")
	}
	inds, err := defenderClient(cfg).Indicators(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var b strings.Builder
	for _, ind := range inds {
		if !defender.BlockingAction(ind.Action, cfg.IndicatorActions) || (ind.ExpirationTime != nil && ind.ExpirationTime.Before(now)) {
			continue
		}
		v := strings.TrimSpace(ind.IndicatorValue)
		if v == "" || strings.ContainsAny(v, "\t\r\n") {
			continue
		}
		switch ind.IndicatorType {
		case "DomainName":
			b.WriteString("domain\t" + v + "\n")
		case "Url":
			b.WriteString("url\t" + v + "\n")
		case "IpAddress":
			b.WriteString("ip\t" + v + "\n")
		case "FileSha256":
			b.WriteString("sha256\t" + v + "\n")
		}
	}
	return []byte(b.String()), nil
}

// TestDefender checks credentials and permissions. The stored client secret is only used for the
// stored tenant, application and endpoints, so a test can never send it elsewhere.
func (s *Store) TestDefender(ctx context.Context, cfg models.DefenderConfig) (map[string]any, error) {
	stored := s.DefenderConfig()
	_ = validateDefender(&stored)
	probe := cfg
	_ = validateDefender(&probe) // fills endpoint defaults for the comparison
	if cfg.ClientSecret == "" {
		if probe.TenantID != stored.TenantID || probe.ClientID != stored.ClientID ||
			probe.AuthorityURL != stored.AuthorityURL || probe.APIBaseURL != stored.APIBaseURL {
			return nil, errors.New("enter the client secret: the stored secret is only used for the saved tenant, application and endpoints")
		}
		cfg.ClientSecret = stored.ClientSecret
	}
	cfg.Enabled = true
	if err := validateDefender(&cfg); err != nil {
		return nil, err
	}
	c := defenderClient(cfg)
	res := map[string]any{}
	inds, err := c.Indicators(ctx)
	if err != nil {
		res["indicators_error"] = err.Error()
	} else {
		res["indicators"] = len(inds)
	}
	ms, err := c.Machines(ctx)
	if err != nil {
		res["devices_error"] = err.Error()
	} else {
		res["devices"] = len(ms)
	}
	res["ok"] = res["indicators_error"] == nil && res["devices_error"] == nil
	return res, nil
}

// claimDefenderSync makes sure only one replica syncs per interval.
func (s *Store) claimDefenderSync(now time.Time, force bool) (models.DefenderConfig, bool) {
	var cfg models.DefenderConfig
	claimed := false
	_ = s.withWrite(func() error {
		d := &s.state.Defender
		if !d.Enabled || !d.DeviceSync {
			return nil
		}
		if !force && d.LastSyncAt != nil && now.Sub(*d.LastSyncAt) < time.Duration(d.SyncMinutes)*time.Minute-10*time.Second {
			return nil
		}
		t := now.UTC()
		d.LastSyncAt = &t
		s.markDirtyLocked()
		cfg, claimed = *d, true
		return nil
	})
	return cfg, claimed
}

// SyncDefenderDevices fetches devices and isolation state, maps them to servers and applies the
// quarantine policy. force bypasses the interval (manual "sync now").
func (s *Store) SyncDefenderDevices(ctx context.Context, force bool) error {
	cfg, ok := s.claimDefenderSync(time.Now(), force)
	if !ok {
		return nil
	}
	c := defenderClient(cfg)
	machines, err := c.Machines(ctx)
	var isolated map[string]bool
	if err == nil && cfg.QuarantineOnIsolation {
		isolated, err = c.IsolatedMachines(ctx)
	}
	if err != nil {
		_ = s.withWrite(func() error {
			s.state.Defender.LastSyncError = err.Error()
			s.markDirtyLocked()
			return nil
		})
		return err
	}
	type decision struct {
		idx                 int
		quarantine, release bool
		reason              string
	}
	var notify []models.Server
	err = s.withWrite(func() error {
		now := time.Now().UTC()
		byName, byShort, byIP := map[string]int{}, map[string]int{}, map[string]int{}
		for i, srv := range s.state.Servers {
			h := strings.ToLower(strings.TrimSpace(srv.Hostname))
			byName[h] = i
			short, _, _ := strings.Cut(h, ".")
			if _, dup := byShort[short]; !dup {
				byShort[short] = i
			} else {
				byShort[short] = -1 // ambiguous short name
			}
			if srv.IP != "" {
				byIP[srv.IP] = i
			}
			s.state.Servers[i].Defender = nil
		}
		matched := 0
		var decisions []decision
		for _, m := range machines {
			name := strings.ToLower(strings.TrimSpace(m.ComputerDNSName))
			short, _, _ := strings.Cut(name, ".")
			idx, by := -1, ""
			if i, ok := byName[name]; ok && name != "" {
				idx, by = i, "hostname"
			} else if i, ok := byShort[short]; ok && i >= 0 && short != "" {
				idx, by = i, "hostname"
			} else if a, err := netip.ParseAddr(m.LastIPAddress); err == nil {
				if i, ok := byIP[a.Unmap().String()]; ok {
					idx, by = i, "ip"
				}
			}
			if idx < 0 {
				continue
			}
			matched++
			srv := &s.state.Servers[idx]
			dev := &models.DefenderDevice{MachineID: m.ID, ComputerName: m.ComputerDNSName, RiskScore: m.RiskScore,
				ExposureLevel: m.ExposureLevel, HealthStatus: m.HealthStatus, Isolated: isolated[m.ID], LastSeen: m.LastSeen,
				MatchedBy: by, SyncedAt: now}
			srv.Defender = dev
			var reasons []string
			threshold := map[string]int{"high": riskRank["high"], "medium": riskRank["medium"]}[cfg.QuarantineOnRisk]
			if cfg.QuarantineOnRisk != "off" && riskRank[strings.ToLower(m.RiskScore)] >= threshold {
				reasons = append(reasons, "risk "+m.RiskScore)
			}
			if cfg.QuarantineOnIsolation && dev.Isolated {
				reasons = append(reasons, "device isolated")
			}
			switch {
			case len(reasons) > 0 && !srv.Quarantined:
				decisions = append(decisions, decision{idx: idx, quarantine: true,
					reason: fmt.Sprintf("Microsoft Defender: %s (machine %s)", strings.Join(reasons, ", "), m.ID)})
			case len(reasons) == 0 && srv.Quarantined && srv.QuarantinedBy == defenderActor && cfg.AutoRelease:
				decisions = append(decisions, decision{idx: idx, release: true, reason: "Microsoft Defender: condition cleared"})
			}
		}
		for _, d := range decisions {
			srv := &s.state.Servers[d.idx]
			if d.quarantine {
				srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = true, d.reason, defenderActor, &now
				notify = append(notify, cloneServer(*srv))
				s.appendAuditLocked(models.AuditEvent{Actor: defenderActor, ActorRole: "INTEGRATION", Action: "SERVER_QUARANTINED", Category: "SECURITY",
					EntityType: "server", EntityID: srv.ID, EntityName: srv.Hostname, ScopeGroups: srv.EffectiveGroupIDs,
					Summary: fmt.Sprintf("Quarantined %s (%s) automatically — %s", srv.Hostname, srv.IP, d.reason)})
			} else {
				prev := srv.QuarantineReason
				srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = false, "", "", nil
				s.appendAuditLocked(models.AuditEvent{Actor: defenderActor, ActorRole: "INTEGRATION", Action: "SERVER_RELEASED", Category: "SECURITY",
					EntityType: "server", EntityID: srv.ID, EntityName: srv.Hostname, ScopeGroups: srv.EffectiveGroupIDs,
					Summary: fmt.Sprintf("Released %s automatically (was: %s) — %s", srv.Hostname, prev, d.reason)})
			}
		}
		s.state.Defender.LastSyncError, s.state.Defender.LastSyncDevices, s.state.Defender.MatchedServers = "", len(machines), matched
		if len(decisions) > 0 {
			s.saveLocked()
		} else {
			s.markDirtyLocked()
		}
		return nil
	})
	if s.notifier != nil {
		for _, srv := range notify {
			s.notifier.NotifySecurityEvent(models.SecurityEvent{Timestamp: time.Now().UTC(), Type: "QUARANTINE", Severity: "high", Action: "blocked",
				ServerID: srv.ID, ServerIP: srv.IP, ServerHostname: srv.Hostname, GroupIDs: srv.EffectiveGroupIDs, Detail: srv.QuarantineReason, Count: 1})
		}
	}
	return err
}

func (s *Store) defenderLoop() {
	defer s.persistWG.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if err := s.SyncDefenderDevices(ctx, false); err != nil {
				s.log.Warn("Defender device sync failed", "error", err)
			}
			cancel()
		}
	}
}

// microsoftCloudHost allows the Entra ID authorities and Defender/Graph API hosts of the Microsoft
// clouds (and loopback for local test doubles).
func microsoftCloudHost(raw string) bool {
	return netguard.HostInDomains(raw, append([]string{"microsoft.com", "microsoft.us", "windows.com", "windows.net"}, netguard.EntraAuthorityDomains...)...)
}

// DefenderConfigNormalized returns the configuration with defaults applied (as the API shows it).
func (s *Store) DefenderConfigNormalized() models.DefenderConfig {
	cfg := s.DefenderConfig()
	enabled := cfg.Enabled
	cfg.Enabled = false // defaults only; required fields are validated on save
	_ = validateDefender(&cfg)
	cfg.Enabled = enabled
	return cfg
}
