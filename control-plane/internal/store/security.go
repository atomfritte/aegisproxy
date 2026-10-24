package store

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

const (
	maxIndicators = 50_000
	maxExceptions = 5_000
	maxFeeds      = 64
)

var errNeedSystem = errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can change threat protection settings")

func (s *Store) UpdateSecurityPolicy(p models.SecurityPolicy, actor *auth.TokenClaims) (models.SecurityPolicy, error) {
	if !auth.CanManageSystem(actor) {
		return models.SecurityPolicy{}, errNeedSystem
	}
	err := s.withWrite(func() error {
		if err := validateSecurityPolicy(&p, s.state.Groups); err != nil {
			return err
		}
		now := time.Now().UTC()
		p.UpdatedAt, p.UpdatedBy = &now, actor.Username
		before := s.state.SecurityPolicy
		s.state.SecurityPolicy = p
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SECURITY_POLICY_UPDATED", Category: "SECURITY",
			EntityType: "security_policy", EntityID: "global", EntityName: "Threat Protection Policy",
			Summary: fmt.Sprintf("Threat intel=%s, AV=%v/%s (fail-%s), DLP=%s, blocked file types=%v, IP literals blocked=%v, ports=%v",
				p.ThreatIntelMode, p.AVEnabled, p.AVMode, p.AVFailMode, p.DLPMode, p.BlockedFileTypes, p.BlockIPLiterals, p.AllowedPorts),
			BeforeState: policySummary(before),
			AfterState:  policySummary(p),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.SecurityPolicy{}, err
	}
	return clonePolicy(p), nil
}

func policySummary(p models.SecurityPolicy) string {
	return fmt.Sprintf("threat_intel=%s av=%v/%s fail=%s max_scan=%d oversize=%s dlp=%s dlp_max=%d dlp_oversize=%s file_types=%v ip_literals=%v private=%v raw_tcp=%v ports=%v punycode=%s max_upload=%d burst=%d"+
		" icap_respmod=%q icap_reqmod=%q icap=%s/%s timeout=%d icap_max=%d cdr=%v icap_tls_skip_verify=%v icap_ca=%v yara=%s yara_max=%d",
		p.ThreatIntelMode, p.AVEnabled, p.AVMode, p.AVFailMode, p.AVMaxScanBytes, p.AVOversizeAction, p.DLPMode, p.DLPMaxScanBytes,
		p.DLPOversizeAction, p.BlockedFileTypes, p.BlockIPLiterals, p.BlockPrivateDestinations, p.BlockRawTCP, p.AllowedPorts, p.PunycodeMode, p.MaxUploadBytes, p.BlockedBurstThreshold,
		p.ICAPRespmodURL, p.ICAPReqmodURL, p.ICAPMode, p.ICAPFailMode, p.ICAPTimeoutSeconds, p.ICAPMaxBytes, p.ICAPAllowModified, p.ICAPTLSSkipVerify,
		p.ICAPCACertPEM != "", p.YARAMode, p.YARAMaxBytes)
}

// UpsertThreatFeed creates or updates a feed. For built-in feeds only enabled/refresh/subdomain
// matching/auth settings can be changed.
func (s *Store) UpsertThreatFeed(f models.ThreatFeed, actor *auth.TokenClaims) (models.ThreatFeed, error) {
	if !auth.CanManageSystem(actor) {
		return models.ThreatFeed{}, errNeedSystem
	}
	if f.RefreshMinutes != 0 && (f.RefreshMinutes < 15 || f.RefreshMinutes > 10080) {
		return models.ThreatFeed{}, errors.New("refresh_minutes must be between 15 and 10080")
	}
	if err := checkText("auth_header_name", f.AuthHeaderName, 64, false); err != nil {
		return models.ThreatFeed{}, err
	}
	if strings.ContainsAny(f.AuthHeaderName, " :\r\n") || strings.ContainsAny(string(f.AuthHeaderValue), "\r\n") {
		return models.ThreatFeed{}, errors.New("invalid auth header")
	}
	err := s.withWrite(func() error {

		i := slices.IndexFunc(s.state.ThreatFeeds, func(x models.ThreatFeed) bool { return x.ID == f.ID && f.ID != "" })
		action := "THREAT_FEED_UPDATED"
		if i >= 0 {
			cur := &s.state.ThreatFeeds[i]
			oldOrigin := urlOrigin(cur.URL)
			if f.AuthHeaderName == "" && (f.Format == "misp" || (f.Format == "" && cur.Format == "misp")) {
				f.AuthHeaderName = "Authorization" // MISP's default header; keeps the stored key on saves
			}
			if !cur.Builtin {
				if err := validateCustomFeed(&f); err != nil {
					return err
				}
				cur.Name, cur.Description, cur.URL, cur.Format, cur.Category, cur.License = f.Name, f.Description, f.URL, f.Format, f.Category, f.License
				cur.LookbackDays, cur.CACertPEM = f.LookbackDays, f.CACertPEM
			}
			cur.Enabled, cur.RefreshMinutes, cur.MatchSubdomains = f.Enabled, f.RefreshMinutes, f.MatchSubdomains
			cur.AuthHeaderName = f.AuthHeaderName
			// An empty value keeps the stored secret, unless the header is removed or the feed now points to
			// another host (credentials never follow a URL change).
			if f.AuthHeaderValue != "" || f.AuthHeaderName == "" || urlOrigin(cur.URL) != oldOrigin {
				cur.AuthHeaderValue = f.AuthHeaderValue
			}
			f = *cur
		} else {
			if len(s.state.ThreatFeeds) >= maxFeeds {
				return fmt.Errorf("at most %d feeds can be configured", maxFeeds)
			}
			if err := validateCustomFeed(&f); err != nil {
				return err
			}
			f.ID = newRandomID("feed")
			f.Builtin = false
			s.state.ThreatFeeds = append(s.state.ThreatFeeds, f)
			action = "THREAT_FEED_ADDED"
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "SECURITY",
			EntityType: "threat_feed", EntityID: f.ID, EntityName: f.Name,
			Summary: fmt.Sprintf("Threat feed %s (%s, %s) enabled=%v refresh=%dm", f.Name, f.Format, f.Category, f.Enabled, f.RefreshMinutes),
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
	if err != nil {
		return models.ThreatFeed{}, err
	}
	if f.Enabled && s.threat != nil {
		s.threat.RefreshNow(f.ID)
	}
	return f.Public(), nil
}

func validateCustomFeed(f *models.ThreatFeed) error {
	if err := checkText("name", f.Name, 120, true); err != nil {
		return err
	}
	if err := checkText("description", f.Description, 1000, false); err != nil {
		return err
	}
	if err := checkText("license", f.License, 120, false); err != nil {
		return err
	}
	switch f.Format {
	case models.FeedFormatDomains, models.FeedFormatHosts, models.FeedFormatURLs, models.FeedFormatIPs, models.FeedFormatSHA256:
		if err := threatintel.ValidateFeedURL(f.URL); err != nil {
			return err
		}
	case threatintel.FeedFormatTAXII, threatintel.FeedFormatMISP:
		if err := threatintel.ValidateSourceURL(f.URL, false); err != nil {
			return err
		}
	default:
		return errors.New("format must be one of domains, hosts, urls, ips, sha256, taxii21, misp")
	}
	if f.LookbackDays < 0 || f.LookbackDays > 3650 {
		return errors.New("lookback_days must be between 0 and 3650")
	}
	if len(f.CACertPEM) > 64<<10 || (strings.TrimSpace(f.CACertPEM) != "" && !strings.Contains(f.CACertPEM, "BEGIN CERTIFICATE")) {
		return errors.New("ca_cert_pem must be a PEM certificate")
	}
	f.Category = strings.ToLower(strings.TrimSpace(f.Category))
	if f.Category == "" {
		f.Category = "threat_intel"
	}
	return checkText("category", f.Category, 64, true)
}

func (s *Store) DeleteThreatFeed(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errNeedSystem
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ThreatFeeds, func(x models.ThreatFeed) bool { return x.ID == id })
		if i == -1 {
			return errors.New("feed not found")
		}
		f := s.state.ThreatFeeds[i]
		if f.Builtin {
			return errors.New("built-in feeds cannot be deleted; disable them instead")
		}
		s.state.ThreatFeeds = slices.Delete(s.state.ThreatFeeds, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "THREAT_FEED_DELETED", Category: "SECURITY",
			EntityType: "threat_feed", EntityID: f.ID, EntityName: f.Name, Summary: "Deleted threat feed " + f.Name,
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
}

func (s *Store) AddIndicator(ind models.Indicator, actor *auth.TokenClaims) (models.Indicator, error) {
	if !auth.CanManageSystem(actor) {
		return models.Indicator{}, errNeedSystem
	}
	if err := validateIndicator(&ind); err != nil {
		return models.Indicator{}, err
	}
	if ind.ExpiresAt != nil && ind.ExpiresAt.Before(time.Now()) {
		return models.Indicator{}, errors.New("expires_at must be in the future")
	}
	err := s.withWrite(func() error {
		if len(s.state.Indicators) >= maxIndicators {
			return fmt.Errorf("at most %d custom indicators are supported; use a feed for bulk lists", maxIndicators)
		}
		for _, existing := range s.state.Indicators {
			if existing.Type == ind.Type && existing.Value == ind.Value {
				return errors.New("indicator already exists")
			}
		}
		ind.ID = newRandomID("ioc")
		ind.Enabled = true
		ind.AddedBy = actor.Username
		ind.CreatedAt = time.Now().UTC()
		s.state.Indicators = append([]models.Indicator{ind}, s.state.Indicators...)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "IOC_ADDED", Category: "SECURITY",
			EntityType: "indicator", EntityID: ind.ID, EntityName: ind.Value,
			Summary: fmt.Sprintf("Added %s indicator %s (%s): %s", ind.Type, ind.Value, ind.Category, ind.Reason),
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
	if err != nil {
		return models.Indicator{}, err
	}
	return ind, nil
}

func (s *Store) DeleteIndicator(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errNeedSystem
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Indicators, func(x models.Indicator) bool { return x.ID == id })
		if i == -1 {
			return errors.New("indicator not found")
		}
		ind := s.state.Indicators[i]
		s.state.Indicators = slices.Delete(s.state.Indicators, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "IOC_DELETED", Category: "SECURITY",
			EntityType: "indicator", EntityID: ind.ID, EntityName: ind.Value, Summary: fmt.Sprintf("Removed %s indicator %s", ind.Type, ind.Value),
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
}

func (s *Store) AddThreatException(ex models.ThreatException, actor *auth.TokenClaims) (models.ThreatException, error) {
	if !auth.CanManageSystem(actor) {
		return models.ThreatException{}, errNeedSystem
	}
	if err := validateException(&ex); err != nil {
		return models.ThreatException{}, err
	}
	err := s.withWrite(func() error {
		if len(s.state.ThreatExceptions) >= maxExceptions {
			return fmt.Errorf("at most %d exceptions are supported", maxExceptions)
		}
		ex.ID = newRandomID("tex")
		ex.AddedBy = actor.Username
		ex.CreatedAt = time.Now().UTC()
		s.state.ThreatExceptions = append([]models.ThreatException{ex}, s.state.ThreatExceptions...)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "THREAT_EXCEPTION_ADDED", Category: "SECURITY",
			EntityType: "threat_exception", EntityID: ex.ID, EntityName: ex.Value,
			Summary: fmt.Sprintf("Suppressed threat-intel matches for %s %s (false positive): %s", ex.Type, ex.Value, ex.Reason),
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
	if err != nil {
		return models.ThreatException{}, err
	}
	return ex, nil
}

func (s *Store) DeleteThreatException(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errNeedSystem
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ThreatExceptions, func(x models.ThreatException) bool { return x.ID == id })
		if i == -1 {
			return errors.New("exception not found")
		}
		ex := s.state.ThreatExceptions[i]
		s.state.ThreatExceptions = slices.Delete(s.state.ThreatExceptions, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "THREAT_EXCEPTION_DELETED", Category: "SECURITY",
			EntityType: "threat_exception", EntityID: ex.ID, EntityName: ex.Value, Summary: "Removed threat-intel exception " + ex.Value,
		})
		s.saveLocked()
		s.syncThreatIntelLocked()
		return nil
	})
}

func (s *Store) AcknowledgeSecurityEvent(id string, actor *auth.TokenClaims) error {
	if actor == nil {
		return errors.New("unauthenticated")
	}
	if !auth.CanManageSystem(actor) && actor.Role != models.RoleTeamLead {
		return errors.New("RBAC Policy: read-only role")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.SecurityEvents, func(x models.SecurityEvent) bool { return x.ID == id })
		if i == -1 {
			return errors.New("event not found")
		}
		ev := &s.state.SecurityEvents[i]
		if actor.Role == models.RoleTeamLead && !auth.CanApproveForGroups(actor, ev.GroupIDs) {
			return errors.New("RBAC Policy: event belongs to server groups outside your scope")
		}
		now := time.Now().UTC()
		ev.Acknowledged, ev.AcknowledgedBy, ev.AcknowledgedAt = true, actor.Username, &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SECURITY_EVENT_ACKNOWLEDGED", Category: "SECURITY",
			EntityType: "security_event", EntityID: ev.ID, EntityName: ev.Type,
			Summary: fmt.Sprintf("Acknowledged %s event on %s (%s)", ev.Type, ev.ServerHostname, ev.Host),
		})
		s.markDirtyLocked()
		if s.telemetry != nil {
			s.telemetry.add(nil, []models.SecurityEvent{*ev}, nil)
		}
		return nil
	})
}

// ThreatFeedConfigs returns the raw feed configuration (including secrets) for the manager.
func (s *Store) ThreatFeedConfigs() []models.ThreatFeed {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.ThreatFeed(nil), s.state.ThreatFeeds...)
}

// urlOrigin returns scheme://host:port of a URL ("" when unparsable).
func urlOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
