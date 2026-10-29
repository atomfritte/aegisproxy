package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const (
	defaultBlockPageID = "bp-default"
	maxLogoBytes       = 200 << 10
	maxTemplates       = 50
)

var (
	logoRe    = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp|svg\+xml);base64,([A-Za-z0-9+/]+={0,2})$`)
	phoneRe   = regexp.MustCompile(`^[0-9+()./ -]{3,40}$`)
	tplLocale = []string{"en", "de"}
)

func DefaultBlockPageTemplate() models.BlockPageTemplate {
	return models.BlockPageTemplate{
		ID: defaultBlockPageID, Name: "Default", IsDefault: true, CompanyName: "AegisProxy",
		PrimaryColor: "#2563EB", AccentColor: "#DC2626", Theme: "auto",
		ShowRequestForm: true, ShowCASection: true, ShowTechnicalDetails: true, ShowSuggestedRule: true,
		AllowedScopes: append([]string{}, validScopes...), AllowedDurations: append([]string{}, validDurations...),
		DefaultLocale: "en", Links: []models.LinkItem{},
	}
}

func cloneTemplate(t models.BlockPageTemplate) models.BlockPageTemplate {
	t.Links = append([]models.LinkItem{}, t.Links...)
	t.AllowedScopes = append([]string{}, t.AllowedScopes...)
	t.AllowedDurations = append([]string{}, t.AllowedDurations...)
	return t
}

func checkHTTPURL(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(raw) > 500 {
		return fmt.Errorf("%s must be an http(s) URL", field)
	}
	return nil
}

// checkMultiline validates admin texts that may contain line breaks.
func checkMultiline(field, v string, maxLen int) error {
	if len(v) > maxLen {
		return fmt.Errorf("%s must be at most %d characters", field, maxLen)
	}
	return checkText(field, strings.NewReplacer("\r\n", " ", "\n", " ", "\t", " ").Replace(v), maxLen, false)
}

// ValidateBlockPageTemplate normalizes and validates a template (also used for unsaved previews).
func ValidateBlockPageTemplate(t *models.BlockPageTemplate) error {
	t.Name = strings.TrimSpace(t.Name)
	if err := checkText("name", t.Name, 80, true); err != nil {
		return err
	}
	if err := checkText("company_name", t.CompanyName, 120, false); err != nil {
		return err
	}
	if t.LogoDataURL != "" {
		m := logoRe.FindStringSubmatch(t.LogoDataURL)
		if m == nil {
			return errors.New("logo must be a base64 data: URL of a PNG, JPEG, GIF, WebP or SVG image")
		}
		raw, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil {
			return errors.New("logo is not valid base64")
		}
		if len(raw) > maxLogoBytes {
			return fmt.Errorf("logo must be at most %d KB", maxLogoBytes>>10)
		}
	}
	if t.PrimaryColor == "" {
		t.PrimaryColor = "#2563EB"
	}
	if t.AccentColor == "" {
		t.AccentColor = "#DC2626"
	}
	if !colorRe.MatchString(t.PrimaryColor) || !colorRe.MatchString(t.AccentColor) {
		return errors.New("colors must be hex colors like #2563EB")
	}
	if t.Theme == "" {
		t.Theme = "auto"
	}
	if err := validateMode("theme", t.Theme, "auto", "light", "dark"); err != nil {
		return err
	}
	if err := checkText("title", t.Title, 120, false); err != nil {
		return err
	}
	for _, f := range []struct {
		n, v string
		max  int
	}{{"message", t.Message, 2000}, {"threat_message", t.ThreatMessage, 2000}, {"footer_text", t.FooterText, 1000},
		{"cli_header", t.CLIHeader, 1000}, {"cli_footer", t.CLIFooter, 1000}} {
		if err := checkMultiline(f.n, f.v, f.max); err != nil {
			return err
		}
	}
	sc := &t.Support
	sc.Label, sc.Email, sc.Phone, sc.URL = strings.TrimSpace(sc.Label), strings.TrimSpace(sc.Email), strings.TrimSpace(sc.Phone), strings.TrimSpace(sc.URL)
	if err := checkText("support.label", sc.Label, 80, false); err != nil {
		return err
	}
	if sc.Email != "" {
		if a, err := mail.ParseAddress(sc.Email); err != nil || a.Address != sc.Email || len(sc.Email) > 200 {
			return errors.New("support.email must be a plain e-mail address")
		}
	}
	if sc.Phone != "" && !phoneRe.MatchString(sc.Phone) {
		return errors.New("support.phone may only contain digits, spaces and + ( ) . / -")
	}
	if err := checkHTTPURL("support.url", sc.URL); err != nil {
		return err
	}
	if len(t.Links) > 6 {
		return errors.New("at most 6 links")
	}
	if t.Links == nil {
		t.Links = []models.LinkItem{}
	}
	for i := range t.Links {
		l := &t.Links[i]
		l.Label, l.URL = strings.TrimSpace(l.Label), strings.TrimSpace(l.URL)
		if err := checkText("link label", l.Label, 60, true); err != nil {
			return err
		}
		if l.URL == "" {
			return errors.New("links need a URL")
		}
		if err := checkHTTPURL("link URL", l.URL); err != nil {
			return err
		}
	}
	for _, s := range t.AllowedScopes {
		if !slices.Contains(validScopes, s) {
			return fmt.Errorf("unknown scope %q (allowed: %v)", s, validScopes)
		}
	}
	for _, d := range t.AllowedDurations {
		if !slices.Contains(validDurations, d) {
			return fmt.Errorf("unknown duration %q (allowed: %v)", d, validDurations)
		}
	}
	if t.AllowedScopes == nil {
		t.AllowedScopes = []string{}
	}
	if t.AllowedDurations == nil {
		t.AllowedDurations = []string{}
	}
	if t.ShowRequestForm && (len(t.AllowedScopes) == 0 || len(t.AllowedDurations) == 0) {
		return errors.New("the request form needs at least one allowed scope and duration")
	}
	if t.DefaultLocale == "" {
		t.DefaultLocale = "en"
	}
	if !slices.Contains(tplLocale, t.DefaultLocale) {
		return fmt.Errorf("default_locale must be one of %v", tplLocale)
	}
	// "%%" delimits the placeholders the data-plane fills in (%%AEGIS:<key>%%).
	texts := map[string]string{"name": t.Name, "company_name": t.CompanyName, "title": t.Title, "message": t.Message,
		"threat_message": t.ThreatMessage, "footer_text": t.FooterText, "cli_header": t.CLIHeader, "cli_footer": t.CLIFooter,
		"support.label": sc.Label, "support.email": sc.Email, "support.phone": sc.Phone, "support.url": sc.URL}
	for i, l := range t.Links {
		texts[fmt.Sprintf("links[%d].label", i)], texts[fmt.Sprintf("links[%d].url", i)] = l.Label, l.URL
	}
	for _, field := range slices.Sorted(maps.Keys(texts)) {
		if strings.Contains(texts[field], "%%") {
			return fmt.Errorf(`%s must not contain "%%%%"`, field)
		}
	}
	return nil
}

func (s *Store) BlockPages() []models.BlockPageTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.BlockPageTemplate, len(s.state.BlockPages))
	for i, t := range s.state.BlockPages {
		out[i] = cloneTemplate(t)
	}
	return out
}

func (s *Store) BlockPage(id string) (models.BlockPageTemplate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.state.BlockPages {
		if t.ID == id {
			return cloneTemplate(t), true
		}
	}
	return models.BlockPageTemplate{}, false
}

// BlockPageAssignments returns the default template ID and the group -> template map (bundle).
func (s *Store) BlockPageAssignments() (string, map[string]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := map[string]string{}
	for _, g := range s.state.Groups {
		if g.BlockPageTemplateID != "" {
			m[g.ID] = g.BlockPageTemplateID
		}
	}
	return s.defaultTemplateIDLocked(), m
}

func (s *Store) defaultTemplateIDLocked() string {
	for _, t := range s.state.BlockPages {
		if t.IsDefault {
			return t.ID
		}
	}
	if len(s.state.BlockPages) > 0 {
		return s.state.BlockPages[0].ID
	}
	return ""
}

// templateForGroupsLocked picks the template of the first group that has one, else the default.
func (s *Store) templateForGroupsLocked(groups []string) string {
	for _, gid := range groups {
		for _, g := range s.state.Groups {
			if g.ID == gid && g.BlockPageTemplateID != "" {
				return g.BlockPageTemplateID
			}
		}
	}
	return s.defaultTemplateIDLocked()
}

func (s *Store) templateLocked(id string) (models.BlockPageTemplate, bool) {
	for _, t := range s.state.BlockPages {
		if t.ID == id {
			return t, true
		}
	}
	return models.BlockPageTemplate{}, false
}

func (s *Store) UpsertBlockPage(t models.BlockPageTemplate, actor *auth.TokenClaims) (models.BlockPageTemplate, error) {
	if !auth.CanManageSystem(actor) {
		return models.BlockPageTemplate{}, errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage block pages")
	}
	if err := ValidateBlockPageTemplate(&t); err != nil {
		return models.BlockPageTemplate{}, err
	}
	err := s.withWrite(func() error {
		now := time.Now().UTC()
		t.UpdatedAt, t.UpdatedBy = &now, actor.Username
		action := "BLOCK_PAGE_UPDATED"
		i := slices.IndexFunc(s.state.BlockPages, func(x models.BlockPageTemplate) bool { return x.ID == t.ID })
		if t.ID != "" && i < 0 {
			return errors.New("block page template not found")
		}
		if t.ID == "" {
			if len(s.state.BlockPages) >= maxTemplates {
				return fmt.Errorf("at most %d block page templates", maxTemplates)
			}
			t.ID = newRandomID("bp")
			action = "BLOCK_PAGE_CREATED"
			s.state.BlockPages = append(s.state.BlockPages, t)
			i = len(s.state.BlockPages) - 1
		} else {
			if s.state.BlockPages[i].IsDefault && !t.IsDefault {
				return errors.New("choose another template as default instead of unsetting the default")
			}
			s.state.BlockPages[i] = t
		}
		if t.IsDefault {
			for j := range s.state.BlockPages {
				s.state.BlockPages[j].IsDefault = j == i
			}
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "SYSTEM",
			EntityType: "block_page", EntityID: t.ID, EntityName: t.Name,
			Summary: fmt.Sprintf("Saved block page template %q (default=%v, request form=%v, scopes %v, durations %v)", t.Name, t.IsDefault, t.ShowRequestForm, t.AllowedScopes, t.AllowedDurations),
		})
		s.saveLocked()
		return nil
	})
	return cloneTemplate(t), err
}

func (s *Store) DeleteBlockPage(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage block pages")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.BlockPages, func(x models.BlockPageTemplate) bool { return x.ID == id })
		if i < 0 {
			return errors.New("block page template not found")
		}
		if s.state.BlockPages[i].IsDefault {
			return errors.New("the default template cannot be deleted")
		}
		for _, g := range s.state.Groups {
			if g.BlockPageTemplateID == id {
				return fmt.Errorf("template is still assigned to group %s", g.ID)
			}
		}
		t := s.state.BlockPages[i]
		s.state.BlockPages = slices.Delete(s.state.BlockPages, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "BLOCK_PAGE_DELETED", Category: "SYSTEM",
			EntityType: "block_page", EntityID: t.ID, EntityName: t.Name, Summary: fmt.Sprintf("Deleted block page template %q", t.Name),
		})
		s.saveLocked()
		return nil
	})
}

// TemplateForGroups returns the block page template that applies to a set of group memberships.
func (s *Store) TemplateForGroups(groups []string) models.BlockPageTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.templateLocked(s.templateForGroupsLocked(groups)); ok {
		return cloneTemplate(t)
	}
	return DefaultBlockPageTemplate()
}
