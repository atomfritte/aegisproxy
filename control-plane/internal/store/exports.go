package store

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
)

// ExportSinks returns the configured sinks with secrets redacted.
func (s *Store) ExportSinks() []models.ExportSink {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.ExportSink, len(s.state.ExportSinks))
	for i, sink := range s.state.ExportSinks {
		out[i] = sink.Public()
	}
	return out
}

// MergeExportSecrets fills omitted write-only fields of in from the stored sink with the same ID.
func (s *Store) MergeExportSecrets(in models.ExportSink) models.ExportSink {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return mergeSinkSecrets(in, s.exportSinkLocked(in.ID))
}

// MergeExportSecretsForTest fills omitted secrets of a test configuration from the stored sink,
// but only when the destination is unchanged: stored credentials never go to another host.
func (s *Store) MergeExportSecretsForTest(in models.ExportSink) (models.ExportSink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prev := s.exportSinkLocked(in.ID)
	unmaskEndpoint(&in, prev)
	if err := storedCredentialsStay(in, prev); err != nil {
		return models.ExportSink{}, err
	}
	if prev != nil && !sameSinkDestination(in, *prev) {
		prev = nil
	}
	return mergeSinkSecrets(in, prev), nil
}

// storedCredentialsStay refuses a configuration that changes the destination of a stored sink while
// relying on its stored secret, header values or client key: they belong to the saved destination.
func storedCredentialsStay(in models.ExportSink, prev *models.ExportSink) error {
	if prev == nil || sameSinkDestination(in, *prev) {
		return nil
	}
	needs := in.Secret == "" && !in.ClearSecret && prev.Secret != ""
	for k, v := range in.Headers {
		if _, ok := prev.Headers[k]; ok && v == "" {
			needs = true
		}
	}
	if in.ClientCertPEM != "" && in.ClientKeyPEM == "" && prev.ClientKeyPEM != "" {
		needs = true
	}
	if needs {
		return errors.New("the destination changed: enter the credentials again (stored credentials are only used for the saved destination)")
	}
	return nil
}

// ExportSinkWithSecrets returns a stored sink including its secrets.
func (s *Store) ExportSinkWithSecrets(id string) (models.ExportSink, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p := s.exportSinkLocked(id); p != nil {
		out := *p
		out.Headers = maps.Clone(p.Headers)
		out.Labels = maps.Clone(p.Labels)
		return out, true
	}
	return models.ExportSink{}, false
}

// sameSinkDestination reports whether credentials of b may be used with configuration a.
func sameSinkDestination(a, b models.ExportSink) bool {
	a, b = destinationDefaults(a), destinationDefaults(b)
	return a.Type == b.Type && a.Endpoint == b.Endpoint && a.Transport == b.Transport && a.Username == b.Username &&
		a.TenantID == b.TenantID && a.ClientID == b.ClientID && a.AuthorityURL == b.AuthorityURL && a.AzureAuth == b.AzureAuth &&
		a.TLSSkipVerify == b.TLSSkipVerify && a.CACertPEM == b.CACertPEM && a.ClientCertPEM == b.ClientCertPEM
}

// destinationDefaults fills the destination defaults export.Validate applies, so an update that omits
// them compares equal to the stored (validated) sink.
func destinationDefaults(s models.ExportSink) models.ExportSink {
	s.Endpoint = strings.TrimSpace(s.Endpoint)
	switch {
	case s.Type == "syslog" && s.Transport == "":
		s.Transport = "tcp"
	case s.Type == "datadog" && s.Endpoint == "":
		s.Endpoint = "https://http-intake.logs.datadoghq.com"
	case s.Type == "sentinel" && s.AzureAuth == "":
		s.AzureAuth = "client_secret"
	}
	return s
}

func (s *Store) exportSinkLocked(id string) *models.ExportSink {
	if id == "" {
		return nil
	}
	for i := range s.state.ExportSinks {
		if s.state.ExportSinks[i].ID == id {
			return &s.state.ExportSinks[i]
		}
	}
	return nil
}

// unmaskEndpoint restores the stored endpoint when the masked form (query values or webhook path
// hidden) is sent back.
func unmaskEndpoint(in *models.ExportSink, prev *models.ExportSink) {
	if prev != nil && in.Endpoint != prev.Endpoint && strings.Contains(in.Endpoint, models.MaskedSecretMarker) &&
		in.Endpoint == models.MaskSinkEndpoint(prev.Type, prev.Endpoint) {
		in.Endpoint = prev.Endpoint
	}
}

func mergeSinkSecrets(in models.ExportSink, prev *models.ExportSink) models.ExportSink {
	unmaskEndpoint(&in, prev)
	in.Headers = maps.Clone(in.Headers) // never write stored values into the caller's map
	if prev != nil {
		if in.Secret == "" && !in.ClearSecret {
			in.Secret = prev.Secret
		}
		if in.ClientKeyPEM == "" && in.ClientCertPEM != "" {
			in.ClientKeyPEM = prev.ClientKeyPEM
		}
		for k, v := range in.Headers {
			if v == "" {
				if old, ok := prev.Headers[k]; ok {
					in.Headers[k] = old
				}
			}
		}
	}
	if in.Headers != nil {
		for k, v := range in.Headers {
			if v == "" {
				delete(in.Headers, k)
			}
		}
	}
	in.ClearSecret, in.HasSecret, in.HasClientKey = false, false, false
	return in
}

// UpsertExportSink creates or updates a sink. Only Super Admins can direct logs to external systems.
func (s *Store) UpsertExportSink(in models.ExportSink, actor *auth.TokenClaims) (models.ExportSink, error) {
	if actor == nil || actor.Role != models.RoleSuperAdmin {
		return models.ExportSink{}, errors.New("RBAC Policy: only Super Admins can configure log export destinations")
	}
	var out models.ExportSink
	err := s.withWrite(func() error {
		prev := s.exportSinkLocked(in.ID)
		if in.ID != "" && prev == nil {
			return errors.New("export sink not found")
		}
		unmaskEndpoint(&in, prev)
		if err := storedCredentialsStay(in, prev); err != nil {
			return err
		}
		sink := mergeSinkSecrets(in, prev)
		if err := export.Validate(&sink); err != nil {
			return err
		}
		if len(s.state.ExportSinks) >= 20 && prev == nil {
			return errors.New("at most 20 export sinks")
		}
		for _, other := range s.state.ExportSinks {
			if other.ID != sink.ID && strings.EqualFold(other.Name, sink.Name) {
				return fmt.Errorf("an export sink named %q already exists", sink.Name)
			}
			if sink.Type == "file" && other.ID != sink.ID && other.Type == "file" && other.Endpoint == sink.Endpoint {
				return fmt.Errorf("file %s is already used by %q", sink.Endpoint, other.Name)
			}
		}
		now := time.Now().UTC()
		sink.UpdatedAt, sink.UpdatedBy = &now, actor.Username
		action := "EXPORT_SINK_UPDATED"
		if prev == nil {
			sink.ID = newRandomID("exp")
			action = "EXPORT_SINK_CREATED"
			s.state.ExportSinks = append(s.state.ExportSinks, sink)
		} else {
			*prev = sink
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "SYSTEM",
			EntityType: "export_sink", EntityID: sink.ID, EntityName: sink.Name,
			Summary: fmt.Sprintf("%s log export %q (%s → %s, streams %v, format %s, enabled=%v)", strings.ToLower(strings.TrimPrefix(action, "EXPORT_SINK_")),
				sink.Name, sink.Type, models.MaskSinkEndpoint(sink.Type, sink.Endpoint), sink.Streams, sink.Format, sink.Enabled),
		})
		s.markDirtyLocked()
		s.syncExportLocked()
		out = sink.Public()
		return nil
	})
	return out, err
}

func (s *Store) DeleteExportSink(id string, actor *auth.TokenClaims) error {
	if actor == nil || actor.Role != models.RoleSuperAdmin {
		return errors.New("RBAC Policy: only Super Admins can configure log export destinations")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.ExportSinks, func(x models.ExportSink) bool { return x.ID == id })
		if i < 0 {
			return errors.New("export sink not found")
		}
		sink := s.state.ExportSinks[i]
		s.state.ExportSinks = slices.Delete(s.state.ExportSinks, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "EXPORT_SINK_DELETED", Category: "SYSTEM",
			EntityType: "export_sink", EntityID: sink.ID, EntityName: sink.Name,
			Summary: fmt.Sprintf("Deleted log export %q (%s → %s)", sink.Name, sink.Type, models.MaskSinkEndpoint(sink.Type, sink.Endpoint)),
		})
		s.markDirtyLocked()
		s.syncExportLocked()
		return nil
	})
}
