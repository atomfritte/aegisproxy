package provenance

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// In-toto and predicate types.
const (
	InTotoPayloadType      = "application/vnd.in-toto+json"
	inTotoStatementV01     = "https://in-toto.io/Statement/v0.1"
	inTotoStatementV1      = "https://in-toto.io/Statement/v1"
	PredicateSLSAv02       = "https://slsa.dev/provenance/v0.2"
	PredicateSLSAv1        = "https://slsa.dev/provenance/v1"
	PredicateNPMPublish    = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
	PredicatePyPIPublish   = "https://docs.pypi.org/attestations/publish/v1"
	bundleMediaTypePrefix  = "application/vnd.dev.sigstore.bundle+json;version="
	bundleMediaTypeV03Long = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// Subject is an in-toto statement subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Result is a verified attestation.
type Result struct {
	MediaType      string          `json:"media_type,omitempty"` // bundle media type
	PredicateType  string          `json:"predicate_type"`
	Subjects       []Subject       `json:"subjects"`
	Predicate      json.RawMessage `json:"predicate,omitempty"`
	IntegratedTime time.Time       `json:"integrated_time"` // signed by the transparency log
	LogIndex       int64           `json:"log_index"`
	LogID          string          `json:"log_id"`             // hex
	Identity       *Identity       `json:"identity,omitempty"` // Fulcio-certified signer
	KeyID          string          `json:"key_id,omitempty"`   // or the registry key that signed it
	SLSA           *SLSAProvenance `json:"slsa,omitempty"`     // key fields of an SLSA provenance predicate
}

type bundleJSON struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial *struct {
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes b64 `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		Certificate *struct {
			RawBytes b64 `json:"rawBytes"`
		} `json:"certificate"`
		PublicKey *struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
		TlogEntries []tlogEntry `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	DSSEEnvelope *struct {
		Payload     b64    `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig   b64    `json:"sig"`
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
	MessageSignature json.RawMessage `json:"messageSignature"`
}

// envelope is a DSSE envelope with its single signature.
type envelope struct {
	payloadType string
	payload     []byte
	sig         []byte
}

// material is what a bundle or a PEP 740 attestation provides for verification.
type material struct {
	mediaType string
	minor     int    // bundle version 0.<minor>
	leaf      []byte // Fulcio leaf certificate (DER), or
	keyHint   string // the hint of the public key that signed the envelope
	entries   []tlogEntry
	env       envelope
}

func parseBundle(data []byte) (*material, error) {
	var b bundleJSON
	if err := decodeJSON(data, &b, "bundle"); err != nil {
		return nil, err
	}
	m := &material{mediaType: b.MediaType}
	switch b.MediaType {
	case bundleMediaTypePrefix + "0.1":
		m.minor = 1
	case bundleMediaTypePrefix + "0.2":
		m.minor = 2
	case bundleMediaTypePrefix + "0.3", bundleMediaTypeV03Long:
		m.minor = 3
	default:
		return nil, failf(ErrUnsupported, "bundle media type %.100q", b.MediaType)
	}
	vm := b.VerificationMaterial
	if vm == nil {
		return nil, failf(ErrMalformed, "bundle has no verification material")
	}
	if b.DSSEEnvelope == nil {
		if b.MessageSignature != nil {
			return nil, failf(ErrUnsupported, "message signature bundles (only DSSE envelopes are supported)")
		}
		return nil, failf(ErrMalformed, "bundle has no DSSE envelope")
	}
	sources := 0
	if c := vm.X509CertificateChain; c != nil {
		sources++
		if len(c.Certificates) == 0 || len(c.Certificates) > MaxCertificates {
			return nil, failf(ErrLimit, "certificate chain has %d certificates (1–%d)", len(c.Certificates), MaxCertificates)
		}
		m.leaf = c.Certificates[0].RawBytes
	}
	if vm.Certificate != nil {
		sources++
		m.leaf = vm.Certificate.RawBytes
	}
	if vm.PublicKey != nil {
		sources++
		m.keyHint = vm.PublicKey.Hint
		if m.keyHint == "" {
			return nil, failf(ErrMalformed, "public key without hint")
		}
	}
	if sources != 1 || (m.keyHint == "" && len(m.leaf) == 0) {
		return nil, failf(ErrMalformed, "bundle must carry exactly one certificate, certificate chain or public key")
	}
	m.entries = vm.TlogEntries
	env := b.DSSEEnvelope
	if len(env.Signatures) != 1 {
		return nil, failf(ErrUnsupported, "DSSE envelope has %d signatures (exactly one is supported)", len(env.Signatures))
	}
	m.env = envelope{payloadType: env.PayloadType, payload: env.Payload, sig: env.Signatures[0].Sig}
	return m, nil
}

// expectation is what the verified statement must state, and how the signer is established.
type expectation struct {
	subjectName string // "" = any name
	digest      Digest
	oneSubject  bool // PEP 740: exactly one subject
	// key resolves the public key of a key-signed bundle (npm publish attestation) valid at the integrated
	// time; nil requires a Fulcio certificate.
	key func(hint string, at time.Time) (pub crypto.PublicKey, spki []byte, err error)
}

// VerifyBundle verifies a Sigstore bundle (v0.1, v0.2, v0.3) that carries a DSSE envelope signed with a Fulcio
// certificate and requires an in-toto statement subject with the expected digest.
func VerifyBundle(bundle []byte, root *TrustedRoot, expected Digest) (*Result, error) {
	return Options{}.VerifyBundle(bundle, root, expected)
}

// VerifyBundle is VerifyBundle with options.
func (o Options) VerifyBundle(bundle []byte, root *TrustedRoot, expected Digest) (*Result, error) {
	m, err := parseBundle(bundle)
	if err != nil {
		return nil, err
	}
	return o.verify(m, root, expectation{digest: expected})
}

func (o Options) verify(m *material, root *TrustedRoot, x expectation) (*Result, error) {
	if root == nil {
		return nil, failf(ErrMalformed, "no trusted root")
	}
	want, err := x.digest.normalized()
	if err != nil {
		return nil, err
	}
	if m.env.payloadType != InTotoPayloadType {
		return nil, failf(ErrUnsupported, "DSSE payload type %.100q", m.env.payloadType)
	}
	if len(m.entries) == 0 {
		return nil, failf(ErrTransparencyLog, "bundle has no transparency log entry")
	}
	if len(m.entries) > maxTlogEntries {
		return nil, failf(ErrLimit, "bundle has %d transparency log entries", len(m.entries))
	}
	// 1. Every log entry: SET, inclusion proof and checkpoint; the signed integrated times (steps as in README.md).
	times := make([]time.Time, len(m.entries))
	for i := range m.entries {
		if times[i], err = o.verifyEntry(root, &m.entries[i], m.minor >= 2); err != nil {
			return nil, err
		}
	}
	// 2, 3. The signer: a Fulcio certificate valid at every integrated time with an SCT, or a registry key.
	res := &Result{MediaType: m.mediaType}
	var pub crypto.PublicKey
	var s signer
	switch {
	case x.key == nil:
		if len(m.leaf) == 0 {
			return nil, failf(ErrUntrustedCert, "bundle is signed with a public key, a Fulcio certificate is required")
		}
		leaf, err := x509.ParseCertificate(m.leaf)
		if err != nil {
			return nil, failf(ErrMalformed, "leaf certificate: %v", err)
		}
		var issuer *x509.Certificate
		for _, t := range times {
			if issuer, err = root.verifyLeaf(leaf, t); err != nil {
				return nil, err
			}
		}
		if err := root.verifySCTs(leaf, issuer); err != nil {
			return nil, err
		}
		if res.Identity, err = identityFromCert(leaf); err != nil {
			return nil, err
		}
		pub, s = leaf.PublicKey, signer{cert: m.leaf}
	default:
		if m.keyHint == "" {
			return nil, failf(ErrUntrustedCert, "bundle is signed with a certificate, a registry key is required")
		}
		var spki []byte
		for _, t := range times {
			if pub, spki, err = x.key(m.keyHint, t); err != nil {
				return nil, err
			}
		}
		res.KeyID, s = m.keyHint, signer{spki: spki}
	}
	if !supportedKey(pub) {
		return nil, failf(ErrUnsupported, "signing key type %T", pub)
	}
	// 4. The log entries must be about this envelope, signature and signer.
	for i := range m.entries {
		if err := matchBody(&m.entries[i], &m.env, s); err != nil {
			return nil, err
		}
	}
	// 5. The DSSE signature over PAE(payloadType, payload).
	if !verifySignature(pub, pae(m.env.payloadType, m.env.payload), m.env.sig) {
		return nil, failf(ErrInvalidSignature, "DSSE envelope signature does not verify")
	}
	// 6. The statement subject.
	st, err := parseStatement(m.env.payload)
	if err != nil {
		return nil, err
	}
	if x.oneSubject && len(st.Subject) != 1 {
		return nil, failf(ErrSubjectMismatch, "statement has %d subjects, exactly one is required", len(st.Subject))
	}
	if !matchSubject(st.Subject, x.subjectName, want) {
		if x.subjectName != "" {
			return nil, failf(ErrSubjectMismatch, "no subject %q with %s %s", x.subjectName, want.Algorithm, want.Value)
		}
		return nil, failf(ErrSubjectMismatch, "no subject with %s %s", want.Algorithm, want.Value)
	}
	// 7. The result.
	res.PredicateType, res.Subjects, res.Predicate = st.PredicateType, st.Subject, st.Predicate
	res.IntegratedTime, res.LogIndex, res.LogID = times[0], int64(m.entries[0].LogIndex), hex.EncodeToString(m.entries[0].LogID.KeyID)
	res.SLSA = parseSLSA(st.PredicateType, st.Predicate)
	return res, nil
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

type statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

func parseStatement(payload []byte) (*statement, error) {
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, failf(ErrMalformed, "in-toto statement: %v", err)
	}
	if st.Type != inTotoStatementV01 && st.Type != inTotoStatementV1 {
		return nil, failf(ErrUnsupported, "in-toto statement type %.100q", st.Type)
	}
	if len(st.Subject) == 0 {
		return nil, failf(ErrMalformed, "statement has no subject")
	}
	if len(st.Subject) > maxSubjects {
		return nil, failf(ErrLimit, "statement has %d subjects", len(st.Subject))
	}
	if st.PredicateType == "" {
		return nil, failf(ErrMalformed, "statement has no predicate type")
	}
	if string(st.Predicate) == "null" {
		st.Predicate = nil
	}
	return &st, nil
}

func matchSubject(subjects []Subject, name string, d Digest) bool {
	for _, s := range subjects {
		if name != "" && s.Name != name {
			continue
		}
		if v, ok := s.Digest[d.Algorithm]; ok && strings.EqualFold(v, d.Value) {
			return true
		}
	}
	return false
}

// SLSAProvenance holds the key fields of an SLSA provenance predicate (v0.2 or v1). They are claims of the build
// platform signed with the certificate; Identity is what Fulcio itself certified.
type SLSAProvenance struct {
	Version      string `json:"version"` // v0.2 | v1
	BuilderID    string `json:"builder_id"`
	BuildType    string `json:"build_type"`
	Repository   string `json:"repository,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Workflow     string `json:"workflow,omitempty"` // workflow path / entry point
	Commit       string `json:"commit,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	EventName    string `json:"event_name,omitempty"`
}

func parseSLSA(predicateType string, predicate json.RawMessage) *SLSAProvenance {
	switch predicateType {
	case PredicateSLSAv1, "https://slsa.dev/provenance/v1.0", "https://slsa.dev/provenance/v1.1":
		var p struct {
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					Workflow struct {
						Ref        string `json:"ref"`
						Repository string `json:"repository"`
						Path       string `json:"path"`
					} `json:"workflow"`
				} `json:"externalParameters"`
				InternalParameters struct {
					GitHub struct {
						EventName string `json:"event_name"`
					} `json:"github"`
				} `json:"internalParameters"`
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
				Metadata struct {
					InvocationID string `json:"invocationId"`
				} `json:"metadata"`
			} `json:"runDetails"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return nil
		}
		w := p.BuildDefinition.ExternalParameters.Workflow
		s := &SLSAProvenance{
			Version: "v1", BuilderID: p.RunDetails.Builder.ID, BuildType: p.BuildDefinition.BuildType,
			Repository: w.Repository, Ref: w.Ref, Workflow: w.Path, InvocationID: p.RunDetails.Metadata.InvocationID,
			EventName: p.BuildDefinition.InternalParameters.GitHub.EventName,
		}
		for _, d := range p.BuildDefinition.ResolvedDependencies {
			if c := firstNonEmpty(d.Digest["gitCommit"], d.Digest["sha1"]); c != "" {
				repo, ref := splitGitURI(d.URI)
				s.Commit, s.Repository, s.Ref = c, firstNonEmpty(s.Repository, repo), firstNonEmpty(s.Ref, ref)
				break
			}
		}
		return s
	case PredicateSLSAv02:
		var p struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			BuildType  string `json:"buildType"`
			Invocation struct {
				ConfigSource struct {
					URI        string            `json:"uri"`
					Digest     map[string]string `json:"digest"`
					EntryPoint string            `json:"entryPoint"`
				} `json:"configSource"`
				Environment map[string]any `json:"environment"`
			} `json:"invocation"`
			Metadata struct {
				BuildInvocationID string `json:"buildInvocationId"`
			} `json:"metadata"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return nil
		}
		cs := p.Invocation.ConfigSource
		repo, ref := splitGitURI(cs.URI)
		event, _ := p.Invocation.Environment["GITHUB_EVENT_NAME"].(string)
		return &SLSAProvenance{
			Version: "v0.2", BuilderID: p.Builder.ID, BuildType: p.BuildType, Repository: repo, Ref: ref,
			Workflow: cs.EntryPoint, Commit: firstNonEmpty(cs.Digest["sha1"], cs.Digest["gitCommit"]),
			InvocationID: p.Metadata.BuildInvocationID, EventName: event,
		}
	}
	return nil
}

// splitGitURI splits "git+https://github.com/o/r@refs/heads/main" into the repository URL and the ref.
func splitGitURI(u string) (repo, ref string) {
	u = strings.TrimPrefix(u, "git+")
	if i := strings.LastIndex(u, "@"); i > strings.Index(u, "://")+2 {
		return u[:i], u[i+1:]
	}
	return u, ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
