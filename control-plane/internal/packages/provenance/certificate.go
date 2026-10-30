package provenance

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
	"unicode/utf8"
)

// verifyLeaf checks a Fulcio leaf certificate against the trusted CAs at time t (the signed integrated time:
// Fulcio certificates are valid for ten minutes) and returns the certificate that issued it.
func (r *TrustedRoot) verifyLeaf(leaf *x509.Certificate, t time.Time) (*x509.Certificate, error) {
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, failf(ErrUntrustedCert, "leaf certificate is a CA or lacks the digitalSignature key usage")
	}
	var lastErr error
	for _, ca := range r.CertificateAuthorities {
		if !ca.ValidFor.Contains(t) {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.Root)
		inter := x509.NewCertPool()
		for _, c := range ca.Intermediates {
			inter.AddCert(c)
		}
		// Only the leaf comes from the bundle; intermediates a bundle carries are ignored.
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter, CurrentTime: t, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		if err != nil {
			lastErr = err
			continue
		}
		if len(chains) > 0 && len(chains[0]) >= 2 {
			return chains[0][1], nil
		}
	}
	if lastErr != nil {
		return nil, failf(ErrUntrustedCert, "%v", lastErr)
	}
	return nil, failf(ErrUntrustedCert, "no Fulcio certificate authority was valid at %s", t.Format(time.RFC3339))
}

var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

const maxSCTs = 16

type sct struct {
	logID     []byte
	timestamp uint64 // milliseconds
	ext       []byte
	hashAlg   byte
	sig       []byte
}

// verifySCTs requires at least one valid embedded signed certificate timestamp from a CT log of the trusted
// root (RFC 6962 section 3.2: the log signed the precertificate, i.e. the leaf's TBSCertificate without the
// SCT list extension, together with the hash of the issuer's public key).
func (r *TrustedRoot) verifySCTs(leaf, issuer *x509.Certificate) error {
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSCTList) {
			ext = e.Value
		}
	}
	if ext == nil {
		return failf(ErrUntrustedCert, "certificate has no embedded SCT")
	}
	var list []byte
	if rest, err := asn1.Unmarshal(ext, &list); err != nil || len(rest) != 0 {
		return failf(ErrUntrustedCert, "malformed SCT list extension")
	}
	scts, err := parseSCTList(list)
	if err != nil {
		return failf(ErrUntrustedCert, "%v", err)
	}
	tbs, err := removeExtension(leaf.RawTBSCertificate, oidSCTList)
	if err != nil {
		return failf(ErrUntrustedCert, "precertificate: %v", err)
	}
	if len(tbs) >= 1<<24 {
		return failf(ErrLimit, "certificate too large")
	}
	keyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	for _, s := range scts {
		log := r.CTLogs[hex.EncodeToString(s.logID)]
		if log == nil || s.hashAlg != 4 /* sha256 */ || s.timestamp > uint64(1)<<62 {
			continue
		}
		if !log.ValidFor.Contains(time.UnixMilli(int64(s.timestamp))) {
			continue
		}
		msg := make([]byte, 0, 2+8+2+32+3+len(tbs)+2+len(s.ext))
		msg = append(msg, 0, 0) // sct_version v1, signature_type certificate_timestamp
		msg = binary.BigEndian.AppendUint64(msg, s.timestamp)
		msg = append(msg, 0, 1) // entry_type precert_entry
		msg = append(msg, keyHash[:]...)
		msg = append(msg, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		msg = append(msg, tbs...)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(s.ext)))
		msg = append(msg, s.ext...)
		if verifySignature(log.PublicKey, msg, s.sig) {
			return nil
		}
	}
	return failf(ErrUntrustedCert, "no valid SCT from a trusted certificate transparency log")
}

// parseSCTList parses a TLS-encoded SignedCertificateTimestampList (RFC 6962 section 3.3).
func parseSCTList(b []byte) ([]sct, error) {
	if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		return nil, failf(ErrMalformed, "SCT list length")
	}
	b = b[2:]
	var out []sct
	for len(b) > 0 {
		if len(out) == maxSCTs {
			return nil, failf(ErrLimit, "more than %d SCTs", maxSCTs)
		}
		if len(b) < 2 {
			return nil, failf(ErrMalformed, "SCT length")
		}
		n := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+n {
			return nil, failf(ErrMalformed, "SCT length")
		}
		s, err := parseSCT(b[2 : 2+n])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		b = b[2+n:]
	}
	return out, nil
}

func parseSCT(b []byte) (sct, error) {
	bad := failf(ErrMalformed, "malformed SCT")
	if len(b) < 1+32+8+2 || b[0] != 0 {
		return sct{}, bad
	}
	s := sct{logID: b[1:33], timestamp: binary.BigEndian.Uint64(b[33:41])}
	n := int(binary.BigEndian.Uint16(b[41:43]))
	b = b[43:]
	if len(b) < n+4 {
		return sct{}, bad
	}
	s.ext, b = b[:n], b[n:]
	s.hashAlg = b[0] // b[1] is the signature algorithm; the log's key type decides
	n = int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) != 4+n {
		return sct{}, bad
	}
	s.sig = b[4:]
	return s, nil
}

// removeExtension re-encodes a DER TBSCertificate without the extension oid; every other element is kept
// byte-for-byte.
func removeExtension(rawTBS []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	var tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(rawTBS, &tbs); err != nil || len(rest) != 0 || tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence {
		return nil, failf(ErrMalformed, "TBSCertificate")
	}
	var out []byte
	removed := false
	for elems := tbs.Bytes; len(elems) > 0; {
		var el asn1.RawValue
		var err error
		if elems, err = asn1.Unmarshal(elems, &el); err != nil {
			return nil, failf(ErrMalformed, "TBSCertificate element")
		}
		if el.Class != asn1.ClassContextSpecific || el.Tag != 3 { // extensions [3] EXPLICIT
			out = append(out, el.FullBytes...)
			continue
		}
		var exts asn1.RawValue
		if rest, err := asn1.Unmarshal(el.Bytes, &exts); err != nil || len(rest) != 0 || exts.Tag != asn1.TagSequence {
			return nil, failf(ErrMalformed, "extensions")
		}
		var kept []byte
		for es := exts.Bytes; len(es) > 0; {
			var ext asn1.RawValue
			if es, err = asn1.Unmarshal(es, &ext); err != nil {
				return nil, failf(ErrMalformed, "extension")
			}
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Bytes, &id); err != nil {
				return nil, failf(ErrMalformed, "extension id")
			}
			if id.Equal(oid) {
				removed = true
				continue
			}
			kept = append(kept, ext.FullBytes...)
		}
		seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
		if err != nil {
			return nil, err
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: seq})
		if err != nil {
			return nil, err
		}
		out = append(out, wrapped...)
	}
	if !removed {
		return nil, failf(ErrMalformed, "extension %s not present", oid)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: out})
}

// Identity is the signer identity that Fulcio certified (from the verified leaf certificate). Field comments
// name the Fulcio extension (OID 1.3.6.1.4.1.57264.1.N).
type Identity struct {
	SAN                             string `json:"san"`                                          // URI or email subject alternative name
	Issuer                          string `json:"issuer"`                                       // OIDC issuer: .8, falling back to the legacy .1
	BuildSignerURI                  string `json:"build_signer_uri"`                             // .9
	BuildSignerDigest               string `json:"build_signer_digest,omitempty"`                // .10
	RunnerEnvironment               string `json:"runner_environment,omitempty"`                 // .11
	SourceRepositoryURI             string `json:"source_repository_uri,omitempty"`              // .12
	SourceRepositoryDigest          string `json:"source_repository_digest,omitempty"`           // .13
	SourceRepositoryRef             string `json:"source_repository_ref,omitempty"`              // .14
	SourceRepositoryIdentifier      string `json:"source_repository_identifier,omitempty"`       // .15
	SourceRepositoryOwnerURI        string `json:"source_repository_owner_uri,omitempty"`        // .16
	SourceRepositoryOwnerIdentifier string `json:"source_repository_owner_identifier,omitempty"` // .17
	BuildConfigURI                  string `json:"build_config_uri,omitempty"`                   // .18
	BuildConfigDigest               string `json:"build_config_digest,omitempty"`                // .19
	BuildTrigger                    string `json:"build_trigger,omitempty"`                      // .20
	RunInvocationURI                string `json:"run_invocation_uri,omitempty"`                 // .21
	SourceRepositoryVisibility      string `json:"source_repository_visibility,omitempty"`       // .22
	// Legacy GitHub Actions extensions (.2–.6), kept by Fulcio for compatibility.
	GitHubWorkflowTrigger    string `json:"github_workflow_trigger,omitempty"`
	GitHubWorkflowSHA        string `json:"github_workflow_sha,omitempty"`
	GitHubWorkflowName       string `json:"github_workflow_name,omitempty"`
	GitHubWorkflowRepository string `json:"github_workflow_repository,omitempty"`
	GitHubWorkflowRef        string `json:"github_workflow_ref,omitempty"`
	// Other holds Fulcio extensions without a field above, keyed by dotted OID.
	Other map[string]string `json:"other,omitempty"`

	issuerV2 string
}

// Source is the build origin as the certificate states it.
type Source struct {
	Repository string `json:"repository"` // e.g. https://github.com/npm/node-semver
	Commit     string `json:"commit"`
	Ref        string `json:"ref,omitempty"`
	Workflow   string `json:"workflow,omitempty"` // build configuration (workflow file) URI
}

// Source returns the source repository, commit, ref and workflow, preferring the current Fulcio extensions over
// the legacy GitHub ones.
func (id *Identity) Source() Source {
	s := Source{Repository: id.SourceRepositoryURI, Commit: id.SourceRepositoryDigest, Ref: id.SourceRepositoryRef, Workflow: id.BuildConfigURI}
	if s.Repository == "" && id.GitHubWorkflowRepository != "" {
		s.Repository = "https://github.com/" + id.GitHubWorkflowRepository
	}
	if s.Commit == "" {
		s.Commit = id.GitHubWorkflowSHA
	}
	if s.Ref == "" {
		s.Ref = id.GitHubWorkflowRef
	}
	if s.Workflow == "" {
		s.Workflow = id.SAN
	}
	return s
}

var oidFulcio = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1}

func identityFromCert(c *x509.Certificate) (*Identity, error) {
	id := &Identity{}
	switch {
	case len(c.URIs) == 1 && len(c.EmailAddresses) == 0:
		id.SAN = c.URIs[0].String()
	case len(c.EmailAddresses) == 1 && len(c.URIs) == 0:
		id.SAN = c.EmailAddresses[0]
	default:
		return nil, failf(ErrUntrustedCert, "certificate must carry exactly one URI or email SAN")
	}
	var issuerV1 string
	for _, e := range c.Extensions {
		if len(e.Id) != len(oidFulcio)+1 || !e.Id[:len(oidFulcio)].Equal(oidFulcio) {
			continue
		}
		n := e.Id[len(oidFulcio)]
		var v string
		if n <= 6 {
			// The deprecated extensions hold the raw string as the extension value.
			if !utf8.Valid(e.Value) {
				continue
			}
			v = string(e.Value)
		} else {
			// Since .8 the value is a DER UTF8String.
			if rest, err := asn1.UnmarshalWithParams(e.Value, &v, "utf8"); err != nil || len(rest) != 0 {
				continue
			}
		}
		switch n {
		case 1:
			issuerV1 = v
		case 2:
			id.GitHubWorkflowTrigger = v
		case 3:
			id.GitHubWorkflowSHA = v
		case 4:
			id.GitHubWorkflowName = v
		case 5:
			id.GitHubWorkflowRepository = v
		case 6:
			id.GitHubWorkflowRef = v
		case 7: // OtherName SAN (DER), not a string
		case 8:
			id.issuerV2 = v
		case 9:
			id.BuildSignerURI = v
		case 10:
			id.BuildSignerDigest = v
		case 11:
			id.RunnerEnvironment = v
		case 12:
			id.SourceRepositoryURI = v
		case 13:
			id.SourceRepositoryDigest = v
		case 14:
			id.SourceRepositoryRef = v
		case 15:
			id.SourceRepositoryIdentifier = v
		case 16:
			id.SourceRepositoryOwnerURI = v
		case 17:
			id.SourceRepositoryOwnerIdentifier = v
		case 18:
			id.BuildConfigURI = v
		case 19:
			id.BuildConfigDigest = v
		case 20:
			id.BuildTrigger = v
		case 21:
			id.RunInvocationURI = v
		case 22:
			id.SourceRepositoryVisibility = v
		default:
			if id.Other == nil {
				id.Other = map[string]string{}
			}
			id.Other[oidFulcio.String()+"."+strconv.Itoa(n)] = v
		}
	}
	id.Issuer = id.issuerV2
	if id.Issuer == "" {
		id.Issuer = issuerV1
	}
	if id.Issuer == "" {
		return nil, failf(ErrUntrustedCert, "certificate has no OIDC issuer extension")
	}
	return id, nil
}
