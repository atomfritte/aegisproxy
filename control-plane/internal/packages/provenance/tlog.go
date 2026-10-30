package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"strings"
	"time"
)

// tlogEntry is a Rekor TransparencyLogEntry in protobuf JSON (bundle tlogEntries, PEP 740 transparency_entries).
type tlogEntry struct {
	LogIndex int64s `json:"logIndex"`
	LogID    struct {
		KeyID b64 `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   int64s `json:"integratedTime"`
	InclusionPromise *struct {
		SignedEntryTimestamp b64 `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof    *inclusionProof `json:"inclusionProof"`
	CanonicalizedBody b64             `json:"canonicalizedBody"`
}

type inclusionProof struct {
	LogIndex   int64s `json:"logIndex"`
	RootHash   b64    `json:"rootHash"`
	TreeSize   int64s `json:"treeSize"`
	Hashes     []b64  `json:"hashes"`
	Checkpoint *struct {
		Envelope string `json:"envelope"`
	} `json:"checkpoint"`
}

// verifyEntry verifies the log's commitments to an entry and returns the signed integrated time.
//
// The integrated time decides which certificate and key were valid, so it must be signed: only the signed entry
// timestamp (SET) covers it, an inclusion proof and its checkpoint do not. Entries without a SET (Rekor v2, which
// relies on RFC 3161 timestamps) are therefore rejected. When an inclusion proof is present it must verify as
// well; requireProof (bundles v0.2 and later) makes it mandatory.
func (o Options) verifyEntry(root *TrustedRoot, e *tlogEntry, requireProof bool) (time.Time, error) {
	if len(e.CanonicalizedBody) == 0 {
		return time.Time{}, failf(ErrMalformed, "transparency log entry has no body")
	}
	log := root.TransparencyLogs[hex.EncodeToString(e.LogID.KeyID)]
	if log == nil {
		return time.Time{}, failf(ErrTransparencyLog, "entry is from an unknown log %x", []byte(e.LogID.KeyID))
	}
	if e.InclusionPromise == nil || len(e.InclusionPromise.SignedEntryTimestamp) == 0 || e.IntegratedTime <= 0 {
		return time.Time{}, failf(ErrUnsupported, "entry has no signed entry timestamp (RFC 3161 timestamps are not supported)")
	}
	t := time.Unix(int64(e.IntegratedTime), 0).UTC()
	if t.After(o.now().Add(maxFutureSkew)) {
		return time.Time{}, failf(ErrTransparencyLog, "integrated time %s lies in the future", t.Format(time.RFC3339))
	}
	if !log.ValidFor.Contains(t) {
		return time.Time{}, failf(ErrTransparencyLog, "log key %s was not valid at %s", log.BaseURL, t.Format(time.RFC3339))
	}
	// SET: the log's signature over the canonical JSON of body, integrated time, log ID and (global) log index.
	// Keys are in RFC 8785 order; base64 and hex never need JSON escaping.
	set := `{"body":"` + base64.StdEncoding.EncodeToString(e.CanonicalizedBody) +
		`","integratedTime":` + strconv.FormatInt(int64(e.IntegratedTime), 10) +
		`,"logID":"` + hex.EncodeToString(e.LogID.KeyID) +
		`","logIndex":` + strconv.FormatInt(int64(e.LogIndex), 10) + `}`
	if !verifySignature(log.PublicKey, []byte(set), e.InclusionPromise.SignedEntryTimestamp) {
		return time.Time{}, failf(ErrTransparencyLog, "signed entry timestamp does not verify")
	}
	p := e.InclusionProof
	if p == nil {
		if requireProof {
			return time.Time{}, failf(ErrTransparencyLog, "inclusion proof missing")
		}
		return t, nil
	}
	if p.Checkpoint == nil || p.Checkpoint.Envelope == "" {
		if requireProof {
			return time.Time{}, failf(ErrTransparencyLog, "inclusion proof has no checkpoint")
		}
		return t, nil // v0.1: a root hash without a signed checkpoint proves nothing beyond the SET
	}
	if len(p.Hashes) > maxProofHashes {
		return time.Time{}, failf(ErrLimit, "inclusion proof has %d hashes", len(p.Hashes))
	}
	leaf := sha256.Sum256(append([]byte{0}, e.CanonicalizedBody...))
	if err := verifyInclusion(uint64(p.LogIndex), uint64(p.TreeSize), leaf[:], p.Hashes, p.RootHash); err != nil {
		return time.Time{}, err
	}
	if err := verifyCheckpoint(log, p.Checkpoint.Envelope, uint64(p.TreeSize), p.RootHash); err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// verifyInclusion checks an RFC 6962 / RFC 9162 (section 2.1.3.2) Merkle audit path from leaf to root.
func verifyInclusion(index, size uint64, leaf []byte, path []b64, root []byte) error {
	if index >= size || len(root) != sha256.Size {
		return failf(ErrTransparencyLog, "inclusion proof: index %d not in a tree of size %d", index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if len(p) != sha256.Size || sn == 0 {
			return failf(ErrTransparencyLog, "inclusion proof: malformed audit path")
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(r, root) {
		return failf(ErrTransparencyLog, "inclusion proof does not lead to the root hash")
	}
	return nil
}

func hashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

const maxCheckpointSize = 64 << 10

// verifyCheckpoint verifies a signed note checkpoint (origin, tree size, base64 root hash, optional extension
// lines, blank line, "— <name> <base64(key hash || signature)>" lines) with the log key and requires it to commit
// to the proof's tree size and root hash.
func verifyCheckpoint(log *TransparencyLog, note string, size uint64, root []byte) error {
	if len(note) > maxCheckpointSize {
		return failf(ErrLimit, "checkpoint too large")
	}
	i := strings.Index(note, "\n\n")
	if i < 0 {
		return failf(ErrTransparencyLog, "malformed checkpoint")
	}
	text, sigs := note[:i+1], note[i+2:]
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] == "" {
		return failf(ErrTransparencyLog, "malformed checkpoint")
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || n != size {
		return failf(ErrTransparencyLog, "checkpoint is for tree size %q, proof for %d", lines[1], size)
	}
	if h, err := base64.StdEncoding.DecodeString(lines[2]); err != nil || !bytes.Equal(h, root) {
		return failf(ErrTransparencyLog, "checkpoint root hash differs from the proof's root hash")
	}
	if !strings.HasSuffix(sigs, "\n") {
		return failf(ErrTransparencyLog, "malformed checkpoint signatures")
	}
	sigLines := strings.Split(strings.TrimSuffix(sigs, "\n"), "\n")
	if len(sigLines) > maxSignatures {
		return failf(ErrLimit, "checkpoint has %d signatures", len(sigLines))
	}
	for _, line := range sigLines {
		rest, ok := strings.CutPrefix(line, "— ")
		name, enc, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 || name == "" {
			return failf(ErrTransparencyLog, "malformed checkpoint signature line")
		}
		sig, err := base64.StdEncoding.DecodeString(enc)
		if err != nil || len(sig) < 5 {
			continue
		}
		if bytes.Equal(sig[:4], noteKeyHash(log, name)) && verifySignature(log.PublicKey, []byte(text), sig[4:]) {
			return nil
		}
	}
	return failf(ErrTransparencyLog, "checkpoint is not signed by %s", log.BaseURL)
}

// noteKeyHash is the 4-byte key hint of a signature line: for Ed25519 the C2SP signed-note key ID
// SHA-256(name || "\n" || 0x01 || key), for ECDSA (Rekor v1) the first bytes of SHA-256(DER key).
func noteKeyHash(log *TransparencyLog, name string) []byte {
	if k, ok := log.PublicKey.(ed25519.PublicKey); ok {
		h := sha256.Sum256(append(append([]byte(name+"\n"), 1), k...))
		return h[:4]
	}
	h := sha256.Sum256(log.DER)
	return h[:4]
}

// signer is what the log entry must name as the verifier: the Fulcio leaf certificate or a public key.
type signer struct {
	cert []byte // DER certificate
	spki []byte // DER SubjectPublicKeyInfo
}

type hashJSON struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// matchBody requires the log entry body to describe exactly this envelope and signer: the same payload (hash),
// the same signature and the same certificate or key. The envelope hashes in the bodies are not compared: they
// cover the client's JSON serialization of the envelope; the payload hash and the signature bind its content.
func matchBody(e *tlogEntry, env *envelope, s signer) error {
	var body struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Spec       json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(e.CanonicalizedBody, &body); err != nil {
		return failf(ErrMalformed, "transparency log entry body: %v", err)
	}
	if body.Kind != e.KindVersion.Kind || body.APIVersion != e.KindVersion.Version {
		return failf(ErrTransparencyLog, "entry body is %s %s, entry says %s %s", body.Kind, body.APIVersion, e.KindVersion.Kind, e.KindVersion.Version)
	}
	var payloadHash *hashJSON
	var logSig, verifier []byte
	switch body.Kind + " " + body.APIVersion {
	case "dsse 0.0.1":
		var spec struct {
			PayloadHash *hashJSON `json:"payloadHash"`
			Signatures  []struct {
				Signature b64 `json:"signature"`
				Verifier  b64 `json:"verifier"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(body.Spec, &spec); err != nil {
			return failf(ErrMalformed, "dsse entry: %v", err)
		}
		if len(spec.Signatures) != 1 {
			return failf(ErrTransparencyLog, "dsse entry has %d signatures, the envelope one", len(spec.Signatures))
		}
		payloadHash, logSig, verifier = spec.PayloadHash, spec.Signatures[0].Signature, spec.Signatures[0].Verifier
	case "intoto 0.0.2":
		var spec struct {
			Content struct {
				Envelope struct {
					PayloadType string `json:"payloadType"`
					Signatures  []struct {
						PublicKey b64 `json:"publicKey"`
						Sig       b64 `json:"sig"`
					} `json:"signatures"`
				} `json:"envelope"`
				PayloadHash *hashJSON `json:"payloadHash"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body.Spec, &spec); err != nil {
			return failf(ErrMalformed, "intoto entry: %v", err)
		}
		c := spec.Content
		if c.Envelope.PayloadType != env.payloadType {
			return failf(ErrTransparencyLog, "intoto entry payload type %q differs from the envelope's", c.Envelope.PayloadType)
		}
		if len(c.Envelope.Signatures) != 1 {
			return failf(ErrTransparencyLog, "intoto entry has %d signatures, the envelope one", len(c.Envelope.Signatures))
		}
		// intoto v0.0.2 stores the envelope's base64 signature text base64-encoded once more.
		raw, err := decodeB64(string(c.Envelope.Signatures[0].Sig))
		if err != nil {
			return failf(ErrMalformed, "intoto entry signature")
		}
		payloadHash, logSig, verifier = c.PayloadHash, raw, c.Envelope.Signatures[0].PublicKey
	default:
		return failf(ErrUnsupported, "transparency log entry kind %s %s", body.Kind, body.APIVersion)
	}
	sum := sha256.Sum256(env.payload)
	if payloadHash == nil || payloadHash.Algorithm != "sha256" || !strings.EqualFold(payloadHash.Value, hex.EncodeToString(sum[:])) {
		return failf(ErrTransparencyLog, "entry payload hash does not match the envelope payload")
	}
	if !bytes.Equal(logSig, env.sig) {
		return failf(ErrTransparencyLog, "entry signature differs from the envelope signature")
	}
	block, rest := pem.Decode(verifier)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return failf(ErrMalformed, "entry verifier is not a PEM block")
	}
	if s.cert != nil {
		if block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, s.cert) {
			return failf(ErrTransparencyLog, "entry was logged for a different certificate")
		}
	} else if block.Type != "PUBLIC KEY" || len(s.spki) == 0 || !bytes.Equal(block.Bytes, s.spki) {
		return failf(ErrTransparencyLog, "entry was logged for a different key")
	}
	return nil
}
