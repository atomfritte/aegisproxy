package provenance

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A synthetic Sigstore deployment (Fulcio CA, CT log, Rekor log) for the paths that real bundles cannot reach:
// an invalid DSSE signature that was logged consistently, missing or untrusted SCTs, validity windows, other key
// types and an Ed25519 (C2SP) checkpoint.

var synthTime = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

type synthPKI struct {
	root      *TrustedRoot
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	interKey  *ecdsa.PrivateKey
	interCert *x509.Certificate
	ctKey     *ecdsa.PrivateKey
	ctID      []byte
	logKey    crypto.Signer
	logID     []byte
}

func newSynthPKI(t *testing.T, ed25519Log bool) *synthPKI {
	t.Helper()
	p := &synthPKI{}
	p.caKey = mustKey(t, elliptic.P384())
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-root"},
		NotBefore: synthTime.AddDate(-5, 0, 0), NotAfter: synthTime.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	p.caCert = mustCert(t, caTmpl, caTmpl, &p.caKey.PublicKey, p.caKey)
	p.interKey = mustKey(t, elliptic.P384())
	p.interCert = mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-intermediate"},
		NotBefore: synthTime.AddDate(-5, 0, 0), NotAfter: synthTime.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}, p.caCert, &p.interKey.PublicKey, p.caKey)
	p.ctKey = mustKey(t, elliptic.P256())
	ctDER, _ := x509.MarshalPKIXPublicKey(&p.ctKey.PublicKey)
	ctSum := sha256.Sum256(ctDER)
	p.ctID = ctSum[:]
	if ed25519Log {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		p.logKey = k
	} else {
		p.logKey = mustKey(t, elliptic.P256())
	}
	logDER, _ := x509.MarshalPKIXPublicKey(p.logKey.Public())
	logSum := sha256.Sum256(logDER)
	p.logID = logSum[:]
	p.root = &TrustedRoot{
		CertificateAuthorities: []CertificateAuthority{{Root: p.caCert, Intermediates: []*x509.Certificate{p.interCert}, ValidFor: TimeRange{Start: synthTime.AddDate(-1, 0, 0)}}},
		TransparencyLogs:       map[string]*TransparencyLog{hex.EncodeToString(p.logID): {BaseURL: "https://log.test", LogID: p.logID, PublicKey: p.logKey.Public(), DER: logDER, ValidFor: TimeRange{Start: synthTime.AddDate(-1, 0, 0)}}},
		CTLogs:                 map[string]*TransparencyLog{hex.EncodeToString(p.ctID): {BaseURL: "https://ct.test", LogID: p.ctID, PublicKey: &p.ctKey.PublicKey, DER: ctDER, ValidFor: TimeRange{Start: synthTime.AddDate(-1, 0, 0)}}},
	}
	return p
}

func mustKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sign(t *testing.T, key crypto.Signer, msg []byte) []byte {
	t.Helper()
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg)
	case *ecdsa.PrivateKey:
		var d []byte
		switch k.Curve {
		case elliptic.P384():
			h := sha512.Sum384(msg)
			d = h[:]
		default:
			h := sha256.Sum256(msg)
			d = h[:]
		}
		s, err := ecdsa.SignASN1(rand.Reader, k, d)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Fatalf("key %T", key)
	return nil
}

func utf8Ext(t *testing.T, n int, v string) pkix.Extension {
	b, err := asn1.MarshalWithParams(v, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: append(append(asn1.ObjectIdentifier{}, oidFulcio...), n), Value: b}
}

type leafSpec struct {
	key       crypto.Signer
	notBefore time.Time
	eku       x509.ExtKeyUsage
	noSCT     bool
	serial    int64
}

// leaf issues a Fulcio-like certificate with an SCT over its precertificate (the same TBSCertificate without
// the SCT list extension).
func (p *synthPKI) leaf(t *testing.T, s leafSpec) []byte {
	t.Helper()
	u, _ := url.Parse("https://github.com/o/r/.github/workflows/release.yml@refs/heads/main")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100 + s.serial), NotBefore: s.notBefore, NotAfter: s.notBefore.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{s.eku}, URIs: []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: append(append(asn1.ObjectIdentifier{}, oidFulcio...), 1), Value: []byte("https://token.actions.githubusercontent.com")},
			utf8Ext(t, 8, "https://token.actions.githubusercontent.com"),
			utf8Ext(t, 12, "https://github.com/o/r"),
			utf8Ext(t, 13, "0123456789abcdef0123456789abcdef01234567"),
			utf8Ext(t, 14, "refs/heads/main"),
			utf8Ext(t, 18, "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main"),
			utf8Ext(t, 99, "future"),
		},
	}
	pre := mustCert(t, tmpl, p.interCert, s.key.Public(), p.interKey)
	if s.noSCT {
		return pre.Raw
	}
	keyHash := sha256.Sum256(p.interCert.RawSubjectPublicKeyInfo)
	ts := uint64(s.notBefore.UnixMilli())
	tbs := pre.RawTBSCertificate
	msg := []byte{0, 0}
	msg = binary.BigEndian.AppendUint64(msg, ts)
	msg = append(msg, 0, 1)
	msg = append(msg, keyHash[:]...)
	msg = append(msg, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
	msg = append(msg, tbs...)
	msg = append(msg, 0, 0)
	sig := sign(t, p.ctKey, msg)
	one := append([]byte{0}, p.ctID...)
	one = binary.BigEndian.AppendUint64(one, ts)
	one = append(one, 0, 0, 4, 3)
	one = binary.BigEndian.AppendUint16(one, uint16(len(sig)))
	one = append(one, sig...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(one)+2))
	list = binary.BigEndian.AppendUint16(list, uint16(len(one)))
	list = append(list, one...)
	ext, _ := asn1.Marshal(list)
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidSCTList, Value: ext})
	return mustCert(t, tmpl, p.interCert, s.key.Public(), p.interKey).Raw
}

func mth(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return hashChildren(mth(leaves[:k]), mth(leaves[k:]))
}

func auditPath(m int, leaves [][]byte) []b64 {
	if len(leaves) == 1 {
		return nil
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	if m < k {
		return append(auditPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(auditPath(m-k, leaves[k:]), mth(leaves[:k]))
}

type bundleSpec struct {
	leafDER    []byte
	leafKey    crypto.Signer
	statement  []byte
	badSig     bool   // sign another message, but log the signature consistently
	verifier   []byte // certificate the log entry names (default: the leaf)
	integrated time.Time
}

// bundle assembles a v0.3 bundle: DSSE envelope, dsse v0.0.1 entry with SET, inclusion proof (index 5 of 7)
// and checkpoint.
func (p *synthPKI) bundle(t *testing.T, s bundleSpec) []byte {
	t.Helper()
	msg := pae(InTotoPayloadType, s.statement)
	if s.badSig {
		msg = pae(InTotoPayloadType, []byte("something else"))
	}
	sig := sign(t, s.leafKey, msg)
	verifier := s.verifier
	if verifier == nil {
		verifier = s.leafDER
	}
	ph := sha256.Sum256(s.statement)
	body, _ := json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": "dsse", "spec": map[string]any{
		"envelopeHash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(make([]byte, 32))},
		"payloadHash":  map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(ph[:])},
		"signatures": []map[string]any{{
			"signature": sig, "verifier": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: verifier}),
		}},
	}})
	const logIndex, treeIndex, treeSize = 4242, 5, 7
	set := `{"body":"` + base64.StdEncoding.EncodeToString(body) + `","integratedTime":` + itoa(s.integrated.Unix()) +
		`,"logID":"` + hex.EncodeToString(p.logID) + `","logIndex":` + itoa(logIndex) + `}`
	leaves := make([][]byte, treeSize)
	for i := range leaves {
		h := sha256.Sum256(append([]byte{0}, byte(i)))
		leaves[i] = h[:]
	}
	lh := sha256.Sum256(append([]byte{0}, body...))
	leaves[treeIndex] = lh[:]
	rootHash := mth(leaves)
	text := "log.test - 1\n" + itoa(treeSize) + "\n" + base64.StdEncoding.EncodeToString(rootHash) + "\n"
	note := text + "\n— log.test " + base64.StdEncoding.EncodeToString(append(noteKeyHash(p.root.TransparencyLogs[hex.EncodeToString(p.logID)], "log.test"), sign(t, p.logKey, []byte(text))...)) + "\n"
	b, _ := json.Marshal(map[string]any{
		"mediaType": bundleMediaTypeV03Long,
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": s.leafDER},
			"tlogEntries": []map[string]any{{
				"logIndex": itoa(logIndex), "logId": map[string]any{"keyId": p.logID},
				"kindVersion": map[string]string{"kind": "dsse", "version": "0.0.1"}, "integratedTime": itoa(s.integrated.Unix()),
				"inclusionPromise": map[string]any{"signedEntryTimestamp": sign(t, p.logKey, []byte(set))},
				"inclusionProof": map[string]any{
					"logIndex": itoa(treeIndex), "rootHash": rootHash, "treeSize": itoa(treeSize),
					"hashes": auditPath(treeIndex, leaves), "checkpoint": map[string]string{"envelope": note},
				},
				"canonicalizedBody": body,
			}},
		},
		"dsseEnvelope": map[string]any{"payload": s.statement, "payloadType": InTotoPayloadType, "signatures": []map[string]any{{"sig": sig}}},
	})
	return b
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func synthStatement(digests ...string) []byte {
	var subjects []map[string]any
	for i, d := range digests {
		subjects = append(subjects, map[string]any{"name": "artifact-" + itoa(int64(i)), "digest": map[string]string{"sha256": d}})
	}
	b, _ := json.Marshal(map[string]any{"_type": inTotoStatementV1, "subject": subjects, "predicateType": PredicateSLSAv1, "predicate": map[string]any{}})
	return b
}

func TestSyntheticBundles(t *testing.T) {
	digest := hex.EncodeToString(make([]byte, 32))
	other := "ff" + digest[2:]
	want := Digest{Algorithm: "sha256", Value: digest}
	cases := []struct {
		name    string
		ed25519 bool // Rekor key (SET and checkpoint)
		leafKey func(t *testing.T) crypto.Signer
		leaf    func(p *synthPKI, l *leafSpec)
		bundle  func(t *testing.T, p *synthPKI, b *bundleSpec)
		root    func(p *synthPKI)
		opts    Options
		err     error
	}{
		{name: "valid, ECDSA log"},
		{name: "valid, Ed25519 log", ed25519: true},
		{name: "valid, P-384 leaf", leafKey: func(t *testing.T) crypto.Signer { return mustKey(t, elliptic.P384()) }},
		{name: "valid, Ed25519 leaf", leafKey: func(t *testing.T) crypto.Signer { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }},
		{name: "valid, digest on second subject", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) { b.statement = synthStatement(other, digest) }},
		{name: "fixture keeps verifying in the future", opts: Options{Now: func() time.Time { return synthTime.AddDate(20, 0, 0) }}},
		{name: "invalid DSSE signature, consistently logged", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) { b.badSig = true }, err: ErrInvalidSignature},
		{name: "no SCT", leaf: func(p *synthPKI, l *leafSpec) { l.noSCT = true }, err: ErrUntrustedCert},
		{name: "SCT from an unknown CT log", root: func(p *synthPKI) { p.root.CTLogs = map[string]*TransparencyLog{} }, err: ErrUntrustedCert},
		{name: "CT log not valid at SCT time", root: func(p *synthPKI) {
			for _, l := range p.root.CTLogs {
				l.ValidFor.End = synthTime.AddDate(0, -1, 0)
			}
		}, err: ErrUntrustedCert},
		{name: "integrated after certificate expiry", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) { b.integrated = synthTime.Add(11 * time.Minute) }, err: ErrUntrustedCert},
		{name: "integrated before certificate validity", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) { b.integrated = synthTime.Add(-2 * time.Minute) }, err: ErrUntrustedCert},
		{name: "CA window closed", root: func(p *synthPKI) { p.root.CertificateAuthorities[0].ValidFor.End = synthTime.Add(-time.Hour) }, err: ErrUntrustedCert},
		{name: "Rekor key window closed", root: func(p *synthPKI) {
			for _, l := range p.root.TransparencyLogs {
				l.ValidFor.End = synthTime.Add(-time.Hour)
			}
		}, err: ErrTransparencyLog},
		{name: "server-auth leaf", leaf: func(p *synthPKI, l *leafSpec) { l.eku = x509.ExtKeyUsageServerAuth }, err: ErrUntrustedCert},
		{name: "entry logged for another certificate", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) {
			b.verifier = p.leaf(t, leafSpec{key: mustKey(t, elliptic.P256()), notBefore: synthTime.Add(-time.Minute), eku: x509.ExtKeyUsageCodeSigning, serial: 1})
		}, err: ErrTransparencyLog},
		{name: "integrated time in the future", opts: Options{Now: func() time.Time { return synthTime.Add(-time.Hour) }}, err: ErrTransparencyLog},
		{name: "subject digest differs", bundle: func(t *testing.T, p *synthPKI, b *bundleSpec) { b.statement = synthStatement(other) }, err: ErrSubjectMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newSynthPKI(t, c.ed25519)
			key := crypto.Signer(mustKey(t, elliptic.P256()))
			if c.leafKey != nil {
				key = c.leafKey(t)
			}
			ls := leafSpec{key: key, notBefore: synthTime.Add(-time.Minute), eku: x509.ExtKeyUsageCodeSigning}
			if c.leaf != nil {
				c.leaf(p, &ls)
			}
			bs := bundleSpec{leafDER: p.leaf(t, ls), leafKey: key, statement: synthStatement(digest), integrated: synthTime}
			if c.bundle != nil {
				c.bundle(t, p, &bs)
			}
			if c.root != nil {
				c.root(p)
			}
			r, err := c.opts.VerifyBundle(p.bundle(t, bs), p.root, want)
			if c.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				if r.Identity.Source().Repository != "https://github.com/o/r" || r.Identity.Other["1.3.6.1.4.1.57264.1.99"] != "future" || !r.IntegratedTime.Equal(synthTime) {
					t.Errorf("result: %+v %+v", r, r.Identity)
				}
				return
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("got %v, want %v", err, c.err)
			}
		})
	}
}

// TestVerifyInclusionAllShapes checks every leaf of trees up to 70 leaves against a reference implementation
// (RFC 6962 section 2.1.1). The tree size itself is bound by the signed checkpoint, not by the path.
func TestVerifyInclusionAllShapes(t *testing.T) {
	for size := 1; size <= 70; size++ {
		leaves := make([][]byte, size)
		for i := range leaves {
			h := sha256.Sum256([]byte{0, byte(i), byte(size)})
			leaves[i] = h[:]
		}
		root := mth(leaves)
		for i := range leaves {
			path := auditPath(i, leaves)
			if err := verifyInclusion(uint64(i), uint64(size), leaves[i], path, root); err != nil {
				t.Fatalf("size %d index %d: %v", size, i, err)
			}
			if size > 1 {
				if err := verifyInclusion(uint64((i+1)%size), uint64(size), leaves[i], path, root); err == nil {
					t.Fatalf("size %d index %d: wrong index accepted", size, i)
				}
				if err := verifyInclusion(uint64(i), uint64(size), leaves[i], path[:len(path)-1], root); err == nil {
					t.Fatalf("size %d index %d: short path accepted", size, i)
				}
				bad := append([]b64{}, path...)
				bad[0] = append([]byte{bad[0][0] ^ 1}, bad[0][1:]...)
				if err := verifyInclusion(uint64(i), uint64(size), leaves[i], bad, root); err == nil {
					t.Fatalf("size %d index %d: tampered path accepted", size, i)
				}
			}
			if err := verifyInclusion(uint64(i), uint64(size), leaves[i], append(path, root), root); err == nil {
				t.Fatalf("size %d index %d: long path accepted", size, i)
			}
		}
	}
	if err := verifyInclusion(3, 3, make([]byte, 32), nil, make([]byte, 32)); err == nil {
		t.Error("index beyond the tree accepted")
	}
}

func TestPAE(t *testing.T) {
	// Example from the DSSE protocol specification.
	if got := string(pae("http://example.com/HelloWorld", []byte("hello world"))); got != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Errorf("PAE = %q", got)
	}
}

func TestPublicGoodTrustedRoot(t *testing.T) {
	r, err := PublicGoodTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.CertificateAuthorities) != 2 || len(r.TransparencyLogs) != 2 || len(r.CTLogs) != 2 {
		t.Fatalf("CAs %d, Rekor logs %d, CT logs %d", len(r.CertificateAuthorities), len(r.TransparencyLogs), len(r.CTLogs))
	}
	rekor := r.TransparencyLogs["c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"]
	if rekor == nil || rekor.BaseURL != "https://rekor.sigstore.dev" {
		t.Fatal("rekor.sigstore.dev missing")
	}
	// Rekor v1 and CT log IDs are the SHA-256 of the DER key.
	for _, l := range append([]*TransparencyLog{rekor}, values(r.CTLogs)...) {
		if sum := sha256.Sum256(l.DER); hex.EncodeToString(sum[:]) != hex.EncodeToString(l.LogID) {
			t.Errorf("%s: log ID is not SHA-256(DER)", l.BaseURL)
		}
	}
	if _, err := ParseTrustedRoot([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty root: %v", err)
	}
	if _, err := ParseTrustedRoot([]byte(`{"mediaType":"text/plain"}`)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("media type: %v", err)
	}
}

func values(m map[string]*TransparencyLog) []*TransparencyLog {
	var out []*TransparencyLog
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestCheckpointParsing(t *testing.T) {
	p := newSynthPKI(t, true)
	log := p.root.TransparencyLogs[hex.EncodeToString(p.logID)]
	root := make([]byte, 32)
	text := "log.test - 1\n7\n" + base64.StdEncoding.EncodeToString(root) + "\nTimestamp: 1\n"
	line := func(name string, text string) string {
		return "— " + name + " " + base64.StdEncoding.EncodeToString(append(noteKeyHash(log, name), sign(t, p.logKey, []byte(text))...)) + "\n"
	}
	cases := map[string]struct {
		note string
		ok   bool
	}{
		"valid with extension line": {text + "\n" + line("log.test", text), true},
		"foreign signature first":   {text + "\n— other AAAAAAAA\n" + line("log.test", text), true},
		"key hint bound to name":    {text + "\n" + "— other " + line("log.test", text)[len("— log.test "):], false},
		"signature over other text": {text + "\n" + line("log.test", "x"), false},
		"no signature":              {text + "\n", false},
		"no blank line":             {text + line("log.test", text), false},
		"wrong tree size":           {"log.test - 1\n8\n" + base64.StdEncoding.EncodeToString(root) + "\n\n" + line("log.test", "log.test - 1\n8\n"+base64.StdEncoding.EncodeToString(root)+"\n"), false},
		"missing trailing newline":  {text + "\n" + line("log.test", text)[:len(line("log.test", text))-1], false},
		"garbage signature line":    {text + "\n" + "garbage\n", false},
		"too many signatures":       {text + "\n" + strings.Repeat("— other AAAAAAAA\n", maxSignatures+1), false},
		"oversized":                 {strings.Repeat("x", maxCheckpointSize+1), false},
		"empty":                     {"", false},
	}
	for name, c := range cases {
		err := verifyCheckpoint(log, c.note, 7, root)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := append([]byte{1}, root[1:]...)
	if err := verifyCheckpoint(log, text+"\n"+line("log.test", text), 7, other); err == nil {
		t.Error("checkpoint for another root hash accepted")
	}
	// Rekor v1 (ECDSA): the key hint is the start of SHA-256(DER key), whatever the name.
	p = newSynthPKI(t, false)
	log = p.root.TransparencyLogs[hex.EncodeToString(p.logID)]
	if err := verifyCheckpoint(log, text+"\n"+line("any.name", text), 7, root); err != nil || !bytes.Equal(noteKeyHash(log, "x"), p.logID[:4]) {
		t.Errorf("ECDSA checkpoint: %v", err)
	}
}

func TestCheckPublisher(t *testing.T) {
	github := Identity{
		SAN: "https://github.com/o/shared/.github/workflows/reusable.yml@refs/heads/main", issuerV2: "https://token.actions.githubusercontent.com",
		SourceRepositoryURI: "https://github.com/o/r", SourceRepositoryDigest: "abc", SourceRepositoryRef: "refs/tags/v1",
		BuildConfigURI: "https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1",
	}
	gitlab := Identity{
		issuerV2: "https://gitlab.com", SourceRepositoryURI: "https://gitlab.com/g/sub/p", SourceRepositoryDigest: "abc",
		SourceRepositoryRef: "refs/heads/main", BuildConfigURI: "https://gitlab.com/g/sub/p//ci/release.yml@abc",
	}
	google := Identity{SAN: "release@p.iam.gserviceaccount.com", Issuer: "https://accounts.google.com"}
	circle := Identity{
		issuerV2: "https://oidc.circleci.com", SourceRepositoryURI: "github.com/o/r", SourceRepositoryRef: "refs/heads/main",
		BuildSignerURI: "https://circleci.com/api/v2/projects/p1/pipeline-definitions/d1",
	}
	without := func(id Identity, f func(i *Identity)) Identity { f(&id); return id }
	cases := []struct {
		name string
		p    PyPIPublisher
		id   Identity
		err  error
	}{
		// The build config is the caller's workflow even when the SAN names a reusable workflow elsewhere.
		{"GitHub via reusable workflow", PyPIPublisher{Kind: "GitHub", Repository: "o/r", Workflow: "release.yml"}, github, nil},
		{"GitHub other workflow", PyPIPublisher{Kind: "GitHub", Repository: "o/r", Workflow: "reusable.yml"}, github, ErrIdentityMismatch},
		{"GitHub without ref or digest", PyPIPublisher{Kind: "GitHub", Repository: "o/r", Workflow: "release.yml"},
			without(github, func(i *Identity) { i.SourceRepositoryDigest, i.SourceRepositoryRef = "", "" }), ErrIdentityMismatch},
		{"GitHub legacy issuer only", PyPIPublisher{Kind: "GitHub", Repository: "o/r", Workflow: "release.yml"},
			without(github, func(i *Identity) { i.issuerV2, i.Issuer = "", "https://token.actions.githubusercontent.com" }), ErrIdentityMismatch},
		{"GitLab", PyPIPublisher{Kind: "GitLab", Repository: "g/sub/p", WorkflowFilepath: "ci/release.yml"}, gitlab, nil},
		{"GitLab other project", PyPIPublisher{Kind: "GitLab", Repository: "g/p", WorkflowFilepath: "ci/release.yml"}, gitlab, ErrIdentityMismatch},
		{"GitLab other file", PyPIPublisher{Kind: "GitLab", Repository: "g/sub/p", WorkflowFilepath: ".gitlab-ci.yml"}, gitlab, ErrIdentityMismatch},
		{"Google", PyPIPublisher{Kind: "Google", Email: "release@p.iam.gserviceaccount.com"}, google, nil},
		{"Google other account", PyPIPublisher{Kind: "Google", Email: "other@p.iam.gserviceaccount.com"}, google, ErrIdentityMismatch},
		{"CircleCI", PyPIPublisher{Kind: "CircleCI", ProjectID: "p1", PipelineDefinitionID: "d1", VCSOrigin: "github.com/o/r", VCSRef: "refs/heads/main"}, circle, nil},
		{"CircleCI other pipeline", PyPIPublisher{Kind: "CircleCI", ProjectID: "p1", PipelineDefinitionID: "d2"}, circle, ErrIdentityMismatch},
		{"CircleCI other ref", PyPIPublisher{Kind: "CircleCI", ProjectID: "p1", PipelineDefinitionID: "d1", VCSRef: "refs/heads/dev"}, circle, ErrIdentityMismatch},
		{"unknown kind", PyPIPublisher{Kind: "Jenkins"}, github, ErrUnsupported},
	}
	for _, c := range cases {
		err := checkPublisher(&c.p, &c.id)
		if (c.err == nil && err != nil) || (c.err != nil && !errors.Is(err, c.err)) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}
}
