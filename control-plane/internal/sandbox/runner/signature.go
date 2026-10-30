package runner

import (
	"crypto/x509"
	"encoding/base64"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// ScanSignatures finds and parses the signatures embedded in an artifact: a NuGet .signature.p7s (PKCS#7 /
// CMS SignedData) and Authenticode signature blocks appended to PowerShell .ps1/.psm1 files. It reports the
// end-entity signer subject + issuer. Verified is left nil: cryptographic verification against a trusted root is
// the control-plane's job (or, for NuGet, `dotnet nuget verify` when the image can run it offline).
func ScanSignatures(root string, files []sandbox.File) []sandbox.Signature {
	var sigs []sandbox.Signature
	for _, f := range files {
		low := strings.ToLower(f.Path)
		switch {
		case strings.HasSuffix(low, ".signature.p7s"):
			s := sandbox.Signature{File: f.Path, Kind: "nuget-author"}
			der, _ := readBytesCapped(join(root, f.Path), 1<<20)
			if subj, iss, ok := parsePKCS7Signer(der); ok {
				s.Signer, s.Issuer = subj, iss
			} else {
				s.Detail = "signature present; signer not parsed"
			}
			sigs = append(sigs, s)
		case strings.HasSuffix(low, ".ps1"), strings.HasSuffix(low, ".psm1"):
			if blk := authenticodeBlock(join(root, f.Path)); blk != nil {
				s := sandbox.Signature{File: f.Path, Kind: "authenticode"}
				if subj, iss, ok := parsePKCS7Signer(blk); ok {
					s.Signer, s.Issuer = subj, iss
				} else {
					s.Detail = "Authenticode block present; signer not parsed"
				}
				sigs = append(sigs, s)
			}
		}
		if len(sigs) >= 64 {
			break
		}
	}
	return sigs
}

// authenticodeBlock extracts and base64-decodes the PKCS#7 blob of a PowerShell signature block, if present.
func authenticodeBlock(abs string) []byte {
	raw, ok := readTextCapped(abs, 4<<20)
	if !ok {
		return nil
	}
	const begin = "SIG # Begin signature block"
	const end = "SIG # End signature block"
	bi := strings.Index(raw, begin)
	ei := strings.Index(raw, end)
	if bi < 0 || ei < 0 || ei <= bi {
		return nil
	}
	var b strings.Builder
	for _, line := range strings.Split(raw[bi+len(begin):ei], "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if line == "" {
			continue
		}
		b.WriteString(line)
	}
	dec, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		return nil
	}
	return dec
}

// parsePKCS7Signer extracts the end-entity certificate's subject and issuer from a CMS/PKCS#7 SignedData blob,
// using a minimal DER walk (no external dependency). Best-effort: ok=false on anything unexpected.
func parsePKCS7Signer(der []byte) (subject, issuer string, ok bool) {
	defer func() { _ = recover() }() // any malformed DER just yields ok=false
	// ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content }
	ci := derFirst(der)
	if ci == nil || !ci.constructed {
		return "", "", false
	}
	var signedData *tlv
	for _, el := range derChildren(ci) {
		if el.class == 2 && el.tag == 0 { // [0] EXPLICIT content
			signedData = derFirst(el.content)
		}
	}
	if signedData == nil {
		return "", "", false
	}
	// Within SignedData, find the [0] IMPLICIT certificates set.
	var certsBlob []byte
	for _, el := range derChildren(signedData) {
		if el.class == 2 && el.tag == 0 {
			certsBlob = el.content
			break
		}
	}
	if certsBlob == nil {
		return "", "", false
	}
	var certs []*x509.Certificate
	for _, el := range derElements(certsBlob) {
		if el.class == 0 && el.tag == 16 && el.constructed { // SEQUENCE = a certificate
			if c, err := x509.ParseCertificate(el.full); err == nil {
				certs = append(certs, c)
			}
		}
	}
	if len(certs) == 0 {
		return "", "", false
	}
	leaf := certs[0]
	for _, c := range certs {
		if !c.IsCA {
			leaf = c
			break
		}
	}
	return clampStr(leaf.Subject.String(), 400), clampStr(leaf.Issuer.String(), 400), true
}

// ---------- minimal DER / BER TLV walker ----------

type tlv struct {
	class       int // 0 universal, 1 application, 2 context, 3 private
	tag         int
	constructed bool
	content     []byte // value bytes
	full        []byte // tag+len+value
}

func derFirst(b []byte) *tlv {
	els := derElements(b)
	if len(els) == 0 {
		return nil
	}
	return &els[0]
}

func derChildren(t *tlv) []tlv {
	if t == nil || !t.constructed {
		return nil
	}
	return derElements(t.content)
}

// derElements parses a concatenation of DER TLVs (definite length only). Malformed input stops the walk.
func derElements(b []byte) []tlv {
	var out []tlv
	i := 0
	for i < len(b) {
		if i+2 > len(b) {
			break
		}
		tagByte := b[i]
		class := int(tagByte >> 6)
		constructed := tagByte&0x20 != 0
		tag := int(tagByte & 0x1f)
		j := i + 1
		if tag == 0x1f { // high-tag-number form
			tag = 0
			for j < len(b) {
				tag = tag<<7 | int(b[j]&0x7f)
				more := b[j]&0x80 != 0
				j++
				if !more {
					break
				}
			}
		}
		if j >= len(b) {
			break
		}
		lenByte := b[j]
		j++
		var length int
		if lenByte&0x80 == 0 {
			length = int(lenByte)
		} else {
			n := int(lenByte & 0x7f)
			if n == 0 || n > 4 || j+n > len(b) {
				break // indefinite or oversized length: give up
			}
			for k := 0; k < n; k++ {
				length = length<<8 | int(b[j+k])
			}
			j += n
		}
		if length < 0 || j+length > len(b) {
			break
		}
		out = append(out, tlv{
			class: class, tag: tag, constructed: constructed,
			content: b[j : j+length], full: b[i : j+length],
		})
		i = j + length
		if len(out) > 4096 {
			break
		}
	}
	return out
}

func readBytesCapped(abs string, max int64) ([]byte, bool) {
	s, ok := readTextCapped(abs, max)
	return []byte(s), ok
}
