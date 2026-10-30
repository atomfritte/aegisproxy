package runner

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// Decoys is a per-run set of bait secrets: dummy credential files planted in the usual developer locations and a
// CI-persona environment, all filled with unique random marker values and nothing real. A CanaryHit is raised
// when a decoy file is read (detected from the strace) or when a marker value — in raw, base64, hex or url form,
// or hidden inside a base64/hex blob — appears in captured DNS names or HTTP/TCP traffic.
type Decoys struct {
	Home       string
	Env        map[string]string
	files      []decoyFile
	fileByPath map[string]string // resolved path -> canary name
	needles    []needle          // raw + encoded marker forms to scan captured text for
	markers    []marker          // raw markers (for decode-and-search)
}

type decoyFile struct {
	rel     string
	canary  string
	content string
}

type needle struct {
	s      string
	canary string
}

type marker struct {
	value  string
	canary string
}

// GenerateDecoys builds a decoy plan for the given home directory. Call Plant to write the files.
func GenerateDecoys(home string) *Decoys {
	d := &Decoys{Home: home, fileByPath: map[string]string{}, Env: map[string]string{}}

	mk := func(canary string) string {
		return "aegis" + strings.ReplaceAll(canary, "-", "") + randHex(16)
	}

	// File decoys.
	awsKey := mk("aws-access-key")
	awsSecret := mk("aws-secret-key")
	npmTok := mk("npm-token")
	ghTok := mk("github-token")
	glTok := mk("gitlab-token")
	sshKey := mk("ssh-private-key")
	gcpKey := mk("gcp-service-account")
	dockerAuth := mk("docker-auth")
	pypiTok := mk("pypi-token")
	nugetKey := mk("nuget-apikey")
	netrcPass := mk("netrc-password")
	gitCred := mk("git-credentials")
	histSecret := mk("shell-history-secret")

	d.addFile(".ssh/id_rsa", "ssh-private-key", sshKey,
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"+sshKey+"\n-----END OPENSSH PRIVATE KEY-----\n")
	d.addFile(".ssh/id_ed25519", "ssh-private-key", sshKey,
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"+sshKey+"\n-----END OPENSSH PRIVATE KEY-----\n")
	d.addFile(".aws/credentials", "aws-secret-key", awsSecret,
		"[default]\naws_access_key_id = AKIA"+strings.ToUpper(awsKey[:16])+"\naws_secret_access_key = "+awsSecret+"\n")
	d.addMarker("aws-access-key", "AKIA"+strings.ToUpper(awsKey[:16]))
	d.addFile(".config/gcloud/application_default_credentials.json", "gcp-service-account", gcpKey,
		`{"type":"service_account","private_key":"`+gcpKey+`","client_email":"ci@sandbox.iam.gserviceaccount.com"}`+"\n")
	d.addFile(".npmrc", "npm-token", npmTok, "//registry.npmjs.org/:_authToken="+npmTok+"\n")
	d.addFile(".pypirc", "pypi-token", pypiTok, "[pypi]\nusername = __token__\npassword = pypi-"+pypiTok+"\n")
	d.addFile(".config/pip/pip.conf", "pypi-token", pypiTok, "[global]\nextra-index-url = https://user:"+pypiTok+"@pypi.internal/simple\n")
	d.addFile(".docker/config.json", "docker-auth", dockerAuth,
		`{"auths":{"registry.internal":{"auth":"`+base64.StdEncoding.EncodeToString([]byte("ci:"+dockerAuth))+`"}}}`+"\n")
	d.addFile(".netrc", "netrc-password", netrcPass, "machine registry.internal login ci password "+netrcPass+"\n")
	d.addFile(".config/NuGet/NuGet.Config", "nuget-apikey", nugetKey,
		`<?xml version="1.0"?><configuration><apikeys><add key="https://api.nuget.org" value="`+nugetKey+`"/></apikeys></configuration>`+"\n")
	d.addFile(".git-credentials", "git-credentials", gitCred, "https://ci:"+gitCred+"@github.com\n")
	d.addFile(".bash_history", "shell-history-secret", histSecret,
		"ls\nexport DEPLOY_TOKEN="+histSecret+"\nssh prod\n")
	d.addFile(".zsh_history", "shell-history-secret", histSecret,
		": 1700000000:0;export DEPLOY_TOKEN="+histSecret+"\n")

	// CI-persona environment + secret env vars (their values are also canaries).
	envCI := mk("env-ci-token")
	d.Env["CI"] = "true"
	d.Env["GITHUB_ACTIONS"] = "true"
	d.Env["GITHUB_WORKFLOW"] = "release"
	d.Env["GITHUB_REPOSITORY"] = "acme-corp/widget"
	d.Env["GITHUB_RUN_ID"] = "1234567890"
	d.Env["RUNNER_OS"] = "Linux"
	d.Env["RUNNER_TEMP"] = "/tmp"
	d.Env["AWS_ACCESS_KEY_ID"] = "AKIA" + strings.ToUpper(awsKey[:16])
	d.Env["AWS_SECRET_ACCESS_KEY"] = awsSecret
	d.Env["NPM_TOKEN"] = npmTok
	d.Env["NODE_AUTH_TOKEN"] = npmTok
	d.Env["GITHUB_TOKEN"] = "ghp_" + ghTok
	d.addMarker("github-token", "ghp_"+ghTok)
	d.Env["GITLAB_TOKEN"] = "glpat-" + glTok
	d.addMarker("gitlab-token", "glpat-"+glTok)
	d.Env["CI_DEPLOY_TOKEN"] = envCI

	d.buildNeedles()
	return d
}

func (d *Decoys) addFile(rel, canary, markerVal, content string) {
	d.files = append(d.files, decoyFile{rel: rel, canary: canary, content: content})
	d.addMarker(canary, markerVal)
}

func (d *Decoys) addMarker(canary, value string) {
	if value == "" {
		return
	}
	d.markers = append(d.markers, marker{value: value, canary: canary})
}

// buildNeedles precomputes the raw/base64/hex/url-safe forms of every marker for fast substring scanning.
func (d *Decoys) buildNeedles() {
	seen := map[string]bool{}
	add := func(s, canary string) {
		if len(s) < 8 || seen[s] {
			return
		}
		seen[s] = true
		d.needles = append(d.needles, needle{s: s, canary: canary})
	}
	for _, m := range d.markers {
		add(m.value, m.canary)
		add(base64.StdEncoding.EncodeToString([]byte(m.value)), m.canary)
		add(strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(m.value)), "="), m.canary)
		add(base64.URLEncoding.EncodeToString([]byte(m.value)), m.canary)
		add(hex.EncodeToString([]byte(m.value)), m.canary)
	}
}

// Plant writes every decoy file under Home with user-only permissions and records resolved paths for the strace
// cross-reference. It also marks shell-history files world-readable like real ones.
func (d *Decoys) Plant() error {
	for _, f := range d.files {
		abs := filepath.Join(d.Home, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if err := os.WriteFile(abs, []byte(f.content), mode); err != nil {
			return err
		}
		d.fileByPath[abs] = f.canary
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			d.fileByPath[resolved] = f.canary
		}
	}
	return nil
}

// DecoyFileMap maps every planted decoy path to its canary name (for AnalyzeConfig.DecoyFiles).
func (d *Decoys) DecoyFileMap() map[string]string {
	out := make(map[string]string, len(d.fileByPath))
	for k, v := range d.fileByPath {
		out[k] = v
	}
	return out
}

var (
	b64TokenRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexTokenRe = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
)

// ScanCaptures scans captured sink text for marker values in any form and returns the canary hits (deduped per
// canary+where). It catches raw markers, their standalone base64/hex/url encodings, and markers hidden inside a
// larger base64/hex blob (by decoding candidate tokens and searching the plaintext).
func (d *Decoys) ScanCaptures(caps []capture) []sandbox.CanaryHit {
	type key struct{ canary, where string }
	hits := map[key]string{}
	note := func(canary, where, detail string) {
		k := key{canary, where}
		if _, ok := hits[k]; !ok {
			hits[k] = detail
		}
	}
	for _, c := range caps {
		text := c.text
		for _, n := range d.needles {
			if strings.Contains(text, n.s) {
				note(n.canary, c.where, "marker in "+c.where+" traffic")
			}
		}
		// Decode base64/hex tokens and search for raw markers inside.
		for _, tok := range b64TokenRe.FindAllString(text, 64) {
			for _, dec := range tryB64(tok) {
				d.matchRaw(dec, c.where, note)
			}
		}
		for _, tok := range hexTokenRe.FindAllString(text, 64) {
			if raw, err := hex.DecodeString(evenPrefix(tok)); err == nil {
				d.matchRaw(string(raw), c.where, note)
			}
		}
	}
	var out []sandbox.CanaryHit
	for k, detail := range hits {
		out = append(out, sandbox.CanaryHit{Canary: k.canary, Where: k.where, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Canary != out[j].Canary {
			return out[i].Canary < out[j].Canary
		}
		return out[i].Where < out[j].Where
	})
	return out
}

func (d *Decoys) matchRaw(decoded, where string, note func(canary, where, detail string)) {
	for _, m := range d.markers {
		if len(m.value) >= 8 && strings.Contains(decoded, m.value) {
			note(m.canary, where, "marker in decoded "+where+" payload")
		}
	}
}

func tryB64(tok string) []string {
	var out []string
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(tok); err == nil && len(b) > 0 {
			out = append(out, string(b))
		}
	}
	return out
}

func evenPrefix(s string) string {
	if len(s)%2 == 1 {
		return s[:len(s)-1]
	}
	return s
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i * 7)
		}
	}
	return hex.EncodeToString(b)
}
