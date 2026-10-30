package pkgver

import (
	"regexp"
	"strings"
)

// Kinds of npm dependency specs (NPMSpec.Kind). Only range, tag and alias resolve through the registry; the other
// kinds fetch code from elsewhere and cannot be approved through the registry.
const (
	NPMSpecRange     = "range"     // semver range or exact version, incl. "" and "*"
	NPMSpecTag       = "tag"       // dist-tag such as latest or next
	NPMSpecAlias     = "alias"     // npm:<name>@<range|tag>
	NPMSpecGit       = "git"       // git URLs, hosted shortcuts (github:, gitlab:, bitbucket:, gist:, sourcehut:), user/repo
	NPMSpecURL       = "url"       // http(s) tarball URL
	NPMSpecFile      = "file"      // file: specs, paths and local tarballs
	NPMSpecWorkspace = "workspace" // workspace: protocol (pnpm, yarn)
	NPMSpecLink      = "link"      // link: protocol (pnpm, yarn)
	NPMSpecInvalid   = "invalid"   // npm refuses the spec (unsupported protocol, invalid tag or alias)
)

// NPMSpec is a dependency spec (the value in package.json dependencies) classified as npm-package-arg does.
type NPMSpec struct {
	Kind string
	// Name is the package an alias installs.
	Name string
	// Range is the semver range of range and alias specs ("*" for an empty spec).
	Range string
	// Tag is the dist-tag of tag specs and of aliases of a tag.
	Tag string
	// Version is the canonical version when the range is a single exact version.
	Version string
	// Ref is the committish of git specs (after "#"; "" = default branch).
	Ref string
}

var (
	// npm-package-arg: isURL, isGit (scp-like user@host:path), isFileType.
	reNPAURL      = regexp.MustCompile(`(?i)^(?:git[+])?[a-z]+:`)
	reNPAGit      = regexp.MustCompile(`^[^@]+@[^:.]+\.[^:]+:.+$`)
	reNPAFileType = regexp.MustCompile(`(?i)[.](?:tgz|tar\.gz|tar)$`)
)

// ClassifyNPMSpec classifies a dependency spec. File paths are recognized with both POSIX and Windows rules, and
// scp-like git URLs (git@host:repo.git) count as git even for hosts npm does not know.
func ClassifyNPMSpec(spec string) NPMSpec {
	return classifyNPM(jsTrim(spec), true)
}

func classifyNPM(s string, allowAlias bool) NPMSpec {
	lower := strings.ToLower(s)
	switch {
	case s == "":
		return NPMSpec{Kind: NPMSpecRange, Range: "*"}
	case strings.HasPrefix(lower, "file:") || isNPMPath(s):
		return NPMSpec{Kind: NPMSpecFile}
	case strings.HasPrefix(lower, "npm:"):
		if !allowAlias {
			return NPMSpec{Kind: NPMSpecInvalid} // nested aliases are not supported
		}
		return classifyNPMAlias(s[4:])
	}
	if npmHostedGit(s) {
		return NPMSpec{Kind: NPMSpecGit, Ref: gitRef(s)}
	}
	if reNPAURL.MatchString(s) {
		switch strings.ToLower(s[:strings.IndexByte(s, ':')]) {
		case "git", "git+http", "git+https", "git+rsync", "git+ftp", "git+file", "git+ssh":
			return NPMSpec{Kind: NPMSpecGit, Ref: gitRef(s)}
		case "http", "https":
			return NPMSpec{Kind: NPMSpecURL}
		case "workspace":
			return NPMSpec{Kind: NPMSpecWorkspace}
		case "link":
			return NPMSpec{Kind: NPMSpecLink}
		}
		return NPMSpec{Kind: NPMSpecInvalid}
	}
	if reNPAGit.MatchString(s) {
		return NPMSpec{Kind: NPMSpecGit, Ref: gitRef(s)}
	}
	if strings.ContainsAny(s, `/\`) || reNPAFileType.MatchString(s) {
		return NPMSpec{Kind: NPMSpecFile}
	}
	return classifyNPMRegistry(s)
}

func classifyNPMRegistry(s string) NPMSpec {
	if len(s) <= semverMaxLength {
		if v, err := parseSemver(s, true); err == nil {
			return NPMSpec{Kind: NPMSpecRange, Range: s, Version: v.String()}
		}
	}
	if _, err := ParseNPMRange(s); err == nil {
		return NPMSpec{Kind: NPMSpecRange, Range: s}
	}
	if uriComponentSafe(s) {
		return NPMSpec{Kind: NPMSpecTag, Tag: s}
	}
	return NPMSpec{Kind: NPMSpecInvalid}
}

// classifyNPMAlias resolves the part after "npm:" like npm-package-arg's npa(): name@spec, where the spec must be a
// registry spec.
func classifyNPMAlias(sub string) NPMSpec {
	nameEnd := -1
	if len(sub) > 1 {
		if k := strings.IndexByte(sub[1:], '@'); k >= 0 {
			nameEnd = k + 1
		}
	}
	namePart := sub
	if nameEnd > 0 {
		namePart = sub[:nameEnd]
	}
	var name, spec string
	switch {
	case reNPAURL.MatchString(sub), reNPAGit.MatchString(sub):
		return NPMSpec{Kind: NPMSpecInvalid}
	case !strings.HasPrefix(namePart, "@") && (strings.ContainsAny(namePart, `/\`) || reNPAFileType.MatchString(namePart)):
		return NPMSpec{Kind: NPMSpecInvalid}
	case nameEnd > 0:
		name, spec = namePart, sub[nameEnd+1:]
		if spec == "" {
			spec = "*"
		}
	default:
		name, spec = sub, "*"
	}
	if !validNPMName(name) {
		return NPMSpec{Kind: NPMSpecInvalid}
	}
	r := classifyNPM(jsTrim(spec), false)
	if r.Kind != NPMSpecRange && r.Kind != NPMSpecTag {
		return NPMSpec{Kind: NPMSpecInvalid} // aliases only work for registry dependencies
	}
	r.Kind, r.Name = NPMSpecAlias, name
	return r
}

// isNPMPath reports a local path: ".", "/", "\", "~/" or a drive letter at the start.
func isNPMPath(s string) bool {
	if s[0] == '.' || s[0] == '/' || s[0] == '\\' || strings.HasPrefix(s, "~/") {
		return true
	}
	return len(s) >= 2 && s[1] == ':' && (s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z')
}

func gitRef(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// npmHostedGit reports whether hosted-git-info recognizes s: a hosted shortcut, GitHub's user/repo shorthand, or a
// repository URL on github.com, gitlab.com, bitbucket.org, gist.github.com or git.sr.ht.
func npmHostedGit(s string) bool {
	if isGitHubShorthand(s) {
		return true
	}
	if i := strings.IndexByte(s, ':'); i > 0 {
		switch strings.ToLower(s[:i]) {
		case "github", "gitlab", "bitbucket", "gist", "sourcehut":
			return true
		}
	}
	body, _, _ := strings.Cut(s, "#")
	var proto, rest string
	if i := strings.Index(body, "://"); i > 0 {
		proto, rest = strings.ToLower(body[:i+1]), body[i+3:]
	} else if at, colon := strings.IndexByte(body, '@'), strings.LastIndexByte(body, ':'); at > 0 && colon > at {
		// scp-like user@host:path, which hosted-git-info reads as git+ssh://user@host/path
		proto, rest = "git+ssh:", body[:colon]+"/"+body[colon+1:]
	} else {
		return false
	}
	authority, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	if c := strings.IndexByte(authority, ':'); c >= 0 {
		port := authority[c+1:]
		authority = authority[:c]
		if strings.Trim(port, "0123456789") != "" {
			path = "/" + port + path // git+ssh://git@github.com:user/repo
		}
	}
	return hostedRepoPath(proto, strings.TrimPrefix(strings.ToLower(authority), "www."), path)
}

// hostedRepoPath applies hosted-git-info's per-host protocol lists and path rules.
func hostedRepoPath(proto, host, path string) bool {
	seg := strings.Split(path, "/")
	get := func(i int) string {
		if i < len(seg) {
			return seg[i]
		}
		return ""
	}
	user, project, aux := get(1), strings.TrimSuffix(get(2), ".git"), get(3)
	switch host {
	case "github.com":
		if !oneOf(proto, "git:", "http:", "git+ssh:", "git+https:", "ssh:", "https:") || (aux != "" && aux != "tree") {
			return false
		}
		return user != "" && project != ""
	case "bitbucket.org":
		return oneOf(proto, "git+ssh:", "git+https:", "ssh:", "https:") && aux != "get" && user != "" && project != ""
	case "gitlab.com":
		p := path[1:]
		if !oneOf(proto, "git+ssh:", "git+https:", "ssh:", "https:") || strings.Contains(p, "/-/") ||
			strings.Contains(p, "/archive.tar.gz") {
			return false
		}
		k := strings.LastIndexByte(p, '/')
		return k > 0 && strings.TrimSuffix(p[k+1:], ".git") != ""
	case "gist.github.com":
		return oneOf(proto, "git:", "git+ssh:", "git+https:", "ssh:", "https:") && aux != "raw" &&
			(get(2) != "" || user != "")
	case "git.sr.ht":
		return oneOf(proto, "git+ssh:", "https:") && aux != "archive" && user != "" && project != ""
	}
	return false
}

// isGitHubShorthand is hosted-git-info's test for "user/repo[#committish]".
func isGitHubShorthand(arg string) bool {
	firstHash := strings.IndexByte(arg, '#')
	firstSlash := strings.IndexByte(arg, '/')
	secondSlash := -1
	if firstSlash >= 0 {
		if k := strings.IndexByte(arg[firstSlash+1:], '/'); k >= 0 {
			secondSlash = firstSlash + 1 + k
		}
	}
	firstColon := strings.IndexByte(arg, ':')
	firstSpace := strings.IndexFunc(arg, isJSSpace)
	firstAt := strings.IndexByte(arg, '@')
	afterHash := func(i int) bool { return i == -1 || (firstHash > -1 && i > firstHash) }
	notEndSlash := !strings.HasSuffix(arg, "/")
	if firstHash > 0 {
		notEndSlash = arg[firstHash-1] != '/'
	} else if firstHash == 0 {
		notEndSlash = true
	}
	return afterHash(firstSpace) && firstSlash > 0 && notEndSlash && !strings.HasPrefix(arg, ".") &&
		afterHash(firstAt) && afterHash(firstColon) && afterHash(secondSlash)
}

// validNPMName is validate-npm-package-name's validForOldPackages.
func validNPMName(name string) bool {
	if name == "" || name[0] == '.' || name[0] == '-' || name[0] == '_' || jsTrim(name) != name {
		return false
	}
	switch strings.ToLower(name) {
	case "node_modules", "favicon.ico":
		return false
	}
	if uriComponentSafe(name) {
		return true
	}
	scope, pkg, ok := strings.Cut(name, "/")
	return ok && len(scope) > 1 && scope[0] == '@' && pkg != "" && pkg[0] != '.' &&
		uriComponentSafe(scope[1:]) && uriComponentSafe(pkg)
}

// uriComponentSafe reports whether encodeURIComponent leaves s unchanged.
func uriComponentSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0) {
			return false
		}
	}
	return true
}

func oneOf(s string, options ...string) bool {
	for _, o := range options {
		if s == o {
			return true
		}
	}
	return false
}
