package runner

import (
	"encoding/json"
	"encoding/xml"
	"path"
	"regexp"
	"sort"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// ManifestResult is the parsed, ecosystem-specific metadata of an artifact plus the install/build hooks it would
// run and the module entry points a load scenario should import.
type ManifestResult struct {
	Manifest    map[string]any
	Hooks       []sandbox.InstallHook
	Entrypoints []string
	// PkgDir is the directory inside the extraction root that holds the package proper (npm "package/",
	// a wheel root, the sdist's inner dir, the nupkg root). Phases run relative to it.
	PkgDir   string
	Warnings []string
}

// ParseEcosystem parses the manifest of an already-extracted artifact. files is the inventory from Extract
// (relative, slash-separated member paths). It never fails; unparsable input yields a partial result.
func ParseEcosystem(eco, root string, files []sandbox.File) ManifestResult {
	switch eco {
	case "npm":
		return parseNpm(root, files)
	case "pypi":
		return parsePypi(root, files)
	case "nuget":
		return parseNuget(root, files)
	case "psgallery":
		return parsePsgallery(root, files)
	}
	return ManifestResult{Manifest: map[string]any{}}
}

// ---------- npm ----------

func parseNpm(root string, files []sandbox.File) ManifestResult {
	res := ManifestResult{Manifest: map[string]any{}, PkgDir: "."}
	pj := findFile(files, "package.json")
	if pj == "" {
		res.Warnings = append(res.Warnings, "no package.json")
		return res
	}
	res.PkgDir = path.Dir(pj)
	raw, _ := readTextCapped(join(root, pj), 4<<20)
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		res.Warnings = append(res.Warnings, "package.json parse: "+err.Error())
		return res
	}
	for _, k := range []string{"name", "version", "license", "main", "type", "gypfile"} {
		if v, ok := m[k]; ok {
			res.Manifest[k] = v
		}
	}
	for _, k := range []string{"dependencies", "optionalDependencies", "peerDependencies", "bin", "exports"} {
		if v, ok := m[k]; ok {
			res.Manifest[k] = v
		}
	}
	scripts, _ := m["scripts"].(map[string]any)
	if len(scripts) > 0 {
		res.Manifest["scripts"] = scripts
	}
	for _, name := range []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"} {
		if cmd, ok := scripts[name].(string); ok && cmd != "" {
			res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "npm-script", Name: name, File: "package.json", Command: clampStr(cmd, 400)})
		}
	}
	// Implicit node-gyp rebuild: binding.gyp present and no explicit install/preinstall script.
	hasBinding := findFile(files, "binding.gyp") != ""
	if gf, ok := m["gypfile"].(bool); ok && gf {
		hasBinding = true
	}
	_, hasInstall := scripts["install"]
	_, hasPre := scripts["preinstall"]
	if hasBinding && !hasInstall && !hasPre {
		res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "npm-gyp", Name: "node-gyp rebuild", File: "binding.gyp", Command: "node-gyp rebuild"})
	}
	// Entry points: main, then exports["."].
	if mainS, ok := m["main"].(string); ok && mainS != "" {
		res.Entrypoints = append(res.Entrypoints, mainS)
	}
	res.Entrypoints = append(res.Entrypoints, exportsEntrypoints(m["exports"])...)
	if len(res.Entrypoints) == 0 {
		if findFile(files, "index.js") != "" {
			res.Entrypoints = append(res.Entrypoints, "index.js")
		}
	}
	res.Entrypoints, _ = dedupeCap(res.Entrypoints, 16)
	return res
}

// exportsEntrypoints pulls string targets out of the "exports" field (string, map of conditions, or map of
// subpaths), focused on the "." subpath and common conditions.
func exportsEntrypoints(exports any) []string {
	var out []string
	switch e := exports.(type) {
	case string:
		out = append(out, e)
	case map[string]any:
		dot, ok := e["."]
		if !ok {
			// Maybe it is itself a conditions map (require/import/default).
			dot = e
		}
		out = append(out, conditionTargets(dot)...)
	}
	return out
}

func conditionTargets(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case map[string]any:
		for _, cond := range []string{"import", "require", "default", "node"} {
			if s, ok := t[cond].(string); ok {
				out = append(out, s)
			} else if nested, ok := t[cond].(map[string]any); ok {
				out = append(out, conditionTargets(nested)...)
			}
		}
	}
	return out
}

// ---------- pypi ----------

func parsePypi(root string, files []sandbox.File) ManifestResult {
	res := ManifestResult{Manifest: map[string]any{}, PkgDir: "."}
	// Wheel: a *.dist-info/METADATA exists.
	if meta := findSuffix(files, ".dist-info/METADATA"); meta != "" {
		res.Manifest["format"] = "wheel"
		parseRFC822(join(root, meta), res.Manifest)
		if tl := strings.TrimSuffix(meta, "METADATA") + "top_level.txt"; findFile(files, tl) != "" {
			txt, _ := readTextCapped(join(root, tl), 1<<16)
			res.Entrypoints = append(res.Entrypoints, splitLines(txt)...)
			res.Manifest["top_level"] = splitLines(txt)
		}
		if ep := strings.TrimSuffix(meta, "METADATA") + "entry_points.txt"; findFile(files, ep) != "" {
			txt, _ := readTextCapped(join(root, ep), 1<<16)
			res.Manifest["entry_points"] = clampStr(txt, 2000)
		}
		// .pth files (executed by site at import time).
		for _, f := range files {
			if strings.HasSuffix(f.Path, ".pth") {
				res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "pth", Name: path.Base(f.Path), File: f.Path})
			}
		}
		if len(res.Entrypoints) == 0 {
			res.Entrypoints = append(res.Entrypoints, guessTopLevel(files)...)
		}
		res.Entrypoints, _ = dedupeCap(res.Entrypoints, 32)
		return res
	}
	// sdist: PKG-INFO + setup.py / pyproject.toml.
	res.Manifest["format"] = "sdist"
	if pkg := findSuffix(files, "PKG-INFO"); pkg != "" {
		parseRFC822(join(root, pkg), res.Manifest)
		res.PkgDir = path.Dir(pkg)
		if res.PkgDir == "." {
			res.PkgDir = topDir(files)
		}
	} else {
		res.PkgDir = topDir(files)
	}
	if sp := findFile(files, "setup.py"); sp != "" {
		raw, _ := readTextCapped(join(root, sp), 1<<20)
		res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "setup-py", Name: "setup.py", File: sp, Command: firstLine(raw)})
	}
	if py := findFile(files, "pyproject.toml"); py != "" {
		raw, _ := readTextCapped(join(root, py), 1<<20)
		if backend := tomlBuildBackend(raw); backend != "" {
			res.Manifest["build_backend"] = backend
			res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "pep517", Name: backend, File: py})
		}
	}
	res.Entrypoints = append(res.Entrypoints, guessTopLevel(files)...)
	res.Entrypoints, _ = dedupeCap(res.Entrypoints, 32)
	return res
}

// guessTopLevel returns the importable top-level package names: a directory that holds an __init__.py and whose
// parent directory does not (so sub-packages are excluded). This handles both the wheel layout (pkg/__init__.py)
// and the sdist layout (dist-1.0/pkg/__init__.py).
func guessTopLevel(files []sandbox.File) []string {
	pkgDirs := map[string]bool{}
	for _, f := range files {
		if path.Base(f.Path) == "__init__.py" {
			pkgDirs[path.Dir(f.Path)] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for dir := range pkgDirs {
		if pkgDirs[path.Dir(dir)] {
			continue // a sub-package: its parent is also a package
		}
		name := path.Base(dir)
		if name == "." || strings.Contains(name, ".dist-info") || strings.Contains(name, ".egg-info") || strings.Contains(name, ".data") || name == "tests" || name == "test" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---------- nuget ----------

func parseNuget(root string, files []sandbox.File) ManifestResult {
	res := ManifestResult{Manifest: map[string]any{}, PkgDir: "."}
	if nuspec := findSuffix(files, ".nuspec"); nuspec != "" {
		raw, _ := readTextCapped(join(root, nuspec), 1<<20)
		parseNuspec(raw, res.Manifest)
	}
	for _, f := range files {
		p := strings.ToLower(f.Path)
		dir := strings.SplitN(p, "/", 2)[0]
		isBuildDir := dir == "build" || dir == "buildtransitive" || dir == "buildmultitargeting"
		switch {
		case isBuildDir && strings.HasSuffix(p, ".props"):
			res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "msbuild-props", Name: f.Path, File: f.Path})
		case isBuildDir && strings.HasSuffix(p, ".targets"):
			res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "msbuild-targets", Name: f.Path, File: f.Path})
		case strings.HasPrefix(p, "tools/") && (strings.HasSuffix(p, "init.ps1") || strings.HasSuffix(p, "install.ps1") || strings.HasSuffix(p, "uninstall.ps1")):
			res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "nuget-ps", Name: f.Path, File: f.Path})
		}
	}
	if hasAnalyzer(files) {
		res.Manifest["analyzers"] = true
	}
	if findSuffix(files, ".signature.p7s") != "" {
		res.Manifest["signature_present"] = true
	}
	res.Manifest["lib_tfms"] = nugetLibTFMs(files)
	return res
}

func parseNuspec(raw string, out map[string]any) {
	type meta struct {
		ID         string `xml:"metadata>id"`
		Version    string `xml:"metadata>version"`
		Authors    string `xml:"metadata>authors"`
		License    string `xml:"metadata>license"`
		LicenseURL string `xml:"metadata>licenseUrl"`
		ProjectURL string `xml:"metadata>projectUrl"`
	}
	var m meta
	if err := xml.Unmarshal([]byte(raw), &m); err != nil {
		return
	}
	putIf(out, "name", m.ID)
	putIf(out, "version", m.Version)
	putIf(out, "authors", m.Authors)
	putIf(out, "license", firstNonEmpty(m.License, m.LicenseURL))
	putIf(out, "project_url", m.ProjectURL)
}

func nugetLibTFMs(files []sandbox.File) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		p := strings.ToLower(f.Path)
		if strings.HasPrefix(p, "lib/") {
			parts := strings.Split(f.Path, "/")
			if len(parts) >= 2 && !seen[parts[1]] {
				seen[parts[1]] = true
				out = append(out, parts[1])
			}
		}
	}
	return out
}

func hasAnalyzer(files []sandbox.File) bool {
	for _, f := range files {
		if strings.HasPrefix(strings.ToLower(f.Path), "analyzers/") {
			return true
		}
	}
	return false
}

// ---------- psgallery ----------

var (
	psStringKeyRe = regexp.MustCompile(`(?mi)^\s*(RootModule|ModuleVersion|Author|GUID|CompanyName|Description)\s*=\s*['"]([^'"]*)['"]`)
	psArrayKeyRe  = regexp.MustCompile(`(?mis)^\s*(RequiredModules|ScriptsToProcess|NestedModules|RequiredAssemblies|FunctionsToExport)\s*=\s*@?\(([^)]*)\)`)
	psQuotedRe    = regexp.MustCompile(`['"]([^'"]+)['"]`)
)

func parsePsgallery(root string, files []sandbox.File) ManifestResult {
	res := ManifestResult{Manifest: map[string]any{}, PkgDir: "."}
	psd1 := findSuffix(files, ".psd1")
	if psd1 == "" {
		res.Warnings = append(res.Warnings, "no .psd1 manifest")
		return res
	}
	res.Manifest["manifest_file"] = psd1
	raw, _ := readTextCapped(join(root, psd1), 1<<20)
	for _, m := range psStringKeyRe.FindAllStringSubmatch(raw, -1) {
		res.Manifest[strings.ToLower(m[1])] = m[2]
	}
	arrays := map[string][]string{}
	for _, m := range psArrayKeyRe.FindAllStringSubmatch(raw, -1) {
		key := strings.ToLower(m[1])
		var vals []string
		for _, q := range psQuotedRe.FindAllStringSubmatch(m[2], -1) {
			vals = append(vals, q[1])
		}
		arrays[key] = vals
		if len(vals) > 0 {
			res.Manifest[key] = vals
		}
	}
	for _, s := range arrays["scriptstoprocess"] {
		res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "ps-scripts-to-process", Name: s, File: psd1})
	}
	if rm, ok := res.Manifest["rootmodule"].(string); ok && rm != "" {
		res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "ps-module", Name: rm, File: psd1})
		res.Entrypoints = append(res.Entrypoints, rm)
	}
	for _, n := range arrays["nestedmodules"] {
		res.Hooks = append(res.Hooks, sandbox.InstallHook{Kind: "ps-module", Name: n, File: psd1})
	}
	res.Manifest["required_modules"] = arrays["requiredmodules"]
	// The manifest itself is the import target.
	res.Entrypoints = append([]string{psd1}, res.Entrypoints...)
	res.Entrypoints, _ = dedupeCap(res.Entrypoints, 16)
	return res
}

// ---------- shared parsing helpers ----------

// parseRFC822 parses an email.message style header block (METADATA / PKG-INFO) into selected manifest fields.
func parseRFC822(abs string, out map[string]any) {
	raw, ok := readTextCapped(abs, 1<<20)
	if !ok {
		return
	}
	var requires []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers (body follows)
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "name":
			out["name"] = v
		case "version":
			out["version"] = v
		case "license", "license-expression":
			putIf(out, "license", v)
		case "requires-dist":
			if len(requires) < 200 {
				requires = append(requires, v)
			}
		case "home-page", "project-url":
			putIf(out, "home_page", v)
		case "summary":
			out["summary"] = clampStr(v, 300)
		}
	}
	if len(requires) > 0 {
		out["requires_dist"] = requires
	}
}

var tomlBackendRe = regexp.MustCompile(`(?m)^\s*build-backend\s*=\s*["']([^"']+)["']`)

func tomlBuildBackend(raw string) string {
	if m := tomlBackendRe.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	if strings.Contains(raw, "[build-system]") {
		return "setuptools.build_meta (implicit)"
	}
	return ""
}

func findFile(files []sandbox.File, base string) string {
	// Prefer the shallowest match (top-level package.json over a nested one in node_modules).
	best := ""
	bestDepth := 1 << 30
	for _, f := range files {
		if path.Base(f.Path) == base {
			d := strings.Count(f.Path, "/")
			if d < bestDepth {
				best, bestDepth = f.Path, d
			}
		}
	}
	return best
}

func findSuffix(files []sandbox.File, suffix string) string {
	best := ""
	bestDepth := 1 << 30
	for _, f := range files {
		if strings.HasSuffix(f.Path, suffix) {
			d := strings.Count(f.Path, "/")
			if d < bestDepth {
				best, bestDepth = f.Path, d
			}
		}
	}
	return best
}

func topDir(files []sandbox.File) string {
	for _, f := range files {
		if i := strings.IndexByte(f.Path, '/'); i > 0 {
			return f.Path[:i]
		}
	}
	return "."
}

func join(root, rel string) string { return root + "/" + rel }

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return clampStr(strings.TrimSpace(s[:i]), 200)
	}
	return clampStr(strings.TrimSpace(s), 200)
}

func putIf(m map[string]any, k, v string) {
	if v != "" {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
