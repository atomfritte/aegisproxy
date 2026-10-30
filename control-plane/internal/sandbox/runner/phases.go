//go:build linux

package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// sensitivePathRe flags reads of well-known credential / secret locations that are not among our planted decoys.
var sensitivePathRe = regexp.MustCompile(
	`/etc/(passwd|shadow|gshadow)|/\.ssh/|/\.aws/|/\.gnupg|/\.kube/|/\.docker/config|\.git-credentials|/\.(bash|zsh)_history|/proc/\d+/environ|/proc/self/environ|/\.config/gcloud|/\.npmrc|/\.pypirc|/\.netrc|/\.config/NuGet`)

// Observers are the long-lived loopback services (DNS resolver + HTTP/HTTPS/TCP sinks) shared across phases; the
// active Collector is swapped per phase so each phase's network activity is recorded separately.
type Observers struct {
	ca  *SandboxCA
	hub *ColHub
	dns *DNSServer
	web *HTTPSink
	tcp *TCPSink
}

// StartObservers brings up the resolver on 127.0.0.53:53 and the sinks on all (loopback-only) interfaces.
func StartObservers() (*Observers, error) {
	ca, err := sandboxCA()
	if err != nil {
		return nil, fmt.Errorf("sandbox CA: %w", err)
	}
	hub := NewColHub(NewCollector(time.Now()))
	o := &Observers{ca: ca, hub: hub}
	if o.dns, err = StartDNS(hub, "127.0.0.53:53", "127.0.0.53:53"); err != nil {
		return nil, fmt.Errorf("dns sink: %w", err)
	}
	if o.web, err = StartHTTPSink(hub, ca, ":80", ":443"); err != nil {
		o.dns.Close()
		return nil, fmt.Errorf("http sink: %w", err)
	}
	o.tcp = StartTCPSink(hub, "", DefaultSinkPorts)
	return o, nil
}

func (o *Observers) beginPhase(start time.Time) *Collector {
	c := NewCollector(start)
	o.hub.Set(c)
	return c
}

func (o *Observers) Close() {
	if o.dns != nil {
		o.dns.Close()
	}
	if o.web != nil {
		o.web.Close()
	}
	if o.tcp != nil {
		o.tcp.Close()
	}
}

type toolPaths struct {
	node, python, dotnet, pwsh, sh string
}

func findTools() toolPaths {
	look := func(n string) string { p, _ := exec.LookPath(n); return p }
	t := toolPaths{sh: "/bin/sh"}
	t.node = look("node")
	t.python = look("python3")
	if t.python == "" {
		t.python = look("python")
	}
	t.dotnet = look("dotnet")
	t.pwsh = look("pwsh")
	if p := look("sh"); p != "" {
		t.sh = p
	}
	return t
}

// runContext carries everything a phase needs. Paths are absolute and inside the sandbox.
type runContext struct {
	eco           string
	artifactPath  string
	artifactName  string // the registry filename (installers key off its extension)
	extractRoot   string
	pkgDir        string // absolute package directory inside extractRoot
	siteDir       string // pip --target / python site dir
	home          string
	aegisDir      string
	traceDir      string // uid-1000-writable dir for strace -o output
	caPEM         string
	caDir         string
	sentinel      string
	sentinelToken string
	nodeLoader    string
	pyLoader      string
	manifest      ManifestResult
	decoys        *Decoys
	stracePath    string
	timeout       time.Duration
	tools         toolPaths
}

func (ctx *runContext) env() []string {
	e := commonEnv(ctx.home, ctx.caPEM, ctx.caDir, ctx.sentinel, ctx.decoys.Env)
	return e
}

// allowPrefixes are the directories a well-behaved install/load may legitimately write to (package dir, temp,
// and the package managers' own caches); writes anywhere else are reported.
func (ctx *runContext) allowPrefixes() []string {
	return []string{
		"/tmp", "/var/tmp", "/work", "/run", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
		ctx.aegisDir,
		ctx.home + "/.npm", ctx.home + "/.cache", ctx.home + "/.dotnet", ctx.home + "/.nuget",
		ctx.home + "/.local/share", ctx.home + "/.config/dotnet", ctx.home + "/.pki", ctx.home + "/.node-gyp",
		ctx.home + "/.config/NuGet",
	}
}

// runPhase executes one scenario and returns its Phase. It never fails hard: a scenario that cannot be built is
// marked Skipped and a scenario whose process misbehaves still yields a populated Phase.
func (ctx *runContext) runPhase(obs *Observers, scenario string) sandbox.Phase {
	ph := sandbox.Phase{Name: scenario}
	argv, dir, extraEnv, skip := ctx.buildCommand(scenario)
	if skip != "" {
		ph.Skipped = skip
		return ph
	}
	ph.Command = clampArgv(argv)

	start := time.Now()
	col := obs.beginPhase(start)
	traceFile := filepath.Join(ctx.traceDir, "trace-"+scenario+".log")
	_ = os.Remove(traceFile)

	res, err := runTraced(traceSpec{
		argv: argv, dir: dir, env: append(ctx.env(), extraEnv...),
		traceFile: traceFile, timeout: ctx.timeout, stracePath: ctx.stracePath,
	})
	if err != nil {
		ph.Skipped = "exec failed: " + err.Error()
		return ph
	}
	ph.ExitCode = res.exitCode
	ph.TimedOut = res.timedOut
	ph.DurationMs = res.duration.Milliseconds()
	ph.Stdout = res.stdoutTail
	ph.Stderr = res.stderrTail

	// Parse and categorize the trace.
	events := parseTraceFile(traceFile)
	startEpoch := firstEpoch(events)
	analysis := Analyze(events, AnalyzeConfig{
		StartEpoch:  startEpoch,
		MarkerToken: ctx.sentinelToken,
		WorkDir:     ctx.pkgDir,
		AllowPrefix: ctx.allowPrefixes(),
		DecoyFiles:  ctx.decoys.DecoyFileMap(),
		SensitiveRe: sensitivePathRe,
		ResolveHost: col.Resolve,
	})
	ph.Syscalls = analysis.Syscalls
	ph.Processes = analysis.Processes
	ph.Files = analysis.Files

	netw := col.Network()
	conns, dropped := mergeConnections(analysis.Connections, col.tcpConns(), 1000)
	netw.Connections = conns
	netw.Dropped += dropped
	ph.Network = netw

	hits := append([]sandbox.CanaryHit{}, analysis.FileCanary...)
	hits = append(hits, ctx.decoys.ScanCaptures(col.snapshotCaptures())...)
	ph.CanaryHits = dedupeCanary(hits)
	return ph
}

func parseTraceFile(path string) []Event {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	events, _ := ParseStrace(f)
	return events
}

func firstEpoch(events []Event) float64 {
	for _, e := range events {
		if e.Epoch != 0 {
			return e.Epoch
		}
	}
	return 0
}

// buildCommand returns the argv, working dir and extra env for a scenario, or a non-empty skip reason.
func (ctx *runContext) buildCommand(scenario string) (argv []string, dir string, extraEnv []string, skip string) {
	switch ctx.eco {
	case "npm":
		return ctx.npmCommand(scenario)
	case "pypi":
		return ctx.pypiCommand(scenario)
	case "nuget":
		return ctx.nugetCommand(scenario)
	case "psgallery":
		return ctx.psgalleryCommand(scenario)
	}
	return nil, "", nil, "unsupported ecosystem " + ctx.eco
}

// ---------- npm ----------

func (ctx *runContext) npmCommand(scenario string) ([]string, string, []string, string) {
	switch scenario {
	case sandbox.ScenarioInstall:
		scripts := readNpmScripts(ctx.pkgDir)
		var steps []string
		for _, name := range []string{"preinstall", "install", "postinstall"} {
			if cmd := scripts[name]; cmd != "" {
				steps = append(steps, "echo '[aegis] npm "+name+"' 1>&2\n"+cmd)
			}
		}
		if _, hasInstall := scripts["install"]; !hasInstall {
			if _, hasPre := scripts["preinstall"]; !hasPre {
				if fileExists(filepath.Join(ctx.pkgDir, "binding.gyp")) {
					steps = append(steps, "echo '[aegis] node-gyp rebuild' 1>&2\nnode-gyp rebuild")
				}
			}
		}
		if len(steps) == 0 {
			return nil, "", nil, "no npm install hooks"
		}
		script := "cat \"$AEGIS_SENTINEL\" >/dev/null 2>&1\n" + strings.Join(steps, "\n")
		env := npmLifecycleEnv(ctx)
		return []string{ctx.tools.sh, "-c", script}, ctx.pkgDir, env, ""
	case sandbox.ScenarioLoad:
		if ctx.tools.node == "" {
			return nil, "", nil, "node not available in image"
		}
		argv := []string{ctx.tools.node, ctx.nodeLoader, ctx.pkgDir}
		argv = append(argv, ctx.manifest.Entrypoints...)
		return argv, ctx.pkgDir, nil, ""
	}
	return nil, "", nil, "scenario " + scenario + " not applicable to npm"
}

func npmLifecycleEnv(ctx *runContext) []string {
	name, _ := ctx.manifest.Manifest["name"].(string)
	ver, _ := ctx.manifest.Manifest["version"].(string)
	return []string{
		"npm_lifecycle_event=install",
		"npm_package_name=" + name,
		"npm_package_version=" + ver,
		"npm_config_offline=true",
		"npm_config_loglevel=warn",
		"PATH=" + ctx.pkgDir + "/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

func readNpmScripts(pkgDir string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		return out
	}
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(raw, &m) == nil {
		for k, v := range m.Scripts {
			out[k] = v
		}
	}
	return out
}

// ---------- pypi ----------

func (ctx *runContext) pypiCommand(scenario string) ([]string, string, []string, string) {
	if ctx.tools.python == "" {
		return nil, "", nil, "python not available in image"
	}
	switch scenario {
	case sandbox.ScenarioInstall:
		isWheel := ctx.manifest.Manifest["format"] == "wheel"
		// pip decides wheel vs sdist from the file's extension, so install via a correctly-named symlink to the
		// verified artifact rather than the generic artifact.bin.
		target := ctx.artifactPath
		if ctx.artifactName != "" {
			link := filepath.Join("/work", ctx.artifactName)
			if link != ctx.artifactPath {
				_ = os.Remove(link)
				if os.Symlink(ctx.artifactPath, link) == nil {
					target = link
				}
			}
		}
		pip := shellQuote(ctx.tools.python) + " -m pip install --no-deps --no-index --target " + shellQuote(ctx.siteDir)
		if isWheel {
			pip += " --no-compile"
		} else {
			pip += " --no-build-isolation"
		}
		pip += " " + shellQuote(target)
		script := "cat \"$AEGIS_SENTINEL\" >/dev/null 2>&1\n" + pip
		return []string{ctx.tools.sh, "-c", script}, "/work", nil, ""
	case sandbox.ScenarioLoad:
		mods := ctx.manifest.Entrypoints
		sitedirs := ctx.extractRoot + "," + ctx.siteDir + "," + ctx.pkgDir
		argv := []string{ctx.tools.python, "-I", ctx.pyLoader, sitedirs}
		argv = append(argv, mods...)
		return argv, "/work", nil, ""
	}
	return nil, "", nil, "scenario " + scenario + " not applicable to pypi"
}

// ---------- nuget ----------

func (ctx *runContext) nugetCommand(scenario string) ([]string, string, []string, string) {
	if ctx.tools.dotnet == "" {
		return nil, "", nil, "dotnet not available in image"
	}
	switch scenario {
	case sandbox.ScenarioInstall:
		props, targets := ctx.nugetBuildImports()
		if len(props)+len(targets) == 0 {
			return nil, "", nil, "no MSBuild props/targets to import"
		}
		projDir := filepath.Join("/work", "nugetstub")
		if err := writeNugetStub(projDir, props, targets); err != nil {
			return nil, "", nil, "nuget stub: " + err.Error()
		}
		_ = chownR(projDir, unprivUID, unprivGID)
		script := "cat \"$AEGIS_SENTINEL\" >/dev/null 2>&1\n" +
			shellQuote(ctx.tools.dotnet) + " build " + shellQuote(filepath.Join(projDir, "stub.csproj")) +
			" -p:UseSharedCompilation=false --nologo -v minimal"
		return []string{ctx.tools.sh, "-c", script}, projDir, nil, ""
	case sandbox.ScenarioLoad:
		libDir := ctx.nugetBestLib()
		if libDir == "" {
			return nil, "", nil, "no lib/<tfm> assemblies to load"
		}
		loader := filepath.Join(ctx.aegisDir, "loader", "AegisLoader.dll")
		if !fileExists(loader) {
			return nil, "", nil, "prebuilt .NET loader missing from image"
		}
		return []string{ctx.tools.dotnet, loader, libDir}, "/work", nil, ""
	}
	return nil, "", nil, "scenario " + scenario + " not applicable to nuget"
}

func (ctx *runContext) nugetBuildImports() (props, targets []string) {
	for _, h := range ctx.manifest.Hooks {
		switch h.Kind {
		case "msbuild-props":
			props = append(props, filepath.Join(ctx.extractRoot, filepath.FromSlash(h.File)))
		case "msbuild-targets":
			targets = append(targets, filepath.Join(ctx.extractRoot, filepath.FromSlash(h.File)))
		}
	}
	return
}

func (ctx *runContext) nugetBestLib() string {
	tfms, _ := ctx.manifest.Manifest["lib_tfms"].([]string)
	best := ""
	for _, tfm := range tfms {
		dir := filepath.Join(ctx.extractRoot, "lib", tfm)
		if dirHasDLL(dir) {
			if best == "" || preferTFM(tfm, filepath.Base(best)) {
				best = dir
			}
		}
	}
	return best
}

// ---------- psgallery ----------

func (ctx *runContext) psgalleryCommand(scenario string) ([]string, string, []string, string) {
	if ctx.tools.pwsh == "" {
		return nil, "", nil, "pwsh not available in image"
	}
	switch scenario {
	case sandbox.ScenarioInstall:
		toolScripts := ctx.psToolScripts()
		if len(toolScripts) == 0 {
			return nil, "", nil, "PowerShellGet runs no code on install (no tools/*.ps1 in package)"
		}
		var cmds []string
		cmds = append(cmds, "Get-Content $env:AEGIS_SENTINEL -ErrorAction SilentlyContinue | Out-Null")
		for _, s := range toolScripts {
			cmds = append(cmds, "& '"+s+"'")
		}
		script := strings.Join(cmds, "; ")
		return []string{ctx.tools.pwsh, "-NoProfile", "-NonInteractive", "-Command", script}, ctx.pkgDir, nil, ""
	case sandbox.ScenarioLoad:
		psd1, _ := ctx.manifest.Manifest["manifest_file"].(string)
		if psd1 == "" {
			return nil, "", nil, "no .psd1 manifest to import"
		}
		psd1Abs := filepath.Join(ctx.extractRoot, filepath.FromSlash(psd1))
		stubDir := filepath.Join("/work", "psstubs")
		_ = os.MkdirAll(stubDir, 0o755)
		_ = chownR(stubDir, unprivUID, unprivGID)
		required, _ := ctx.manifest.Manifest["required_modules"].([]string)
		script := psLoadScript(psd1Abs, stubDir, required)
		return []string{ctx.tools.pwsh, "-NoProfile", "-NonInteractive", "-Command", script}, ctx.pkgDir, nil, ""
	}
	return nil, "", nil, "scenario " + scenario + " not applicable to psgallery"
}

func (ctx *runContext) psToolScripts() []string {
	var out []string
	for _, f := range ctx.manifest.Hooks {
		if f.Kind == "nuget-ps" {
			out = append(out, filepath.Join(ctx.extractRoot, filepath.FromSlash(f.File)))
		}
	}
	// Also any tools/*.ps1 in the inventory (install.ps1/init.ps1) already captured as nuget-ps hooks.
	return out
}

func psLoadScript(psd1, stubDir string, required []string) string {
	var b strings.Builder
	b.WriteString("$env:PSModulePath = '" + stubDir + "' + [IO.Path]::PathSeparator + $env:PSModulePath; ")
	for _, m := range required {
		if m == "" {
			continue
		}
		safe := strings.ReplaceAll(m, "'", "")
		b.WriteString("New-Item -ItemType Directory -Force -Path (Join-Path '" + stubDir + "' '" + safe + "') | Out-Null; ")
		b.WriteString("Set-Content -Path (Join-Path (Join-Path '" + stubDir + "' '" + safe + "') '" + safe + ".psm1') -Value '# aegis stub'; ")
	}
	b.WriteString("Get-Content $env:AEGIS_SENTINEL -ErrorAction SilentlyContinue | Out-Null; ")
	b.WriteString("Import-Module '" + psd1 + "' -Force -ErrorAction Continue")
	return b.String()
}

// ---------- shared helpers ----------

func clampArgv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = clampStr(a, 2000)
	}
	return out
}

func dedupeCanary(in []sandbox.CanaryHit) []sandbox.CanaryHit {
	seen := map[string]bool{}
	var out []sandbox.CanaryHit
	for _, h := range in {
		k := h.Canary + "|" + h.Where
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirHasDLL(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".dll") {
			return true
		}
	}
	return false
}

// preferTFM is a crude "a is newer/better than b" for net TFMs (prefer higher netX.0, then netstandard, then net4x).
func preferTFM(a, b string) bool {
	return tfmRank(a) > tfmRank(b)
}

func tfmRank(t string) int {
	t = strings.ToLower(t)
	switch {
	case strings.HasPrefix(t, "net9."):
		return 90
	case strings.HasPrefix(t, "net8."):
		return 80
	case strings.HasPrefix(t, "net7."):
		return 70
	case strings.HasPrefix(t, "net6."):
		return 60
	case strings.HasPrefix(t, "netstandard2.1"):
		return 55
	case strings.HasPrefix(t, "netstandard2.0"):
		return 50
	case strings.HasPrefix(t, "netstandard"):
		return 40
	case strings.HasPrefix(t, "netcoreapp"):
		return 30
	case strings.HasPrefix(t, "net4"):
		return 20
	}
	return 10
}

func writeNugetStub(dir string, props, targets []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var imports strings.Builder
	for _, p := range props {
		imports.WriteString("  <Import Project=\"" + xmlAttr(p) + "\" Condition=\"Exists('" + xmlAttr(p) + "')\" />\n")
	}
	for _, t := range targets {
		imports.WriteString("  <Import Project=\"" + xmlAttr(t) + "\" Condition=\"Exists('" + xmlAttr(t) + "')\" />\n")
	}
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <RestoreSources></RestoreSources>
    <AutomaticallyUseReferenceAssemblyPackages>false</AutomaticallyUseReferenceAssemblyPackages>
  </PropertyGroup>
` + imports.String() + `</Project>
`
	return os.WriteFile(filepath.Join(dir, "stub.csproj"), []byte(csproj), 0o644)
}

func xmlAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return s
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func chownR(root string, uid, gid int) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Lchown(p, uid, gid)
		return nil
	})
}
