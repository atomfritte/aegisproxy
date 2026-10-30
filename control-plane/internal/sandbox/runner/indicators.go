package runner

import (
	"math"
	"regexp"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// StaticScan is the text-level result of static inspection: suspicious indicators and the literal network
// locations found in the package's text/script files.
type StaticScan struct {
	Indicators []sandbox.Indicator
	URLs       []string
	Domains    []string
	IPs        []string
	Dropped    int
}

type indicatorRule struct {
	id       string
	severity string
	desc     string
	re       *regexp.Regexp
	exts     map[string]bool // applicable extensions; nil = any text/script
}

func exts(e ...string) map[string]bool {
	m := make(map[string]bool, len(e))
	for _, x := range e {
		m[x] = true
	}
	return m
}

var jsExts = exts(".js", ".mjs", ".cjs", ".ts")
var pyExts = exts(".py")
var psExts = exts(".ps1", ".psm1", ".psd1")
var msbuildExts = exts(".props", ".targets")

// indicatorRules are ordered; all are tried against every eligible file/line.
var indicatorRules = []indicatorRule{
	// JavaScript / npm.
	{"js-dynamic-eval-b64", "high", "dynamic code execution of base64/hex-decoded data", regexp.MustCompile(`(?i)(eval|Function)\s*\(\s*(Buffer\.from|atob|global\[)`), jsExts},
	{"js-eval", "medium", "use of eval()/new Function() for dynamic code", regexp.MustCompile(`(?:\beval\s*\(|new\s+Function\s*\()`), jsExts},
	{"js-child-process", "medium", "spawns a child process (child_process)", regexp.MustCompile(`require\(\s*['"]child_process['"]\s*\)|\b(execSync|exec|spawn|spawnSync|execFile)\s*\(`), jsExts},
	{"js-network", "medium", "network client in script (http/https/net/fetch)", regexp.MustCompile(`require\(\s*['"](https?|net|dgram|dns|tls)['"]\s*\)|\bfetch\s*\(|axios|node-fetch`), jsExts},
	{"js-env-enum", "medium", "reads/enumerates environment or secret locations", regexp.MustCompile(`process\.env\b|\.ssh/|\.aws/|\.npmrc|AWS_SECRET|NPM_TOKEN|GITHUB_TOKEN`), jsExts},
	{"js-fs-sensitive", "low", "filesystem access to home/credential paths", regexp.MustCompile(`(?i)(os\.homedir|process\.env\.HOME|\/etc\/passwd|id_rsa|credentials)`), jsExts},
	// Python / pypi.
	{"py-exec-b64", "high", "exec/eval of base64/marshal-decoded data", regexp.MustCompile(`(?i)(exec|eval)\s*\(\s*(base64\.b64decode|bytes\.fromhex|codecs\.decode|marshal\.loads|zlib\.decompress)`), pyExts},
	{"py-exec", "medium", "dynamic exec()/eval()/compile()", regexp.MustCompile(`\b(exec|eval)\s*\(`), pyExts},
	{"py-subprocess", "medium", "spawns a process (os.system/subprocess/popen)", regexp.MustCompile(`\bos\.system\s*\(|\bsubprocess\.|\bos\.popen\s*\(|\bpty\.spawn`), pyExts},
	{"py-network", "medium", "network client in script (socket/urllib/requests)", regexp.MustCompile(`\bsocket\.socket\s*\(|urllib\.request|\brequests\.(get|post)|http\.client|\.connect\s*\(`), pyExts},
	{"py-env-enum", "medium", "reads environment or secret locations", regexp.MustCompile(`os\.environ|\.ssh/|\.aws/|AWS_SECRET|expanduser\(\s*['"]~`), pyExts},
	{"py-setup-cmd", "high", "overrides setuptools command classes (runs on install)", regexp.MustCompile(`cmdclass\s*=|class\s+\w+\((install|develop|build_py|egg_info)\)`), pyExts},
	// PowerShell / psgallery.
	{"ps-invoke-expression", "high", "Invoke-Expression (iex) executes a string", regexp.MustCompile(`(?i)\b(Invoke-Expression|iex)\b`), psExts},
	{"ps-encoded-command", "high", "encoded / base64 command", regexp.MustCompile(`(?i)-EncodedCommand|FromBase64String|-enc\b`), psExts},
	{"ps-web-download", "high", "downloads from the web (WebClient/Invoke-WebRequest)", regexp.MustCompile(`(?i)Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer|DownloadString|DownloadFile|\biwr\b|\bcurl\b|\bwget\b`), psExts},
	{"ps-process", "medium", "starts a process", regexp.MustCompile(`(?i)Start-Process|New-Object\s+System\.Diagnostics\.Process`), psExts},
	{"ps-hidden", "medium", "hidden / no-profile execution", regexp.MustCompile(`(?i)-WindowStyle\s+Hidden|-NonInteractive|-NoProfile|-ExecutionPolicy\s+Bypass`), psExts},
	// MSBuild / nuget.
	{"msbuild-exec", "high", "MSBuild <Exec> runs a shell command on build", regexp.MustCompile(`(?i)<Exec\b`), msbuildExts},
	{"msbuild-inline-task", "high", "MSBuild inline code task (UsingTask/Code)", regexp.MustCompile(`(?i)<UsingTask\b|<Code\b|RoslynCodeTaskFactory|CodeTaskFactory`), msbuildExts},
	{"msbuild-download", "high", "MSBuild DownloadFile / web access", regexp.MustCompile(`(?i)<DownloadFile\b|DownloadFile|WebClient|Invoke-WebRequest`), msbuildExts},
	{"msbuild-powershell", "high", "MSBuild invokes PowerShell", regexp.MustCompile(`(?i)powershell|pwsh`), msbuildExts},
}

var (
	urlRe    = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?)://[a-z0-9._~:/?#@!$&'()*+,;=%\-\[\]]{3,512}`)
	domainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|ru|cn|xyz|info|co|me|sh|app|cloud|top|tk|gq|ml|ga|cf|site|online|pw|su|cc|biz|link|pro|zip|mov|example|test|internal|local|lan|corp|invalid)\b`)
	ipv4Re   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
)

const (
	maxIndicators = 500
	maxLiterals   = 200
	maxScanBytes  = 1 << 20 // per-file bytes scanned for indicators/literals
	maxLineLen    = 2000    // long-line obfuscation threshold
)

// ScanStatic walks the package's text/script files and returns indicators and network literals. root is the
// extraction root; files is the inventory.
func ScanStatic(eco, root string, files []sandbox.File) StaticScan {
	var sc StaticScan
	var urls, domains, ips []string
	indCount := 0
	for _, f := range files {
		if f.Kind != "text" && f.Kind != "script" {
			continue
		}
		ext := strings.ToLower(extOf(f.Path))
		raw, ok := readTextCapped(join(root, f.Path), maxScanBytes)
		if !ok {
			continue
		}
		// Literals (whole-file).
		for _, u := range urlRe.FindAllString(raw, 64) {
			urls = append(urls, trimURL(u))
		}
		domains = append(domains, domainRe.FindAllString(raw, 64)...)
		ips = append(ips, ipv4Re.FindAllString(raw, 64)...)
		ips = append(ips, ipv6Re.FindAllString(raw, 64)...)

		lines := strings.Split(raw, "\n")
		longLines := 0
		for ln, line := range lines {
			if len(line) > maxLineLen {
				longLines++
			}
			if indCount >= maxIndicators {
				sc.Dropped++
				continue
			}
			for _, rule := range indicatorRules {
				if rule.exts != nil && !rule.exts[ext] {
					continue
				}
				if rule.exts == nil && f.Kind != "script" && f.Kind != "text" {
					continue
				}
				if rule.re.MatchString(line) {
					sc.Indicators = append(sc.Indicators, sandbox.Indicator{
						Rule: rule.id, Severity: rule.severity, File: f.Path, Line: ln + 1,
						Snippet: clampStr(strings.TrimSpace(line), 160), Description: rule.desc,
					})
					indCount++
					if indCount >= maxIndicators {
						break
					}
				}
			}
		}
		// Obfuscation heuristics, one indicator per file at most.
		if indCount < maxIndicators {
			if obf := obfuscationIndicator(f.Path, ext, raw, longLines); obf != nil {
				sc.Indicators = append(sc.Indicators, *obf)
				indCount++
			}
		}
	}
	sc.URLs, _ = dedupeCap(normalizeAll(urls, strings.ToLower), maxLiterals)
	sc.Domains, _ = dedupeCap(normalizeAll(domains, strings.ToLower), maxLiterals)
	sc.IPs, _ = dedupeCap(ips, maxLiterals)
	return sc
}

// obfuscationIndicator flags a file as obfuscated based on long lines, a packed-identifier look (JS), or a very
// long high-entropy string literal.
func obfuscationIndicator(file, ext, raw string, longLines int) *sandbox.Indicator {
	if longLines > 0 && (ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts") {
		return &sandbox.Indicator{Rule: "obf-long-lines", Severity: "medium", File: file,
			Description: "very long source lines (minified/packed code)", Snippet: "lines over 2000 chars"}
	}
	if s := longestToken(raw); len(s) >= 200 && entropy([]byte(s)) >= 4.2 {
		return &sandbox.Indicator{Rule: "obf-high-entropy", Severity: "medium", File: file,
			Description: "long high-entropy string (possible packed/encoded payload)",
			Snippet:     clampStr(s, 80)}
	}
	if (ext == ".js" || ext == ".mjs" || ext == ".cjs") && packedJS(raw) {
		return &sandbox.Indicator{Rule: "obf-packed-js", Severity: "medium", File: file,
			Description: "packed-identifier JavaScript (\\x hex escapes / _0x names)", Snippet: "obfuscated identifiers"}
	}
	return nil
}

var packedJSRe = regexp.MustCompile(`_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}`)

func packedJS(raw string) bool {
	return len(packedJSRe.FindAllString(raw, 6)) >= 5
}

// longestToken returns the longest run of base64/hex-ish characters in the text.
func longestToken(raw string) string {
	best, cur := 0, 0
	bestEnd := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' {
			cur++
			if cur > best {
				best, bestEnd = cur, i+1
			}
		} else {
			cur = 0
		}
	}
	if best == 0 {
		return ""
	}
	return raw[bestEnd-best : bestEnd]
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// trimURL strips trailing source punctuation (quotes, closing brackets, commas, semicolons) that the greedy URL
// regex can swallow when a URL sits inside a string literal or call.
func trimURL(u string) string {
	u = strings.TrimRight(u, "'\")>;,.]}")
	// Balance a trailing ')' only if there is no matching '('.
	if strings.HasSuffix(u, ")") && strings.Count(u, "(") < strings.Count(u, ")") {
		u = strings.TrimRight(u, ")")
	}
	return u
}

func normalizeAll(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
