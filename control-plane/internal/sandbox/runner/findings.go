package runner

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// exfilHostPatterns are substrings of hostnames that are characteristic of data-exfiltration / C2 drops.
var exfilHostPatterns = []string{
	".onion", "pastebin.", "hastebin.", "webhook.site", "requestbin", "requestb.in", "interactsh",
	"burpcollaborator", "oast.", "ngrok.io", "ngrok-free", "trycloudflare.com", "api.telegram.org",
	"discord.com/api/webhooks", "dnslog.", "canarytokens",
}

// shellBins are interpreters/downloaders whose appearance as a spawned process is notable.
var shellBins = map[string]string{
	"sh": "shell", "bash": "shell", "dash": "shell", "zsh": "shell", "ksh": "shell",
	"curl": "downloader", "wget": "downloader", "powershell": "powershell", "pwsh": "powershell",
	"nc": "netcat", "ncat": "netcat", "socat": "netcat", "python": "interpreter", "python3": "interpreter",
	"perl": "interpreter", "ruby": "interpreter", "node": "interpreter", "base64": "decoder", "xxd": "decoder",
}

// persistencePatterns map a written path to a persistence mechanism.
func persistenceKind(p string) string {
	low := strings.ToLower(p)
	base := path.Base(low)
	switch {
	case strings.HasSuffix(base, ".pth"):
		return "python .pth startup file"
	case base == ".bashrc" || base == ".bash_profile" || base == ".profile" || base == ".zshrc" || base == ".zprofile":
		return "shell startup file"
	case strings.Contains(low, "/.config/autostart/"):
		return "desktop autostart entry"
	case strings.Contains(low, "/cron") || strings.Contains(low, "/.crontab"):
		return "cron job"
	case strings.Contains(low, "/.config/systemd/user/") || strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".timer"):
		return "systemd user unit"
	case strings.Contains(low, "/.ssh/authorized_keys"):
		return "SSH authorized_keys"
	case base == ".npmrc" || base == ".bash_logout":
		return "shell/package config"
	}
	return ""
}

type findingAccum struct {
	byKey map[string]*sandbox.Finding
	order []string
}

func newFindingAccum() *findingAccum { return &findingAccum{byKey: map[string]*sandbox.Finding{}} }

func (a *findingAccum) add(id, sev, cat, phase, title, detail string, evidence ...string) {
	key := id + "|" + phase
	f, ok := a.byKey[key]
	if !ok {
		f = &sandbox.Finding{ID: id, Severity: sev, Category: cat, Phase: phase, Title: title, Detail: detail}
		a.byKey[key] = f
		a.order = append(a.order, key)
	}
	if severityRank(sev) > severityRank(f.Severity) {
		f.Severity = sev
	}
	for _, e := range evidence {
		if e != "" && len(f.Evidence) < 12 && !contains(f.Evidence, e) {
			f.Evidence = append(f.Evidence, clampStr(e, 300))
		}
	}
}

func (a *findingAccum) list() []sandbox.Finding {
	out := make([]sandbox.Finding, 0, len(a.order))
	for _, k := range a.order {
		out = append(out, *a.byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// DeriveFindings turns the static and dynamic data already in rep into Findings with stable IDs and severities.
func DeriveFindings(rep *sandbox.Report) []sandbox.Finding {
	a := newFindingAccum()
	deriveStaticFindings(a, rep)
	for i := range rep.Phases {
		derivePhaseFindings(a, &rep.Phases[i])
	}
	return a.list()
}

func deriveStaticFindings(a *findingAccum, rep *sandbox.Report) {
	s := rep.Static
	// Install hooks.
	for _, h := range s.InstallHooks {
		sev := "low"
		switch h.Kind {
		case "npm-script", "setup-py", "nuget-ps", "ps-scripts-to-process", "msbuild-targets", "pth":
			sev = "medium"
		}
		a.add("SBX-HOOK", sev, "install-hook", "static", "Package runs code on install/build",
			"The package declares hooks that execute during installation or build.",
			h.Kind+": "+h.Name)
	}
	// Native binaries.
	if len(s.NativeBinaries) > 0 {
		ev := make([]string, 0, 4)
		for i, f := range s.NativeBinaries {
			if i >= 4 {
				break
			}
			ev = append(ev, f.Path)
		}
		a.add("SBX-NATIVE", "low", "native", "static", "Package ships native executable code",
			"The package contains compiled binaries (ELF/PE/Mach-O/.node/.so/.dll) that cannot be inspected as source.", ev...)
	}
	// Signatures.
	for _, sig := range s.Signatures {
		if sig.Verified != nil && !*sig.Verified {
			a.add("SBX-SIG-INVALID", "high", "signature", "static", "Embedded signature failed verification",
				"A signature embedded in the artifact did not verify.", sig.File+": "+sig.Detail)
		}
	}
	// Static indicators, grouped by severity into one finding each.
	for _, ind := range s.Indicators {
		a.add("SBX-STATIC-"+strings.ToUpper(ind.Severity), ind.Severity, "obfuscation", "static",
			"Suspicious code patterns found by static inspection",
			"Static scanning flagged patterns that often indicate malicious or install-time behavior.",
			fmt.Sprintf("%s %s:%d %s", ind.Rule, ind.File, ind.Line, ind.Snippet))
		if strings.HasPrefix(ind.Rule, "obf-") {
			a.add("SBX-OBFUSCATION", "medium", "obfuscation", "static", "Obfuscated code",
				"The package contains obfuscated or packed code.", ind.File+": "+ind.Rule)
		}
	}
}

func derivePhaseFindings(a *findingAccum, p *sandbox.Phase) {
	phase := p.Name
	if p.Skipped != "" {
		return
	}
	if p.TimedOut {
		a.add("SBX-TIMEOUT", "medium", "runtime", phase, "Scenario did not finish within the timeout",
			"The phase was killed at the timeout; it may be waiting on network, sleeping to evade analysis, or stuck.",
			fmt.Sprintf("%s ran for %dms", phase, p.DurationMs))
	}

	// Canary hits.
	for _, c := range p.CanaryHits {
		if c.Where == "file" {
			a.add("SBX-CRED-READ", "high", "credentials", phase, "Package read a planted credential file",
				"The code opened a decoy credential/secret file. A legitimate package has no reason to read developer secrets.",
				c.Canary+": "+c.Detail)
		} else {
			a.add("SBX-CRED-EXFIL", "critical", "credentials", phase, "Planted secret left the sandbox in traffic",
				"A unique marker from a decoy secret appeared in outbound "+c.Where+" traffic — the package is exfiltrating credentials.",
				c.Canary+" via "+c.Where+": "+c.Detail)
		}
	}

	// Network.
	net := p.Network
	netSeen := len(net.DNS) > 0 || len(net.HTTP) > 0 || hasRealConnect(net.Connections)
	if netSeen {
		sev := "high"
		id, title := "SBX-NET-INSTALL", "Network access during install"
		detail := "The package tried to reach the network while installing/building. Install-time network access is a common supply-chain attack vector."
		if phase == sandbox.ScenarioLoad {
			sev = "medium"
			id, title = "SBX-NET-LOAD", "Network access when the module is loaded"
			detail = "The package tried to reach the network simply on import/require/load."
		}
		ev := networkEvidence(net)
		// Escalate on raw-IP targets or known exfil-style hosts.
		if raw := rawIPTargets(net); len(raw) > 0 {
			sev = "high"
			ev = append(ev, raw...)
		}
		if ex := exfilHosts(net); len(ex) > 0 {
			sev = "critical"
			ev = append(ev, ex...)
		}
		a.add(id, sev, "network", phase, title, detail, ev...)
	}

	// Processes: shells / downloaders / interpreters spawned.
	for _, proc := range p.Processes {
		base := path.Base(proc.Exe)
		if base == "" && len(proc.Argv) > 0 {
			base = path.Base(proc.Argv[0])
		}
		if kind, ok := shellBins[base]; ok {
			sev := "medium"
			if phase == sandbox.ScenarioInstall {
				sev = "high"
			}
			if kind == "downloader" || kind == "netcat" || kind == "powershell" {
				sev = "high"
			}
			a.add("SBX-PROC-SPAWN", sev, "process", phase, "Package spawned a shell / downloader / interpreter",
				"The code executed an external program ("+kind+"). This is unusual for install/load and is a common execution primitive for malware.",
				clampStr(strings.Join(proc.Argv, " "), 200))
		}
	}

	// Filesystem writes & persistence.
	for _, w := range p.Files.Written {
		if kind := persistenceKind(w.Path); kind != "" {
			a.add("SBX-PERSIST", "high", "filesystem", phase, "Package wrote a persistence / autostart location",
				"The code wrote to a location used to persist across logins/reboots ("+kind+").",
				w.Path)
		} else {
			a.add("SBX-FS-WRITE", "medium", "filesystem", phase, "Package wrote outside its own directory",
				"The code wrote files outside the package directory and temp space.", w.Path)
		}
	}

	// Privilege / evasion syscalls.
	for _, se := range p.Syscalls.Events {
		switch se.Category {
		case "privilege":
			a.add("SBX-PRIV", "high", "runtime", phase, "Privilege / namespace / mount operation",
				"The code attempted a privileged operation (setuid/capset/mount/chroot/namespace).",
				se.Syscall+"("+se.Args+")")
		case "evasion":
			a.add("SBX-EVASION", "high", "runtime", phase, "Anti-analysis behavior",
				"The code used syscalls associated with anti-debugging / sandbox evasion.",
				se.Syscall+"("+se.Args+")")
		}
	}
}

func hasRealConnect(conns []sandbox.Connection) bool {
	for _, c := range conns {
		if c.Protocol == "unix" {
			continue
		}
		return true
	}
	return false
}

func networkEvidence(n sandbox.Network) []string {
	var ev []string
	for i, q := range n.DNS {
		if i >= 6 {
			break
		}
		ev = append(ev, "DNS "+q.Type+" "+q.Name)
	}
	for i, h := range n.HTTP {
		if i >= 6 {
			break
		}
		ev = append(ev, h.Method+" "+h.URL)
	}
	for i, c := range n.Connections {
		if i >= 6 {
			break
		}
		if c.Protocol == "unix" {
			continue
		}
		ev = append(ev, fmt.Sprintf("connect %s:%d %s", c.Address, c.Port, c.Result))
	}
	return ev
}

func rawIPTargets(n sandbox.Network) []string {
	var out []string
	for _, c := range n.Connections {
		ip := net.ParseIP(c.Address)
		if ip == nil || c.Hostname != "" {
			continue
		}
		if ip.IsLoopback() || isSandboxIP(ip) {
			continue
		}
		out = append(out, "raw IP connect "+c.Address)
	}
	for _, h := range n.HTTP {
		host := h.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !isSandboxIP(ip) {
			out = append(out, "HTTP to raw IP "+host)
		}
	}
	return out
}

func isSandboxIP(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 127
}

func exfilHosts(n sandbox.Network) []string {
	var out []string
	check := func(s string) {
		low := strings.ToLower(s)
		for _, pat := range exfilHostPatterns {
			if strings.Contains(low, pat) {
				out = append(out, "exfil-style host "+s)
				return
			}
		}
	}
	for _, q := range n.DNS {
		check(q.Name)
	}
	for _, h := range n.HTTP {
		check(h.URL)
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
