// Package blockpage renders customizable block pages.
//
// Templates are rendered by the control-plane into "shells": complete HTML documents and CLI texts
// in which request-specific values appear as placeholders (%%AEGIS:<key>%%). Data-plane workers
// receive the shells in their policy bundle and only substitute escaped values in a single pass,
// so all layout, branding and localization logic lives here and is previewable in the console.
package blockpage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"

	"aegisproxy/control-plane/internal/models"
)

// Locales supported by the built-in texts.
var Locales = []string{"en", "de"}

// Variants: "request" for policy blocks (self-service possible), "threat" for threat-protection
// and quarantine blocks (no self-service).
var Variants = []string{"request", "threat"}

// Placeholder keys substituted by the data-plane. Values are HTML-escaped (HTML shells) or stripped
// of control characters (CLI shells), except the raw keys documented in RawKeys.
var Keys = []string{"status", "verdict", "reason", "server_hostname", "server_ip", "groups", "method", "url",
	"trace_id", "public_url", "portal_url", "suggested", "suggested_host", "nonce", "data_json", "logo", "cli_payload"}

// RawKeys are inserted without HTML escaping: nonce (URL-safe random), data_json (JSON with "<"
// escaped) and logo (validated data: URL, also checked by the data-plane).
var RawKeys = []string{"nonce", "data_json", "logo"}

func ph(key string) string { return "%%AEGIS:" + key + "%%" }

// Shells is the rendered output for one template and locale.
type Shells struct {
	RequestHTML string `json:"request_html"`
	ThreatHTML  string `json:"threat_html"`
	RequestCLI  string `json:"request_cli"`
	ThreatCLI   string `json:"threat_cli"`
}

// Variables admins can use in template texts.
var textVars = map[string]string{
	"hostname": "server_hostname", "ip": "server_ip", "url": "url", "host": "suggested_host", "trace_id": "trace_id",
	"groups": "groups", "verdict": "verdict", "reason": "reason", "method": "method",
}

var varRe = regexp.MustCompile(`\{([a-z_]+)\}`)

// expandText turns admin text into display text: "{hostname}" etc. become placeholders, "{company}"
// the company name. Literal placeholder syntax in admin input is neutralized.
func expandText(text, company string) string {
	text = strings.ReplaceAll(text, "%%", "%")
	return varRe.ReplaceAllStringFunc(text, func(m string) string {
		name := m[1 : len(m)-1]
		if name == "company" {
			return strings.ReplaceAll(company, "%%", "%")
		}
		if key, ok := textVars[name]; ok {
			return ph(key)
		}
		return m
	})
}

func paragraphs(text string) []string {
	var out []string
	for _, p := range regexp.MustCompile(`\n\s*\n`).Split(strings.TrimSpace(text), -1) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type strs map[string]string

var builtin = map[string]strs{
	"en": {
		"title":           "Outbound access blocked",
		"message":         "This server tried to reach a destination that is not on its allow list. Outbound connections are denied by default.",
		"threat_title":    "Destination blocked by threat protection",
		"threat_message":  "This request was stopped by {company} threat protection (malware, phishing, command-and-control or data-loss prevention). Self-service access is not available. If you believe this is a false positive, contact the security team and quote the trace ID.",
		"reason":          "Reason",
		"server":          "Server",
		"groups":          "Server groups",
		"url":             "Blocked URL",
		"trace":           "Trace ID",
		"suggested":       "Suggested rule",
		"request_heading": "Request access",
		"request_intro":   "Requests are reviewed by the responsible team. The server identity and URL are attested by the proxy.",
		"requester":       "Your name, e-mail or change ticket",
		"scope":           "Requested scope",
		"duration":        "Duration",
		"justification":   "Business or technical justification",
		"submit":          "Submit access request",
		"submitting":      "Submitting…",
		"request_id":      "Request ID",
		"portal":          "Prefer the console? Open the self-service portal",
		"scope_prefix":    "Path prefix and linked download objects",
		"scope_exact":     "Exact URL path only",
		"scope_domain":    "Entire domain",
		"scope_learning":  "15-minute learning session for this server",
		"dur_1h":          "1 hour",
		"dur_24h":         "24 hours",
		"dur_7d":          "7 days",
		"dur_permanent":   "Permanent",
		"support":         "Need help?",
		"ca_heading":      "Trust the enterprise root CA",
		"ca_intro":        "Install the root certificate to avoid TLS errors on this server. Compare the installer's SHA-256 with the value shown in the AegisProxy console (TLS & CA) before running it:",
		"ca_pem":          "Download CA (PEM)",
		"ca_der":          "Download CA (DER)",
		"cli_blocked":     "ACCESS BLOCKED",
		"cli_request":     "REQUEST ACCESS",
		"cli_browser":     "In a browser",
		"cli_cli":         "From this server (replace the reason)",
		"cli_threat":      "Blocked by threat protection — self-service is not available. Contact the security team with the trace ID.",
		"cli_ca":          "INSTALL THE ROOT CA",
		"cli_ca_verify":   "Compare the installer's SHA-256 with the AegisProxy console (TLS & CA) before running it.",
		"powered":         "Protected by AegisProxy",
	},
	"de": {
		"title":           "Ausgehender Zugriff blockiert",
		"message":         "Dieser Server hat versucht, ein Ziel zu erreichen, das nicht freigegeben ist. Ausgehende Verbindungen sind standardmäßig gesperrt.",
		"threat_title":    "Ziel durch Threat Protection blockiert",
		"threat_message":  "Diese Anfrage wurde durch die Threat Protection von {company} gestoppt (Malware, Phishing, Command-and-Control oder Data Loss Prevention). Eine Self-Service-Freigabe ist nicht möglich. Bei einem Fehlalarm wenden Sie sich bitte mit der Trace-ID an das Security-Team.",
		"reason":          "Grund",
		"server":          "Server",
		"groups":          "Servergruppen",
		"url":             "Blockierte URL",
		"trace":           "Trace-ID",
		"suggested":       "Vorgeschlagene Regel",
		"request_heading": "Zugriff beantragen",
		"request_intro":   "Anträge werden vom verantwortlichen Team geprüft. Server-Identität und URL werden vom Proxy bestätigt.",
		"requester":       "Ihr Name, E-Mail oder Change-Ticket",
		"scope":           "Gewünschter Umfang",
		"duration":        "Dauer",
		"justification":   "Fachliche oder technische Begründung",
		"submit":          "Antrag absenden",
		"submitting":      "Wird gesendet…",
		"request_id":      "Antrags-ID",
		"portal":          "Lieber in der Konsole? Self-Service-Portal öffnen",
		"scope_prefix":    "Pfad-Präfix inklusive verlinkter Download-Objekte",
		"scope_exact":     "Nur exakter URL-Pfad",
		"scope_domain":    "Gesamte Domain",
		"scope_learning":  "15-minütige Lernsitzung für diesen Server",
		"dur_1h":          "1 Stunde",
		"dur_24h":         "24 Stunden",
		"dur_7d":          "7 Tage",
		"dur_permanent":   "Dauerhaft",
		"support":         "Hilfe benötigt?",
		"ca_heading":      "Unternehmens-Root-CA vertrauen",
		"ca_intro":        "Installieren Sie das Root-Zertifikat, um TLS-Fehler auf diesem Server zu vermeiden. Vergleichen Sie vor dem Ausführen den SHA-256 des Installers mit dem Wert in der AegisProxy-Konsole (TLS & CA):",
		"ca_pem":          "CA herunterladen (PEM)",
		"ca_der":          "CA herunterladen (DER)",
		"cli_blocked":     "ZUGRIFF BLOCKIERT",
		"cli_request":     "ZUGRIFF BEANTRAGEN",
		"cli_browser":     "Im Browser",
		"cli_cli":         "Direkt von diesem Server (Begründung ersetzen)",
		"cli_threat":      "Durch Threat Protection blockiert — keine Self-Service-Freigabe möglich. Bitte das Security-Team mit der Trace-ID kontaktieren.",
		"cli_ca":          "ROOT-CA INSTALLIEREN",
		"cli_ca_verify":   "SHA-256 des Installers vor dem Ausführen mit der AegisProxy-Konsole (TLS & CA) vergleichen.",
		"powered":         "Geschützt durch AegisProxy",
	},
}

func normLocale(l string) string {
	for _, x := range Locales {
		if x == l {
			return l
		}
	}
	return "en"
}

type option struct{ Value, Label string }

type viewModel struct {
	T              strs
	Lang           string
	Company        string
	Logo           bool
	Title          string
	Paragraphs     []string
	Threat         bool
	ShowForm       bool
	ShowCA         bool
	ShowDetails    bool
	ShowSuggested  bool
	Scopes         []option
	Durations      []option
	Support        models.SupportContact
	HasSupport     bool
	Links          []models.LinkItem
	Footer         []string
	CSS            template.CSS
	SubmittingText string
	RequestIDText  string
}

const pageTmpl = `<!DOCTYPE html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><meta name="referrer" content="no-referrer"><title>{{.Title}}</title>
<style nonce="%%AEGIS:nonce%%">{{.CSS}}</style></head>
<body><div class="wrap">
<header class="brand">{{if .Logo}}<img class="logo" src="%%AEGIS:logo%%" alt="">{{end}}<span class="company">{{.Company}}</span></header>
<main class="card">
<div class="badge {{if .Threat}}threat{{end}}"><span class="dot"></span>HTTP %%AEGIS:status%% · %%AEGIS:verdict%%</div>
<h1>{{.Title}}</h1>
{{range .Paragraphs}}<p class="lead">{{.}}</p>{{end}}
<p class="reason"><strong>{{.T.reason}}:</strong> %%AEGIS:reason%%</p>
{{if .ShowDetails}}<dl class="grid">
<div><dt>{{.T.server}}</dt><dd>%%AEGIS:server_hostname%% (%%AEGIS:server_ip%%)</dd></div>
<div><dt>{{.T.groups}}</dt><dd>%%AEGIS:groups%%</dd></div>
<div class="wide"><dt>{{.T.url}}</dt><dd>[%%AEGIS:method%%] %%AEGIS:url%%</dd></div>
<div><dt>{{.T.trace}}</dt><dd>%%AEGIS:trace_id%%</dd></div>
{{if and .ShowSuggested (not .Threat)}}<div><dt>{{.T.suggested}}</dt><dd>%%AEGIS:suggested%%</dd></div>{{end}}
</dl>{{end}}
{{if .ShowForm}}<section class="request">
<h2>{{.T.request_heading}}</h2><p class="muted">{{.T.request_intro}}</p>
<form id="rq" data-submitting="{{.SubmittingText}}" data-request-id="{{.RequestIDText}}">
<label for="requester">{{.T.requester}}</label><input id="requester" required maxlength="200" autocomplete="email">
<div class="row"><div><label for="scope">{{.T.scope}}</label><select id="scope">{{range .Scopes}}<option value="{{.Value}}">{{.Label}}</option>{{end}}</select></div>
<div><label for="duration">{{.T.duration}}</label><select id="duration">{{range .Durations}}<option value="{{.Value}}">{{.Label}}</option>{{end}}</select></div></div>
<label for="reason">{{.T.justification}}</label><textarea id="reason" rows="3" required maxlength="2000"></textarea>
<button type="submit">{{.T.submit}}</button></form>
<div id="st" role="status" aria-live="polite"></div>
<p class="muted small"><a href="%%AEGIS:portal_url%%" rel="noopener noreferrer">{{.T.portal}}</a></p>
</section>{{end}}
{{if .HasSupport}}<section class="support"><h2>{{if .Support.Label}}{{.Support.Label}}{{else}}{{.T.support}}{{end}}</h2><ul>
{{if .Support.Email}}<li><a href="mailto:{{.Support.Email}}">{{.Support.Email}}</a></li>{{end}}
{{if .Support.Phone}}<li><a href="tel:{{.Support.Phone}}">{{.Support.Phone}}</a></li>{{end}}
{{if .Support.URL}}<li><a href="{{.Support.URL}}" rel="noopener noreferrer">{{.Support.URL}}</a></li>{{end}}
</ul></section>{{end}}
{{if .Links}}<nav class="links">{{range .Links}}<a href="{{.URL}}" rel="noopener noreferrer">{{.Label}}</a>{{end}}</nav>{{end}}
</main>
{{if .ShowCA}}<section class="card ca"><h2>{{.T.ca_heading}}</h2><p class="muted">{{.T.ca_intro}}</p>
<pre>d=$(mktemp -d)
curl -fsSLo "$d/aegis-ca-install.sh" %%AEGIS:public_url%%/api/public/ca/install-linux.sh
sha256sum "$d/aegis-ca-install.sh"
sudo bash "$d/aegis-ca-install.sh"; rm -rf "$d"</pre>
<pre>$d = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('aegis-ca-' + [guid]::NewGuid())); $f = Join-Path $d.FullName 'aegis-ca-install.ps1'
iwr -UseBasicParsing %%AEGIS:public_url%%/api/public/ca/install-windows.ps1 -OutFile $f
Get-FileHash $f -Algorithm SHA256
powershell -NoProfile -ExecutionPolicy Bypass -File $f; Remove-Item -Recurse $d.FullName</pre>
<p class="small"><a href="%%AEGIS:public_url%%/api/public/ca/aegis-ca.crt">{{.T.ca_pem}}</a> · <a href="%%AEGIS:public_url%%/api/public/ca/aegis-ca.der">{{.T.ca_der}}</a></p></section>{{end}}
<footer>{{range .Footer}}<p>{{.}}</p>{{end}}<p class="powered">{{.T.powered}}</p></footer>
</div>
<script type="application/json" id="aegis-data">%%AEGIS:data_json%%</script>
{{if .ShowForm}}<script nonce="%%AEGIS:nonce%%">
(function(){var d=JSON.parse(document.getElementById('aegis-data').textContent),f=document.getElementById('rq'),s=document.getElementById('st');
f.addEventListener('submit',function(ev){ev.preventDefault();s.className='show';s.textContent=f.getAttribute('data-submitting');
fetch(d.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({block_token:d.block_token,
requester:document.getElementById('requester').value,requested_scope:document.getElementById('scope').value,
duration:document.getElementById('duration').value,reason:document.getElementById('reason').value})})
.then(function(r){return r.json().then(function(j){s.className='show '+(r.ok?'ok':'err');s.textContent=(j.message||j.error||'')+(j.request?' ('+f.getAttribute('data-request-id')+': '+j.request.id+')':'');});})
.catch(function(e){s.className='show err';s.textContent=e.message;});});})();
</script>{{end}}
</body></html>`

var page = template.Must(template.New("page").Parse(pageTmpl))

var hexRe = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func color(c, def string) string {
	if hexRe.MatchString(c) {
		return c
	}
	return def
}

func css(t models.BlockPageTemplate) string {
	primary := color(t.PrimaryColor, "#2563EB")
	accent := color(t.AccentColor, "#DC2626")
	light := `--bg:#f5f7fb;--card:#ffffff;--border:#e3e8f0;--text:#0f172a;--muted:#5b6b82;--code:#0f172a;--codetext:#e2e8f0;`
	dark := `--bg:#0a1020;--card:#111a2e;--border:#24324d;--text:#e6edf7;--muted:#9fb0c8;--code:#060b16;--codetext:#d7e2f2;`
	var vars string
	switch t.Theme {
	case "dark":
		vars = ":root{" + dark + "}"
	case "light":
		vars = ":root{" + light + "}"
	default:
		vars = ":root{" + light + "}@media (prefers-color-scheme:dark){:root{" + dark + "}}"
	}
	return vars + fmt.Sprintf(`:root{--primary:%s;--accent:%s}`, primary, accent) + `
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:28px 16px 40px}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:18px;min-height:40px}.logo{max-height:40px;max-width:200px}.company{font-weight:650;font-size:17px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:16px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 8px 24px rgba(15,23,42,.05)}
.badge{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:999px;font-size:12px;font-weight:650;letter-spacing:.02em;color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent)}
.badge .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
h1{font-size:24px;line-height:1.25;margin:16px 0 8px}h2{font-size:16px;margin:0 0 6px}
.lead{color:var(--muted);margin:6px 0}.reason{margin:14px 0 0;padding:10px 14px;border-left:3px solid var(--accent);background:color-mix(in srgb,var(--accent) 6%,transparent);border-radius:6px;font-size:14px}
.muted{color:var(--muted)}.small{font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:20px 0 4px;padding:16px;border:1px solid var(--border);border-radius:12px}
.grid .wide{grid-column:1/-1}dt{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:650;margin-bottom:3px}
dd{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.request{margin-top:24px;padding-top:20px;border-top:1px solid var(--border)}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:560px){.row{grid-template-columns:1fr}.card{padding:20px}}
input,select,textarea{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit;font-size:14px}
input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--primary) 45%,transparent);outline-offset:1px}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:9px;background:var(--primary);color:#fff;font:inherit;font-weight:650;cursor:pointer}
button:hover{filter:brightness(1.07)}a{color:var(--primary)}
#st{display:none;margin-top:14px;padding:12px;border-radius:9px;border:1px solid var(--border);font-size:14px}#st.show{display:block}#st.ok{border-color:#16a34a}#st.err{border-color:#dc2626}
.support{margin-top:22px;padding-top:18px;border-top:1px solid var(--border)}.support ul{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:8px 18px;font-size:14px}
.links{display:flex;flex-wrap:wrap;gap:8px;margin-top:20px}.links a{padding:6px 12px;border:1px solid var(--border);border-radius:999px;text-decoration:none;font-size:13px}
pre{background:var(--code);color:var(--codetext);padding:14px;border-radius:10px;overflow-x:auto;font-size:12.5px}
footer{text-align:center;color:var(--muted);font-size:12.5px;margin-top:8px}footer p{margin:4px 0}.powered{opacity:.75}
`
}

func durationLabel(t strs, d string) string {
	switch d {
	case "1h":
		return t["dur_1h"]
	case "24h":
		return t["dur_24h"]
	case "7d":
		return t["dur_7d"]
	case "permanent":
		return t["dur_permanent"]
	}
	return d
}

func scopeLabel(t strs, s string) string {
	switch s {
	case "prefix_with_objects":
		return t["scope_prefix"] + " (" + ph("suggested") + ")"
	case "exact_path":
		return t["scope_exact"]
	case "domain":
		return t["scope_domain"] + " (" + ph("suggested_host") + ")"
	case "learning_session_15m":
		return t["scope_learning"]
	}
	return s
}

// Render produces the shells of one template in one locale.
func Render(t models.BlockPageTemplate, locale string) (Shells, error) {
	locale = normLocale(locale)
	tr := strs{}
	for k, v := range builtin[locale] {
		tr[k] = expandText(v, companyName(t))
	}
	var out Shells
	for _, variant := range Variants {
		threat := variant == "threat"
		vm := viewModel{T: tr, Lang: locale, Company: companyName(t), Logo: t.LogoDataURL != "", Threat: threat,
			ShowCA: t.ShowCASection, ShowDetails: t.ShowTechnicalDetails, ShowSuggested: t.ShowSuggestedRule,
			Support: t.Support, Links: t.Links, SubmittingText: tr["submitting"], RequestIDText: tr["request_id"]}
		vm.HasSupport = t.Support.Email != "" || t.Support.Phone != "" || t.Support.URL != ""
		vm.CSS = template.CSS(css(t))
		if threat {
			vm.Title = tr["threat_title"] // the custom title is for policy blocks; threat texts use ThreatMessage
			vm.Paragraphs = paragraphs(firstNonEmpty(expandText(t.ThreatMessage, companyName(t)), tr["threat_message"]))
		} else {
			vm.Title = firstNonEmpty(expandText(t.Title, companyName(t)), tr["title"])
			vm.Paragraphs = paragraphs(firstNonEmpty(expandText(t.Message, companyName(t)), tr["message"]))
			vm.ShowForm = t.ShowRequestForm
			for _, s := range t.AllowedScopes {
				vm.Scopes = append(vm.Scopes, option{s, scopeLabel(tr, s)})
			}
			for _, d := range t.AllowedDurations {
				vm.Durations = append(vm.Durations, option{d, durationLabel(tr, d)})
			}
			if len(vm.Scopes) == 0 || len(vm.Durations) == 0 {
				vm.ShowForm = false
			}
		}
		vm.Footer = paragraphs(expandText(t.FooterText, companyName(t)))
		var buf bytes.Buffer
		if err := page.Execute(&buf, vm); err != nil {
			return Shells{}, err
		}
		cli := renderCLI(t, tr, threat)
		if threat {
			out.ThreatHTML, out.ThreatCLI = buf.String(), cli
		} else {
			out.RequestHTML, out.RequestCLI = buf.String(), cli
		}
	}
	return out, nil
}

func companyName(t models.BlockPageTemplate) string {
	if c := strings.TrimSpace(t.CompanyName); c != "" {
		return c
	}
	return "AegisProxy"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

const rule = "================================================================================\n"
const thin = "--------------------------------------------------------------------------------\n"

// CLICAInstallSteps are the CA installer steps of the terminal block messages (also the data-plane's
// blockpage.py). The installer is downloaded into a fresh private directory, its SHA-256 shown for
// comparison with the console, and exactly that file is run; never a fixed name in a shared or the
// current directory, where another local user could swap it between the check and the run.
func CLICAInstallSteps(publicURL string) string {
	return fmt.Sprintf(`    Linux:   d=$(mktemp -d); curl -fsSLo "$d/aegis-ca-install.sh" %[1]s/api/public/ca/install-linux.sh && sha256sum "$d/aegis-ca-install.sh"
             sudo bash "$d/aegis-ca-install.sh"; rm -rf "$d"
    Windows: $d = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('aegis-ca-' + [guid]::NewGuid())); $f = Join-Path $d.FullName 'aegis-ca-install.ps1'
             iwr -UseBasicParsing %[1]s/api/public/ca/install-windows.ps1 -OutFile $f; Get-FileHash $f -Algorithm SHA256
             powershell -NoProfile -ExecutionPolicy Bypass -File $f; Remove-Item -Recurse $d.FullName
`, publicURL)
}

func renderCLI(t models.BlockPageTemplate, tr strs, threat bool) string {
	var b strings.Builder
	b.WriteString(rule)
	if h := strings.TrimSpace(expandText(t.CLIHeader, companyName(t))); h != "" {
		for _, line := range strings.Split(h, "\n") {
			b.WriteString(" " + strings.TrimRight(line, " \r") + "\n")
		}
	} else {
		fmt.Fprintf(&b, " %s — %s (HTTP %s)\n", strings.ToUpper(companyName(t)), tr["cli_blocked"], ph("status"))
	}
	b.WriteString(rule)
	row := func(label, value string) { fmt.Fprintf(&b, " %-16s: %s\n", label, value) }
	row(tr["server"], ph("server_hostname")+" ("+ph("server_ip")+")")
	row(tr["groups"], ph("groups"))
	row(tr["url"], "["+ph("method")+"] "+ph("url"))
	row(tr["trace"], ph("trace_id"))
	row(tr["reason"], ph("verdict")+" — "+ph("reason"))
	b.WriteString(thin)
	if threat {
		b.WriteString(" " + tr["cli_threat"] + "\n")
	} else if t.ShowRequestForm && len(t.AllowedScopes) > 0 && len(t.AllowedDurations) > 0 {
		fmt.Fprintf(&b, " %s\n  %s:\n    %s\n\n  %s:\n    curl -sX POST %s/api/public/requests \\\n      -H \"Content-Type: application/json\" \\\n      -d %s\n",
			tr["cli_request"], tr["cli_browser"], ph("portal_url"), tr["cli_cli"], ph("public_url"), ph("cli_payload"))
	}
	if t.Support.Email != "" || t.Support.Phone != "" || t.Support.URL != "" {
		b.WriteString(thin)
		label := firstNonEmpty(t.Support.Label, tr["support"])
		b.WriteString(" " + label + "\n")
		for _, v := range []string{t.Support.Email, t.Support.Phone, t.Support.URL} {
			if v != "" {
				b.WriteString("   " + v + "\n")
			}
		}
	}
	if t.ShowCASection {
		b.WriteString(thin)
		fmt.Fprintf(&b, " %s\n  %s\n%s", tr["cli_ca"], tr["cli_ca_verify"], CLICAInstallSteps(ph("public_url")))
	}
	if f := strings.TrimSpace(expandText(t.CLIFooter, companyName(t))); f != "" {
		b.WriteString(thin)
		for _, line := range strings.Split(f, "\n") {
			b.WriteString(" " + strings.TrimRight(line, " \r") + "\n")
		}
	}
	b.WriteString(rule)
	return b.String()
}

// ---------------------------------------------------------------------------
// Substitution (reference implementation of the data-plane side, used for previews and tests)
// ---------------------------------------------------------------------------

var phRe = regexp.MustCompile(`%%AEGIS:([a-z_]+)%%`)

func isRaw(k string) bool {
	for _, r := range RawKeys {
		if r == k {
			return true
		}
	}
	return false
}

// Fill substitutes values in one pass (values are never re-scanned).
func Fill(shell string, values map[string]string, htmlMode bool) string {
	return phRe.ReplaceAllStringFunc(shell, func(m string) string {
		k := m[len("%%AEGIS:") : len(m)-2]
		v := values[k]
		if htmlMode && !isRaw(k) {
			return template.HTMLEscapeString(v)
		}
		if !htmlMode {
			return strings.Map(func(r rune) rune {
				if r < ' ' && r != '\n' || r == 0x7f {
					return -1
				}
				return r
			}, v)
		}
		return v
	})
}

// SampleValues are used for console previews.
func SampleValues(t models.BlockPageTemplate, variant, publicURL, dashboardURL string) map[string]string {
	if publicURL == "" {
		publicURL = "https://aegis.corp.example"
	}
	if dashboardURL == "" {
		dashboardURL = publicURL
	}
	verdict, reason := "BLOCKED", "No allow rule matches this destination (default deny)"
	if variant == "threat" {
		verdict, reason = "THREAT_BLOCKED", "Threat Intelligence: malware distribution (URLhaus)"
	}
	data, _ := json.Marshal(map[string]string{"endpoint": publicURL + "/api/public/requests", "block_token": "v1.preview.preview"})
	return map[string]string{
		"status": "403", "verdict": verdict, "reason": reason, "server_hostname": "build-agent-07.corp.example",
		"server_ip": "10.20.4.17", "groups": "ci-runners, linux-prod", "method": "GET",
		"url": "https://downloads.example.org/tools/v2.4/installer.tar.gz", "trace_id": "4f9c2a7e1b3d",
		"public_url": publicURL, "portal_url": dashboardURL + "/?portal=block&bt=preview",
		"suggested": "downloads.example.org/tools/**", "suggested_host": "downloads.example.org",
		"nonce": "preview", "data_json": strings.ReplaceAll(string(data), "<", `\u003c`), "logo": t.LogoDataURL,
		"cli_payload": `'{"block_token":"v1.preview.preview","requester":"root@build-agent-07","reason":"ENTER_REASON_HERE","requested_scope":"prefix_with_objects","duration":"24h"}'`,
	}
}

// CSP returns the Content-Security-Policy for a filled HTML page.
func CSP(nonce, publicURL string) string {
	origin := publicURL
	if origin == "" {
		origin = "'none'"
	}
	return fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src %s; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'", nonce, nonce, origin)
}
