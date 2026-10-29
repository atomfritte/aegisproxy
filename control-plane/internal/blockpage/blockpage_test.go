package blockpage

import (
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func tpl() models.BlockPageTemplate {
	return models.BlockPageTemplate{
		Name: "t", CompanyName: "ACME <Corp>", PrimaryColor: "#112233", AccentColor: "#445566", Theme: "auto",
		Title: "Blocked on {hostname}", Message: "Para one %%AEGIS:nonce%% {company}\n\nPara two {url}",
		ShowRequestForm: true, ShowCASection: true, ShowTechnicalDetails: true,
		AllowedScopes: []string{"exact_path"}, AllowedDurations: []string{"1h"}, DefaultLocale: "en",
		Support: models.SupportContact{Email: "help@acme.example", URL: "https://help.acme.example"},
		Links:   []models.LinkItem{{Label: "Policy", URL: "https://wiki.acme.example/egress"}},
	}
}

func TestRenderAndFill(t *testing.T) {
	sh, err := Render(tpl(), "en")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sh.RequestHTML, "<Corp>") || !strings.Contains(sh.RequestHTML, "ACME &lt;Corp&gt;") {
		t.Error("company name not escaped")
	}
	if strings.Count(sh.RequestHTML, "%%AEGIS:nonce%%") != 2 { // style + script only; admin text cannot inject placeholders
		t.Errorf("nonce placeholders: %d", strings.Count(sh.RequestHTML, "%%AEGIS:nonce%%"))
	}
	if !strings.Contains(sh.RequestHTML, `value="exact_path"`) || strings.Contains(sh.RequestHTML, `value="domain"`) {
		t.Error("allowed scopes not applied")
	}
	if strings.Contains(sh.ThreatHTML, `id="rq"`) || strings.Contains(sh.ThreatHTML, "<script nonce") {
		t.Error("threat variant must not offer self-service")
	}
	vals := map[string]string{"server_hostname": `<img src=x onerror=alert(1)>`, "url": `https://x/"><script>alert(1)</script>`,
		"nonce": "abc123", "data_json": `{"a":"<"}`, "status": "403"}
	out := Fill(sh.RequestHTML, vals, true)
	if strings.Contains(out, "<img src=x") || strings.Contains(out, "<script>alert") {
		t.Error("values not escaped")
	}
	if !strings.Contains(out, "Blocked on &lt;img") {
		t.Error("{hostname} variable not expanded in the title")
	}
	if strings.Contains(out, "%%AEGIS:") {
		t.Error("unfilled placeholder left")
	}
	// Single pass: a value containing placeholder syntax is not expanded again.
	out = Fill("%%AEGIS:url%%|%%AEGIS:nonce%%", map[string]string{"url": "%%AEGIS:nonce%%", "nonce": "n"}, true)
	if out != "%%AEGIS:nonce%%|n" {
		t.Errorf("re-scanned substitution: %q", out)
	}
	cli := Fill(sh.RequestCLI, map[string]string{"url": "https://x/\x1b[31mred", "cli_payload": "'{}'"}, false)
	if strings.Contains(cli, "\x1b") {
		t.Error("control characters reach the terminal")
	}
}

// R3-5: no admin text field may carry a placeholder into a shell: not with "%%%" runs (a single "%%" → "%"
// pass leaves "%%"), not in fields that were never neutralized (company, support, links incl. URL queries),
// and not where the company name meets the surrounding text.
func TestAdminTextCannotInjectPlaceholders(t *testing.T) {
	fields := func(v string) models.BlockPageTemplate {
		bp := tpl()
		bp.CompanyName, bp.Title, bp.Message, bp.ThreatMessage, bp.FooterText, bp.CLIHeader, bp.CLIFooter = v, v, v+" %{company}%", v, v, v, v
		bp.Support = models.SupportContact{Label: v, Email: v, Phone: v, URL: "https://help.example/?q=" + v}
		bp.Links = []models.LinkItem{{Label: v, URL: "https://wiki.example/?q=" + v}}
		return bp
	}
	clean, err := Render(fields("x"), "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"%%%AEGIS:data_json%%%", "%%%%AEGIS:nonce%%%%", "%AEGIS:data_json%", "%%AEGIS:logo%%"} {
		got, err := Render(fields(v), "en")
		if err != nil {
			t.Fatal(err)
		}
		for name, pair := range map[string][2]string{"request_html": {clean.RequestHTML, got.RequestHTML}, "threat_html": {clean.ThreatHTML, got.ThreatHTML},
			"request_cli": {clean.RequestCLI, got.RequestCLI}, "threat_cli": {clean.ThreatCLI, got.ThreatCLI}} {
			if want, n := strings.Count(pair[0], "%%AEGIS:"), strings.Count(pair[1], "%%AEGIS:"); n != want {
				t.Errorf("%q: %s has %d placeholders, want %d", v, name, n, want)
			}
		}
	}
}

// R3-5: raw values (unescaped) are inserted only in their own spot of the shell.
func TestRawValuesOnlyInTheirContext(t *testing.T) {
	vals := map[string]string{"nonce": "n0", "logo": "data:image/png;base64,AA==", "data_json": `{"a":"b"}`}
	out := Fill(`<a title="%%AEGIS:data_json%%">%%AEGIS:nonce%%</a><i nonce="%%AEGIS:data_json%%"></i><img src="%%AEGIS:logo%%">`+
		`<style nonce="%%AEGIS:nonce%%"></style><script type="application/json" id="aegis-data">%%AEGIS:data_json%%</script>`, vals, true)
	want := `<a title="{&#34;a&#34;:&#34;b&#34;}">n0</a><i nonce="{&#34;a&#34;:&#34;b&#34;}"></i><img src="data:image/png;base64,AA==">` +
		`<style nonce="n0"></style><script type="application/json" id="aegis-data">{"a":"b"}</script>`
	if out != want {
		t.Errorf("Fill:\n got %s\nwant %s", out, want)
	}
}

func TestLocales(t *testing.T) {
	de, _ := Render(tpl(), "de")
	if !strings.Contains(de.RequestHTML, `lang="de"`) || !strings.Contains(de.RequestHTML, "Antrag absenden") {
		t.Error("German texts missing")
	}
	fallback, _ := Render(tpl(), "xx")
	if !strings.Contains(fallback.RequestHTML, `lang="en"`) {
		t.Error("unknown locale should fall back to English")
	}
}
