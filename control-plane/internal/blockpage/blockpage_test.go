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
