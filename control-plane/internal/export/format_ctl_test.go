package export

import (
	"strings"
	"testing"
)

func TestSIEMFormatsStripControlCharacters(t *testing.T) {
	evil := "ok\x1b[31mred\x7f line\u0085next\tend"
	for name, out := range map[string]string{"cef-value": cefValueEsc.Replace(evil), "cef-header": cefHeaderEsc.Replace(evil), "leef": leefValueEsc.Replace(evil)} {
		if strings.ContainsAny(out, "\x1b\x7f \u0085\t") {
			t.Errorf("%s keeps control characters: %q", name, out)
		}
		if !strings.Contains(out, "red") || !strings.Contains(out, "end") {
			t.Errorf("%s lost content: %q", name, out)
		}
	}
}
