package store

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLintYara(t *testing.T) {
	valid, err := os.ReadFile("testdata/yara_valid.yar")
	if err != nil {
		t.Fatal(err)
	}
	if err := lintYara(string(valid)); err != nil {
		t.Fatalf("valid rules rejected: %v", err)
	}
	for src, want := range map[string]string{
		`rule x { condition: }`:                                   "condition of rule x is empty",
		`rule { condition: true }`:                                "needs a name",
		`rule a { strings: $a = "x" }`:                            "no condition",
		`rule a { condition: true`:                                "unbalanced",
		"rule a { condition: true }\nrule a { condition: false }": "duplicate rule name",
		"rule a { strings: $a = \"open\n condition: $a }":         "unterminated text string",
		`rule a { strings: $a = /abc condition: $a }`:             "unterminated regular expression",
		`rule a extra { condition: true }`:                        "unexpected",
		`rule a { condition: true } }`:                            "unexpected '}'",
		`/* never closed rule a { condition: true }`:              "unterminated comment",
		`import "pe"`: "no rule found",
		"rule a {\nrule b {\ncondition: true\n}}": "inside another rule",
	} {
		err := lintYara(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("lintYara(%q) = %v, want error containing %q", src, err, want)
		}
	}
}

func TestLintYaraIsLinear(t *testing.T) {
	// Compares 32 KiB with 256 KiB instead of an absolute time limit (race detector, loaded CI hosts): linear
	// work grows ~8x, a quadratic scan ~64x. The fastest of three runs filters out scheduling noise.
	rules := func(size int) string {
		var b strings.Builder
		for b.Len() < size {
			b.WriteString("rule r")
			b.WriteString(strconv.Itoa(b.Len()))
			b.WriteString(" { strings: $a = /a\\/b/ condition: $a and filesize \\\\ 2 > 1 }\n")
		}
		return b.String()
	}
	fastest := func(src string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 3 {
			start := time.Now()
			if err := lintYara(src); err != nil {
				t.Fatal(err)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	small, large := fastest(rules(32<<10)), fastest(rules(256<<10))
	if large > 24*max(small, time.Millisecond) {
		t.Fatalf("lint of 256 KiB took %v, 32 KiB %v: not linear", large, small)
	}
}
