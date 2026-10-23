package store

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The control-plane has no YARA engine; lintYara catches the structural mistakes that would make
// the data-plane compiler reject a rule set (the data-plane still compiles every set and reports
// the exact compiler error in its heartbeat).

var yaraIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}`)

// stripYara replaces comments, text strings and regular expressions by spaces (keeping newlines),
// so that braces and keywords can be analysed safely.
func stripYara(src string) (string, error) {
	out := []byte(src)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	line := 1
	prevSignificant := func(i int) string {
		j := i - 1
		for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r' || out[j] == '\n') {
			j--
		}
		if j < 0 {
			return ""
		}
		if out[j] == '=' || out[j] == '(' || out[j] == ',' {
			return string(out[j])
		}
		k := j
		for k >= 0 && (out[k] >= 'a' && out[k] <= 'z') {
			k--
		}
		return string(out[k+1 : j+1])
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\n':
			line++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src) - i
			}
			blank(i, i+end)
			i += end - 1
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return "", fmt.Errorf("line %d: unterminated comment", line)
			}
			line += strings.Count(src[i:i+2+end+2], "\n")
			blank(i, i+2+end+2)
			i += 2 + end + 1
		case c == '"':
			j := i + 1
			for ; j < len(src) && src[j] != '"'; j++ {
				if src[j] == '\\' {
					j++
				} else if src[j] == '\n' {
					return "", fmt.Errorf("line %d: unterminated text string", line)
				}
			}
			if j >= len(src) {
				return "", fmt.Errorf("line %d: unterminated text string", line)
			}
			blank(i, j+1)
			i = j
		case c == '/' && (prevSignificant(i) == "=" || prevSignificant(i) == "matches"):
			j := i + 1
			for ; j < len(src) && src[j] != '/'; j++ {
				if src[j] == '\\' {
					j++
				} else if src[j] == '\n' {
					return "", fmt.Errorf("line %d: unterminated regular expression", line)
				}
			}
			if j >= len(src) {
				return "", fmt.Errorf("line %d: unterminated regular expression", line)
			}
			blank(i, j+1)
			i = j
		}
	}
	return string(out), nil
}

var yaraRuleDecl = regexp.MustCompile(`(?m)(^|[\s}])((?:(?:private|global)\s+)*)rule\s`)

func lintYara(src string) error {
	clean, err := stripYara(src)
	if err != nil {
		return err
	}
	var newlines []int
	for i := 0; i < len(clean); i++ {
		if clean[i] == '\n' {
			newlines = append(newlines, i)
		}
	}
	lineOf := func(off int) int { return sort.SearchInts(newlines, off) + 1 }
	depth := 0
	for i, c := range clean {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return fmt.Errorf("line %d: unexpected '}'", lineOf(i))
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced braces: %d '{' not closed", depth)
	}
	locs := yaraRuleDecl.FindAllStringSubmatchIndex(clean, -1)
	if len(locs) == 0 {
		return fmt.Errorf("no rule found (expected: rule name { condition: ... })")
	}
	// Rules cannot be nested: a declaration inside a rule body is an error (this also keeps the
	// brace matching below linear).
	depth, li := 0, 0
	for i := 0; i < len(clean) && li < len(locs); i++ {
		for li < len(locs) && locs[li][1]-1 <= i {
			if depth > 0 {
				return fmt.Errorf("line %d: rule declared inside another rule", lineOf(locs[li][1]))
			}
			li++
		}
		switch clean[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	names := map[string]int{}
	for _, loc := range locs {
		at := loc[1] // after "rule "
		rest := strings.TrimLeft(clean[at:], " \t\r\n")
		at = len(clean) - len(rest)
		name := yaraIdent.FindString(rest)
		if name == "" {
			return fmt.Errorf("line %d: rule needs a name (letters, digits, '_')", lineOf(at))
		}
		if prev, dup := names[name]; dup {
			return fmt.Errorf("line %d: duplicate rule name %q (first defined on line %d)", lineOf(at), name, prev)
		}
		names[name] = lineOf(at)
		open := strings.IndexByte(clean[at:], '{')
		if open < 0 {
			return fmt.Errorf("line %d: rule %s has no body", lineOf(at), name)
		}
		if hdr := strings.TrimSpace(clean[at+len(name) : at+open]); hdr != "" && !strings.HasPrefix(hdr, ":") {
			return fmt.Errorf("line %d: unexpected %q after rule name %s", lineOf(at), hdr, name)
		}
		// Find the matching closing brace of the rule body.
		d, end := 0, -1
		for j := at + open; j < len(clean); j++ {
			if clean[j] == '{' {
				d++
			} else if clean[j] == '}' {
				d--
				if d == 0 {
					end = j
					break
				}
			}
		}
		body := clean[at+open+1 : end]
		ci := strings.LastIndex(body, "condition:")
		if ci < 0 {
			return fmt.Errorf("line %d: rule %s has no condition section", lineOf(at), name)
		}
		if strings.TrimSpace(body[ci+len("condition:"):]) == "" {
			return fmt.Errorf("line %d: the condition of rule %s is empty", lineOf(at+open+1+ci), name)
		}
	}
	return nil
}
