package api

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The module has no YAML dependency, so these tests read openapi.yaml with a small line parser that
// relies on the document's fixed block layout: two-space indentation, path keys at column 2 and
// operations at column 4 below the top-level "paths:" key, component names at column 4 below
// "components:" sections.

var (
	handleFuncRe  = regexp.MustCompile(`HandleFunc\(\s*"([^"]*)"`)
	specPathRe    = regexp.MustCompile(`^  ('[^']+'|"[^"]+"|/[^:]*):\s*$`)
	specOpRe      = regexp.MustCompile(`^    (get|put|post|delete|options|head|patch|trace):\s*$`)
	operationIDRe = regexp.MustCompile(`^\s+operationId:\s*(\S+)\s*$`)
	refRe         = regexp.MustCompile(`\$ref:\s*['"]?#/components/([A-Za-z]+)/([A-Za-z0-9._-]+)['"]?`)
	wildcardRe    = regexp.MustCompile(`\{([A-Za-z0-9_]+)\.\.\.\}`)
)

// registeredRoutes collects every s.mux.HandleFunc("METHOD /path", …) registration of the package
// (non-test sources) as "METHOD /path" → "file:line".
func registeredRoutes(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			m := handleFuncRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			where := f + ":" + itoa(i+1)
			method, path, ok := strings.Cut(m[1], " ")
			if !ok || method == "" || strings.ToUpper(method) != method || !strings.HasPrefix(path, "/") {
				t.Errorf("%s: route pattern %q must have the form \"METHOD /path\" (document the method in openapi.yaml)", where, m[1])
				continue
			}
			// "GET /{$}" (exact root) and "GET /" (catch-all) are both the OpenAPI path "/".
			path = strings.TrimSuffix(path, "{$}")
			path = wildcardRe.ReplaceAllString(path, "{$1}")
			routes[method+" "+path] = where
		}
	}
	if len(routes) == 0 {
		t.Fatal("no route registrations found")
	}
	return routes
}

// specOperations returns the operations of the "paths:" section as "METHOD /path" → line number.
func specOperations(t *testing.T, spec []byte) map[string]int {
	t.Helper()
	ops := map[string]int{}
	paths := map[string]bool{}
	inPaths, current := false, ""
	for i, line := range strings.Split(string(spec), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' { // top-level key
			inPaths, current = trimmed == "paths:", ""
			continue
		}
		if !inPaths {
			continue
		}
		if m := specPathRe.FindStringSubmatch(line); m != nil {
			current = strings.Trim(m[1], `'"`)
			if paths[current] {
				t.Errorf("openapi.yaml:%d: duplicate path %s", i+1, current)
			}
			paths[current] = true
			continue
		}
		if m := specOpRe.FindStringSubmatch(line); m != nil {
			if current == "" {
				t.Errorf("openapi.yaml:%d: operation outside a path", i+1)
				continue
			}
			key := strings.ToUpper(m[1]) + " " + current
			if _, dup := ops[key]; dup {
				t.Errorf("openapi.yaml:%d: duplicate operation %s", i+1, key)
			}
			ops[key] = i + 1
		}
	}
	if len(ops) == 0 {
		t.Fatal("openapi.yaml: no operations found under paths:")
	}
	return ops
}

// TestOpenAPIDocumentsAllRoutes fails when a registered route is missing from openapi.yaml or the
// document describes an operation that is not registered.
func TestOpenAPIDocumentsAllRoutes(t *testing.T) {
	routes := registeredRoutes(t)
	ops := specOperations(t, openAPISpec)

	var missing, stale []string
	for r, where := range routes {
		if _, ok := ops[r]; !ok {
			missing = append(missing, r+" (registered at "+where+")")
		}
	}
	for op, line := range ops {
		if _, ok := routes[op]; !ok {
			stale = append(stale, op+" (openapi.yaml:"+itoa(line)+")")
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, m := range missing {
		t.Errorf("route not documented in openapi.yaml: %s", m)
	}
	for _, s := range stale {
		t.Errorf("openapi.yaml documents an operation that is not registered: %s", s)
	}
	if t.Failed() {
		t.Log("update control-plane/internal/api/openapi.yaml together with the route registrations")
	}
}

// TestOpenAPIStructure checks what the line parser can verify cheaply: version header, one unique
// operationId per operation and that every local component $ref resolves.
func TestOpenAPIStructure(t *testing.T) {
	spec := string(openAPISpec)
	if !strings.HasPrefix(spec, "openapi: 3.1.") {
		t.Fatal("openapi.yaml must start with 'openapi: 3.1.x'")
	}
	if !strings.Contains(spec, "\n  version: ") {
		t.Error("info.version missing")
	}

	ops := specOperations(t, openAPISpec)
	ids := map[string]int{}
	components := map[string]bool{}
	inComponents, section := false, ""
	for i, line := range strings.Split(spec, "\n") {
		if m := operationIDRe.FindStringSubmatch(line); m != nil {
			if prev, dup := ids[m[1]]; dup {
				t.Errorf("openapi.yaml:%d: duplicate operationId %s (first at line %d)", i+1, m[1], prev)
			}
			ids[m[1]] = i + 1
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			inComponents, section = trimmed == "components:", ""
		case inComponents && indent == 2 && strings.HasSuffix(trimmed, ":"):
			section = strings.TrimSuffix(trimmed, ":")
		case inComponents && indent == 4 && section != "" && strings.HasSuffix(trimmed, ":"):
			components[section+"/"+strings.TrimSuffix(trimmed, ":")] = true
		}
	}
	if len(ids) != len(ops) {
		t.Errorf("found %d operationIds for %d operations; every operation needs a unique operationId", len(ids), len(ops))
	}
	for _, m := range refRe.FindAllStringSubmatch(spec, -1) {
		if !components[m[1]+"/"+m[2]] {
			t.Errorf("unresolved $ref #/components/%s/%s", m[1], m[2])
		}
	}
}

// TestOpenAPIEndpoint checks that GET /api/openapi.yaml serves the embedded document without
// authentication, with caching headers and conditional request support.
func TestOpenAPIEndpoint(t *testing.T) {
	h := newHarness(t)
	resp := h.do(t, "GET", "/api/openapi.yaml", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/openapi.yaml: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("Content-Type %q, want application/yaml", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=") || strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control %q, want a cacheable response", cc)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, openAPISpec) {
		t.Fatalf("served document (%d bytes) differs from the embedded openapi.yaml (%d bytes)", len(body), len(openAPISpec))
	}
	onDisk, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, openAPISpec) {
		t.Error("embedded document differs from openapi.yaml on disk")
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("ETag missing")
	}
	if resp := h.do(t, "GET", "/api/openapi.yaml", nil, map[string]string{"If-None-Match": etag}); resp.StatusCode != 304 {
		t.Errorf("conditional GET: status %d, want 304", resp.StatusCode)
	}
}
