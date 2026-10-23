package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestTokenScopePerCloud(t *testing.T) {
	for base, want := range map[string]string{
		"https://api.security.microsoft.com":          "https://api.securitycenter.microsoft.com/.default",
		"https://eu.api.security.microsoft.com/":      "https://api.securitycenter.microsoft.com/.default",
		"https://api.securitycenter.microsoft.com":    "https://api.securitycenter.microsoft.com/.default",
		"https://api-gcc.securitycenter.microsoft.us": "https://api-gcc.securitycenter.microsoft.us/.default",
		"https://api-gov.securitycenter.microsoft.us": "https://api-gov.securitycenter.microsoft.us/.default",
		"https://defender.example.test":               "https://defender.example.test/.default",
	} {
		if got := tokenScope(base); got != want {
			t.Errorf("tokenScope(%s) = %s, want %s", base, got, want)
		}
	}
	if c := New(Config{APIBase: "https://api-gov.securitycenter.microsoft.us"}, nil); c.cfg.Authority != "https://login.microsoftonline.us" {
		t.Errorf("GCC High / DoD authority: %s", c.cfg.Authority)
	}
	if c := New(Config{APIBase: "https://api-gcc.securitycenter.microsoft.us"}, nil); c.cfg.Authority != DefaultAuthority {
		t.Errorf("GCC uses the commercial authority: %s", c.cfg.Authority)
	}
}

// fakeDefender serves collections with $top/$skip only (no @odata.nextLink), like the documented API.
type fakeDefender struct {
	mu        sync.Mutex
	machines  int
	queries   []string
	throttled int
	scope     string
}

func (f *fakeDefender) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
		_ = r.ParseForm()
		f.scope = r.PostForm.Get("scope")
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.queries = append(f.queries, r.URL.RawQuery)
	if f.throttled > 0 {
		f.throttled--
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	switch r.URL.Path {
	case "/api/machines":
		if f.machines == 0 {
			w.WriteHeader(http.StatusNotFound) // "If there are no recent machines, you see 404 Not Found."
			return
		}
		top, _ := strconv.Atoi(r.URL.Query().Get("$top"))
		skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
		var page []map[string]any
		for i := skip; i < f.machines && i < skip+top; i++ {
			page = append(page, map[string]any{"id": fmt.Sprintf("m%d", i), "computerDnsName": fmt.Sprintf("srv%d.corp.example", i)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": page})
	case "/api/indicators":
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}, "@odata.nextLink": "https://evil.example/api/indicators?$skip=1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestListPagingThrottlingAndEmptyCollections(t *testing.T) {
	old := pageSize
	pageSize = 4
	defer func() { pageSize = old }()
	f := &fakeDefender{machines: 10, throttled: 1}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(Config{TenantID: "tenant-1", ClientID: "app", ClientSecret: "s", APIBase: srv.URL, Authority: srv.URL}, srv.Client())

	ms, err := c.Machines(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 10 || ms[9].ComputerDNSName != "srv9.corp.example" {
		t.Fatalf("all pages via $top/$skip: got %d machines", len(ms))
	}
	f.mu.Lock()
	queries := append([]string(nil), f.queries...)
	f.mu.Unlock()
	// 1 throttled + 3 pages (4 + 4 + 2).
	if len(queries) != 4 || queries[1] != "$top=4" || queries[2] != "$top=4&$skip=4" || queries[3] != "$top=4&$skip=8" {
		t.Fatalf("queries: %q", queries)
	}
	for _, q := range queries {
		if strings.Contains(q, "$select") {
			t.Fatalf("$select is not documented for List machines: %s", q)
		}
	}

	f.mu.Lock()
	f.machines = 0
	f.mu.Unlock()
	if ms, err := c.Machines(context.Background()); err != nil || len(ms) != 0 {
		t.Fatalf("404 without recent devices must be an empty list: %v %d", err, len(ms))
	}
	if _, err := c.Indicators(context.Background()); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("a nextLink to a foreign host must be refused (token leak): %v", err)
	}
}

func TestMachineActionsFilter(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		got = r.URL.Query().Get("$filter")
		fmt.Fprint(w, `{"value":[
			{"machineId":"m1","type":"Isolate","status":"Succeeded","creationDateTimeUtc":"2026-10-01T10:00:00Z"},
			{"machineId":"m1","type":"Unisolate","status":"Succeeded","creationDateTimeUtc":"2026-10-02T10:00:00Z"},
			{"machineId":"m2","type":"Isolate","status":"Succeeded","creationDateTimeUtc":"2026-10-02T10:00:00Z"},
			{"machineId":"m3","type":"Isolate","status":"Failed","creationDateTimeUtc":"2026-10-02T10:00:00Z"}]}`)
	}))
	defer srv.Close()
	c := New(Config{TenantID: "t", ClientID: "app", ClientSecret: "s", APIBase: srv.URL, Authority: srv.URL}, srv.Client())
	iso, err := c.IsolatedMachines(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "type eq 'Isolate' or type eq 'Unisolate'" || len(iso) != 1 || !iso["m2"] {
		t.Fatalf("filter %q, isolated %v", got, iso)
	}
}
