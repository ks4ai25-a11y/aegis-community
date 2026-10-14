package contracts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRejectsRemoteAdministration(t *testing.T) {
	for _, u := range []string{"http://169.254.169.254/api/v1", "https://example.com/api/v1", "http://127.0.0.1/api/v1?redirect=evil", "http://user:pass@127.0.0.1/api/v1"} {
		if _, e := NewResearchClient(u, "fixture", "fixture"); e == nil {
			t.Fatal("remote or ambiguous endpoint accepted", u)
		}
	}
}
func TestGeneratedScopeRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/scope-grants" || r.Header.Get("X-CSRF-Token") != "csrf-fixture" {
			t.Error("generated request differs from spec")
		}
		cookie, e := r.Cookie("aegis_session")
		if e != nil || cookie.Value != "session-fixture" {
			t.Error("owner session missing")
		}
		var in ScopeGrantDraftRequestV1
		if e = json.NewDecoder(r.Body).Decode(&in); e != nil || in.LifetimeMinutes != 10 {
			t.Error("invalid request", e)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(ScopeGrantRecordV1{State: "draft", RequestsRemaining: 4})
	}))
	defer srv.Close()
	c, e := NewResearchClient(srv.URL+"/api/v1", "session-fixture", "csrf-fixture")
	if e != nil {
		t.Fatal(e)
	}
	r, e := c.CreateScopeGrant(context.Background(), ScopeGrantDraftRequestV1{AppId: "app_demo", Mode: "test_lab", FixtureId: "crs-synthetic-sqli-pattern-v1", LifetimeMinutes: 10})
	if e != nil || r.State != "draft" {
		t.Fatal(r, e)
	}
}
func TestGeneratedClientDoesNotFollowRedirect(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	c, e := NewResearchClient(srv.URL+"/api/v1", "fixture", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.ListVerifications(context.Background()); e == nil || targetHit {
		t.Fatal("redirect followed or accepted")
	}
}

func TestGeneratedScannerListKeepsBoundedHundredJobs(t *testing.T) {
	jobs := make([]ScannerJobStatusV1Job, 100)
	for i := range jobs {
		jobs[i] = ScannerJobStatusV1Job{OwnerId: strings.Repeat("o", 128), RequestDigest: "sha256:" + strings.Repeat("d", 64), ToolLockDigest: "sha256:" + strings.Repeat("e", 64), Input: ScannerJobStatusV1JobInput{RepositoryId: strings.Repeat("r", 128), MapDigest: "sha256:" + strings.Repeat("f", 64), ToolIds: []string{"bandit", "gitleaks", "osv_v2", "semgrep_ce", "syft", "trivy"}}}
	}
	payload, e := json.Marshal(ScannerJobListV1{Items: jobs})
	if e != nil || len(payload) <= 65536 || len(payload) > 131072 {
		t.Fatal("fixture did not exercise bounded larger list", len(payload), e)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" || r.Method != "GET" {
			t.Error("generated scanner list route differs")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	}))
	defer srv.Close()
	c, e := NewResearchClient(srv.URL+"/api/v1", "session-fixture", "csrf-fixture")
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.ListScans(context.Background())
	if e != nil || len(got.Items) != 100 {
		t.Fatal("bounded scanner list lost jobs", e)
	}
}

func TestGeneratedFindingsQueryKeepsFiltersAndCursorInURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method != "GET" || r.URL.Path != "/api/v1/findings" || q.Get("job_id") != "job fixture" || q.Get("category") != "static_pattern" || q.Get("limit") != "2" || q.Get("cursor") != "a+b/c=" {
			t.Error("query changed", r.URL)
		}
		if r.ContentLength > 0 {
			t.Error("GET query sent as body")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"schema_version":"1.0","owner_id":"fixture","job_id":"fixture","request_digest":"fixture","result_digest":"fixture","snapshot_digest":"fixture","status":"completed","has_partial":false,"has_stale_database":false,"has_tool_error":false,"tool_claims":0,"distinct_static_claims":0,"matching_static_claims":0,"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()
	c, e := NewResearchClient(srv.URL+"/api/v1", "session-fixture", "csrf-fixture")
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.ListFindings(context.Background(), FindingQueryV1{JobId: "job fixture", Category: "static_pattern", Limit: 2, Cursor: "a+b/c="})
	if e != nil {
		t.Fatal(e)
	}
}
