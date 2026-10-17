package repository

import (
	"context"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectionIdentityOwnerScopeAndSourceChange(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(path, "fixture"), 0700)
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte("print('static only')"), 0600)
	s, e := store.Open(filepath.Join(t.TempDir(), "repository.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	owner := domain.ID()
	if _, e = s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", owner, domain.Now()); e != nil {
		t.Fatal(e)
	}
	r, e := Open(s, path)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Root.Close()
	for _, asset := range []string{"../fixture", "/etc", "fixture/../fixture", "https://remote", "missing"} {
		if _, e = r.Connect(owner, "app_demo", asset, true); e == nil {
			t.Fatal("accepted", asset)
		}
	}
	if _, e = r.Connect(owner, "app_demo", "fixture", false); e == nil {
		t.Fatal("missing consent accepted")
	}
	a, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil || a.ID != b.ID || a.MapDigest != b.MapDigest {
		t.Fatalf("unstable %v %v %v", a, b, e)
	}
	m, e := r.Map(owner, a.ID)
	if e != nil || len(m.Files) != 1 || m.SourceRef != "mounted-asset:fixture" {
		t.Fatal(m, e)
	}
	second := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", second, domain.Now())
	if _, e = r.Get(second, a.ID); e != sql.ErrNoRows {
		t.Fatal("owner leak", e)
	}
	if _, e = r.Map(second, a.ID); e != sql.ErrNoRows {
		t.Fatal("map leak", e)
	}
	if _, e = r.Connect(second, "app_demo", "fixture", true); e == nil {
		t.Fatal("second owner stole provisioned asset")
	}
	if _, e = r.Assets(second); e == nil {
		t.Fatal("second owner listed provisioned assets")
	}
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte("changed"), 0600)
	c, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil || c.ID != a.ID || c.MapDigest == a.MapDigest {
		t.Fatal("source identity not updated", e)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM application_maps WHERE repository=?", a.ID).Scan(&count)
	if count != 2 {
		t.Fatal("immutable history lost", count)
	}
	for i := 0; i < 98; i++ {
		if _, e = s.DB.Exec("INSERT INTO application_maps VALUES(?,?,?,?)", a.ID, fmt.Sprintf("sha256:%064x", i+1000), "{}", domain.Now()); e != nil {
			t.Fatal(e)
		}
	}
	// At the cap, the oldest maps no scan job references are pruned instead of
	// refusing the change (rescans previously stopped for ever after 100).
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte("third identity"), 0600)
	third, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil || third.MapDigest == c.MapDigest {
		t.Fatal("change at the history cap refused", e)
	}
	s.DB.QueryRow("SELECT count(*) FROM application_maps WHERE repository=?", a.ID).Scan(&count)
	if count != 100 {
		t.Fatal("history not pruned to the cap", count)
	}
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte("print('static only')"), 0600)
	restored, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil || restored.MapDigest != a.MapDigest {
		t.Fatal("retained identity could not be restored", e)
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestSymlinkAndUnprovisionedAsset(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "repository.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	owner := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", owner, domain.Now())
	r, e := Open(s, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Connect(owner, "app_demo", "anything", true); e != ErrUnavailable {
		t.Fatal(e)
	}
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Symlink("/etc", filepath.Join(path, "escape"))
	r, e = Open(s, path)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Root.Close()
	if _, e = r.Connect(owner, "app_demo", "escape", true); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestStoredMapBudgetCountsUTF8BytesAndRollsBack(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(path, "fixture"), 0700)
	file := filepath.Join(path, "fixture", "source.py")
	os.WriteFile(file, []byte("first"), 0600)
	s, e := store.Open(filepath.Join(t.TempDir(), "quota.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	owner := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", owner, domain.Now())
	r, e := Open(s, path)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Root.Close()
	original, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	// Existing storage can contain multi-byte text. SQLite character length must
	// not be mistaken for its actual byte budget.
	document := strings.Repeat("é", (8<<20)+1)
	// Held by another repository, so this one cannot reclaim it by pruning.
	if _, e = s.DB.Exec("INSERT INTO repositories VALUES('other-repo',?,'app_demo','other',?,?)", owner, domain.Hash([]byte(document)), domain.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO application_maps VALUES(?,?,?,?)", "other-repo", domain.Hash([]byte(document)), document, domain.Now()); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(file, []byte("second"), 0600)
	if _, e = r.Connect(owner, "app_demo", "fixture", true); e != ErrBudget {
		t.Fatal("UTF-8 byte budget ignored", e)
	}
	after, e := r.Get(owner, original.ID)
	if e != nil || after.MapDigest != original.MapDigest {
		t.Fatal("quota refusal changed identity", e)
	}
}

func TestExcerptOnlyServesUnchangedInventoriedFiles(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(path, "fixture"), 0700)
	src := "a\nb\nc\nd\ne\nf\n"
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte(src), 0600)
	os.WriteFile(filepath.Join(path, "fixture", ".env"), []byte("SECRET=1\n"), 0600)
	os.WriteFile(filepath.Join(path, "fixture", "config.py"), []byte("x = 1\nTOKEN = 'ghp_SYNTHETICDEMOONLY0123456789'\ny = 2\n"), 0600)
	s, e := store.Open(filepath.Join(t.TempDir(), "repository.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	owner := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", owner, domain.Now())
	r, e := Open(s, path)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Root.Close()
	rec, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	x, e := r.Excerpt(owner, rec.ID, "query.py", 3, 1)
	if e != nil || x.StartLine != 2 || strings.Join(x.Lines, ",") != "b,c,d" || x.Content != src {
		t.Fatal(x, e)
	}
	c, e := r.Excerpt(owner, rec.ID, "config.py", 2, 1)
	if e != nil || !c.Redacted || strings.Contains(strings.Join(c.Lines, "\n"), "ghp_") {
		t.Fatal("credential not redacted", c, e)
	}
	if x.Redacted {
		t.Fatal("clean file marked redacted")
	}
	for _, bad := range []string{".env", "../fixture/query.py", "missing.py", "/etc/passwd"} {
		if _, e = r.Excerpt(owner, rec.ID, bad, 1, 1); e == nil {
			t.Fatal("served", bad)
		}
	}
	if _, e = r.Excerpt(domain.ID(), rec.ID, "query.py", 1, 1); e == nil {
		t.Fatal("served to another owner")
	}
	os.WriteFile(filepath.Join(path, "fixture", "query.py"), []byte(src+"changed\n"), 0600)
	if _, e = r.Excerpt(owner, rec.ID, "query.py", 1, 1); e != ErrSourceChanged {
		t.Fatal("served modified source", e)
	}
}

func TestRefreshAuditsOnlyChanges(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(path, "fixture"), 0700)
	file := filepath.Join(path, "fixture", "source.py")
	os.WriteFile(file, []byte("first"), 0600)
	s, e := store.Open(filepath.Join(t.TempDir(), "refresh.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	owner := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", owner, domain.Now())
	r, _ := Open(s, path)
	defer r.Root.Close()
	rec, e := r.Connect(owner, "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	audits := func() (n int) { s.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action')='repository.connect'").Scan(&n); return }
	before := audits()
	for i := 0; i < 5; i++ {
		if _, e = r.Refresh(context.Background(), owner, rec.ID); e != nil {
			t.Fatal(e)
		}
	}
	if audits() != before {
		t.Fatal("unchanged refresh audited")
	}
	os.WriteFile(file, []byte("second"), 0600)
	if _, e = r.Refresh(context.Background(), owner, rec.ID); e != nil || audits() != before+1 {
		t.Fatal("changed refresh not audited", e)
	}
}
