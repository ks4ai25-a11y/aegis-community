//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (*Server, scannerauth.Enrollment, scanqueue.Input) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "worker.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	s.DB.Exec("INSERT INTO owners VALUES('owner-a','test',?),('owner-b','test',?)", domain.Now(), domain.Now())
	s.DB.Exec("INSERT INTO settings VALUES('repository_mount_owner','owner-a')")
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "fixture"), 0700)
	os.WriteFile(filepath.Join(root, "fixture", "query.py"), []byte("static only"), 0600)
	reg, e := repository.Open(s, root)
	if e != nil {
		t.Fatal(e)
	}
	defer reg.Root.Close()
	repo, e := reg.Connect("owner-a", "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: s}
	enrollment, e := auth.Enroll("owner-a", "worker-a", 60)
	if e != nil {
		t.Fatal(e)
	}
	guards, _ := scanevidence.NewGuardSet(domain.Hash([]byte("guard")), domain.Hash([]byte("arm64 guard")))
	q := &scanqueue.Queue{Guards: guards, S: s, LockDigest: domain.Hash([]byte("trusted test lock"))}
	return &Server{Q: q, Auth: auth}, enrollment, scanqueue.Input{Schema: "1.0", App: "app_demo", Repository: repo.ID, MapDigest: repo.MapDigest, Mode: "repo_offline", Tools: []string{"bandit"}, Duration: 120}
}
func call(t *testing.T, h http.Handler, token, path, body string, status int) map[string]any {
	t.Helper()
	r := httptest.NewRequest("POST", "http://unix/internal/v1/scanner/"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s: got HTTP %d, expected %d", path, w.Code, status)
	}
	out := map[string]any{}
	if status != 204 {
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func TestPrivateWorkerProtocolClaimsGuardsAndFailsWithoutOwnerOverride(t *testing.T) {
	s, enrollment, in := fixture(t)
	h := s.Handler()
	call(t, h, enrollment.Token, "claim", "{}", 204)
	job, e := s.Q.Enqueue("owner-a", "transport-job-key", in)
	if e != nil {
		t.Fatal(e)
	}
	claimed := call(t, h, enrollment.Token, "claim", "{}", 200)
	if claimed["job"].(map[string]any)["job_id"] != job.ID || claimed["application_map"].(map[string]any)["content_digest"] != in.MapDigest {
		t.Fatal("claim lost source/job binding")
	}
	lease := claimed["lease_token"].(string)
	if !tokenPattern.MatchString(lease) {
		t.Fatal("missing private capability")
	}
	payload, _ := json.Marshal(LeaseRequest{Job: job.ID, Digest: job.RequestDigest, Token: lease})
	call(t, h, enrollment.Token, "guard", string(payload), 200)
	call(t, h, enrollment.Token, "guard", strings.TrimSuffix(string(payload), "}")+`,"owner_id":"owner-b"}`, 400)
	failPayload, _ := json.Marshal(LeaseRequest{Job: job.ID, Digest: job.RequestDigest, Token: lease, Code: "SOURCE_CAPTURE_FAILED"})
	failed := call(t, h, enrollment.Token, "fail", string(failPayload), 200)
	if failed["cleanup_required"] != true {
		t.Fatal("failure implied cleanup")
	}
	call(t, h, enrollment.Token, "fail", string(failPayload), 200)
	call(t, h, enrollment.Token, "claim", "{}", 409)
	if e = s.Q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestWorkerProtocolRejectsMalformedBodiesAndRoleConfusion(t *testing.T) {
	s, enrollment, _ := fixture(t)
	h := s.Handler()
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"worker_id":"worker-a"}`, `{"owner_id":"owner-a"}`, `{"Job_ID":"other"}`, `{"job_id":null}`, `{"job_id":"x","job_id":"y"}`, strings.Repeat(" ", 8193)} {
		call(t, h, enrollment.Token, "claim", body, 400)
	}
	call(t, h, "", "identity", "{}", 401)
	call(t, h, strings.Repeat("0", 64), "identity", "{}", 401)
	for _, header := range []string{"Origin", "Cookie"} {
		r := httptest.NewRequest("POST", "http://unix/internal/v1/scanner/identity", strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+enrollment.Token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(header, "owner-session")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("browser role/channel admitted", header, w.Code)
		}
	}
	if e := s.Auth.Revoke("owner-a", enrollment.Worker.ID); e != nil {
		t.Fatal(e)
	}
	call(t, h, enrollment.Token, "identity", "{}", 401)
}
func TestWorkerProtocolLeaseCapabilityIsNotEnrollmentCapability(t *testing.T) {
	s, enrollment, in := fixture(t)
	h := s.Handler()
	job, e := s.Q.Enqueue("owner-a", "capability-role-key", in)
	if e != nil {
		t.Fatal(e)
	}
	claimed := call(t, h, enrollment.Token, "claim", "{}", 200)
	lease := claimed["lease_token"].(string)
	call(t, h, lease, "identity", "{}", 401)
	payload, _ := json.Marshal(LeaseRequest{Job: job.ID, Digest: job.RequestDigest, Token: enrollment.Token})
	call(t, h, enrollment.Token, "guard", string(payload), 403)
	payload, _ = json.Marshal(LeaseRequest{Job: domain.ID(), Digest: job.RequestDigest, Token: lease})
	call(t, h, enrollment.Token, "guard", string(payload), 404)
}
func TestPrivateSocketLifecycleAndProbe(t *testing.T) {
	s, _, _ := fixture(t)
	short, e := os.MkdirTemp("/tmp", "aw-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	parent, _ := filepath.EvalSymlinks(short)
	os.Chmod(parent, 0700)
	socket := filepath.Join(parent, "worker.sock")
	credential := filepath.Join(parent, "worker.token")
	w, e := s.Auth.EnrollFile("owner-a", "probe-worker", 60, credential)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := Listen(socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: s.Handler()}
	go server.Serve(listener)
	defer server.Close()
	got, e := Probe(context.Background(), socket, credential)
	if e != nil || got.ID != w.ID {
		t.Fatal(got, e)
	}
	if _, e = Listen(socket); e == nil {
		t.Fatal("second listener removed active socket")
	}
	if e = s.Auth.Revoke("owner-a", w.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = Probe(context.Background(), socket, credential); e == nil {
		t.Fatal("revoked probe succeeded")
	}
	server.Close()
	stale, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	successor, e := Listen(socket)
	if e != nil {
		t.Fatal("stale owned socket recovery failed", e)
	}
	successor.Close()
	if _, e = os.Stat(socket); !os.IsNotExist(e) {
		t.Fatal("listener did not remove its socket", e)
	}
}
func TestPrivateSocketAndCredentialsRejectUnsafePaths(t *testing.T) {
	short, e := os.MkdirTemp("/tmp", "aw-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	parent, _ := filepath.EvalSymlinks(short)
	os.Chmod(parent, 0755)
	if _, e := Listen(filepath.Join(parent, "worker.sock")); e == nil {
		t.Fatal("public socket directory accepted")
	}
	os.Chmod(parent, 0700)
	occupied := filepath.Join(parent, "occupied")
	os.WriteFile(occupied, []byte("owner file"), 0600)
	if _, e := Listen(occupied); e == nil {
		t.Fatal("ordinary owner file replaced")
	}
	b, _ := os.ReadFile(occupied)
	if !bytes.Equal(b, []byte("owner file")) {
		t.Fatal("ordinary owner file changed")
	}
	link := filepath.Join(parent, "link")
	os.Symlink(occupied, link)
	if _, e := Listen(link); e == nil {
		t.Fatal("socket symlink accepted")
	}
	os.Chmod(occupied, 0644)
	if f, e := openCredential(occupied); e == nil {
		f.Close()
		t.Fatal("public credential accepted")
	}
}
func TestCuratedToolLockValidation(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tools", "scanners.lock.json")
	digest, e := LoadLock(path)
	if e != nil || !hashPattern.MatchString(digest) {
		t.Fatal(digest, e)
	}
	b, _ := os.ReadFile(path)
	p := filepath.Join(t.TempDir(), "lock.json")
	os.WriteFile(p, bytes.Replace(b, []byte(`"bandit"`), []byte(`"arbitrary-shell"`), 1), 0600)
	if _, e = LoadLock(p); e == nil {
		t.Fatal("unknown tool pin accepted")
	}
	os.WriteFile(p, append(b, []byte("{}")...), 0600)
	if _, e = LoadLock(p); e == nil {
		t.Fatal("trailing lock accepted")
	}
}

func TestNonregularWorkerArtifactsRefusedWithoutBlocking(t *testing.T) {
	short, e := os.MkdirTemp("/tmp", "aw-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	parent, _ := filepath.EvalSymlinks(short)
	fifo := filepath.Join(parent, "fifo")
	if e = syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadLock(fifo); e == nil {
		t.Fatal("FIFO tool lock accepted")
	}
	if f, e := openCredential(fifo); e == nil {
		f.Close()
		t.Fatal("FIFO credential accepted")
	}
	lock := filepath.Join(parent, ".worker-socket-lock")
	if e = syscall.Mkfifo(lock, 0600); e != nil {
		t.Fatal(e)
	}
	if l, e := Listen(filepath.Join(parent, "worker.sock")); e == nil {
		l.Close()
		t.Fatal("FIFO listener lease accepted")
	}
}
