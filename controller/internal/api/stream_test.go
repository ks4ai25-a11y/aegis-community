// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/store"
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A client that opens the event stream and stops reading must not hold the
// controller's only database connection (QA backend finding).
func TestStalledEventStreamDoesNotBlockStore(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "stream.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	if e = a.Enroll(a.Bootstrap, "a sufficiently long test passphrase"); e != nil {
		t.Fatal(e)
	}
	login := httptest.NewRecorder()
	if _, e = a.Login(login, httptest.NewRequest("POST", "http://localhost", nil), "a sufficiently long test passphrase"); e != nil {
		t.Fatal(e)
	}
	cookie := login.Result().Cookies()[0]
	srv := httptest.NewServer((&Server{S: s, A: a, Assets: t.TempDir()}).Handler())
	defer srv.Close()
	big := strings.Repeat("x", 60<<10)
	for i := 0; i < 100; i++ {
		doc := fmt.Sprintf(`{"event_id":"e%d","site_id":"site_demo","pad":"%s"}`, i, big)
		if _, e = s.DB.Exec("INSERT INTO events(id,at,request,source_key,document) VALUES(?,?,?,?,?)", fmt.Sprint("e", i), time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprint("r", i), fmt.Sprint("k", i), doc); e != nil {
			t.Fatal(e)
		}
	}
	conn, e := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadBuffer(4096)
	}
	fmt.Fprintf(conn, "GET /api/v1/sites/site_demo/events/stream HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\n\r\n", strings.TrimPrefix(srv.URL, "http://"), cookie.Name, cookie.Value)
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatal("stream not opened:", status)
	}
	time.Sleep(3 * time.Second) // the stream writes 6 MB to a client that does not read
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var n int
	if e = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&n); e != nil || n != 100 {
		t.Fatal("store blocked by a stalled stream reader:", e)
	}
}
