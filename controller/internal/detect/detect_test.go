package detect

import (
	"aegis.local/controller/internal/domain"
	"fmt"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func access(i int, at time.Time, client, path string, status int, route string) domain.Event {
	s := status
	return domain.Event{ID: fmt.Sprintf("ev-%d", i), At: at.Format(time.RFC3339Nano), Site: "site_shop", Source: "caddy-access", Method: "GET", Route: route, Status: &s, ClientKey: client, PathKey: path}
}

func fired(signals []Signal, id string) int {
	n := 0
	for _, s := range signals {
		if s.Detector == id {
			n++
		}
	}
	return n
}

func run(e *Engine, events []domain.Event) []Signal {
	var out []Signal
	for _, ev := range events {
		out = append(out, e.Observe(ev)...)
	}
	return out
}

func TestEnumerationFiresOncePerWindow(t *testing.T) {
	var events []domain.Event
	for i := 0; i < 80; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*500*time.Millisecond), "aaaaaaaaaaaaaaaa", fmt.Sprintf("%016x", i), 404, "/{segment}"))
	}
	signals := run(New(Defaults()), events)
	if n := fired(signals, "DET-02"); n < 1 || n > 2 {
		t.Fatal("expected one enumeration signal per window bucket, got", n)
	}
	for _, s := range signals {
		if s.Detector == "DET-02" && (len(s.Evidence) == 0 || s.Key != "aaaaaaaaaaaaaaaa") {
			t.Fatal(s)
		}
	}
}

func TestEnumerationNegativeControls(t *testing.T) {
	var events []domain.Event
	// Many distinct successful paths (a normal browsing session or crawler).
	for i := 0; i < 80; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*500*time.Millisecond), "bbbbbbbbbbbbbbbb", fmt.Sprintf("%016x", i), 200, "/{segment}"))
	}
	// Many failures spread across many clients, one path each.
	for i := 0; i < 80; i++ {
		events = append(events, access(100+i, base.Add(time.Duration(i)*time.Second), fmt.Sprintf("%016x", 1000+i), "cccccccccccccccc", 404, "/{segment}"))
	}
	if n := fired(run(New(Defaults()), events), "DET-02"); n != 0 {
		t.Fatal("benign traffic flagged as enumeration", n)
	}
}

func TestBruteForceCandidate(t *testing.T) {
	var events []domain.Event
	for i := 0; i < 12; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*10*time.Second), "dddddddddddddddd", "eeeeeeeeeeeeeeee", 401, "/login"))
	}
	if n := fired(run(New(Defaults()), events), "DET-03"); n != 1 {
		t.Fatal("expected one brute-force candidate, got", n)
	}
	// Nine failures spread over 50 minutes stay below threshold in every window.
	events = nil
	for i := 0; i < 9; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*6*time.Minute), "dddddddddddddddd", "eeeeeeeeeeeeeeee", 401, "/login"))
	}
	if n := fired(run(New(Defaults()), events), "DET-03"); n != 0 {
		t.Fatal("slow failures flagged", n)
	}
}

func TestBurstAdvisory(t *testing.T) {
	var events []domain.Event
	for i := 0; i < 250; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*20*time.Millisecond), "ffffffffffffffff", "1111111111111111", 200, "/catalog"))
	}
	signals := run(New(Defaults()), events)
	if fired(signals, "DET-04") != 1 {
		t.Fatal(signals)
	}
}

func TestErrorSpikeRequiresShareOfTraffic(t *testing.T) {
	var events []domain.Event
	for i := 0; i < 30; i++ {
		events = append(events, access(i, base.Add(time.Duration(i)*time.Second), fmt.Sprintf("%016x", i), "2222222222222222", 502, "/catalog"))
	}
	if fired(run(New(Defaults()), events), "DET-05") != 1 {
		t.Fatal("5xx spike not flagged")
	}
	// 25 errors among 200 successes in the same minute is below the 50% share.
	events = nil
	for i := 0; i < 225; i++ {
		status := 200
		if i%9 == 0 {
			status = 500
		}
		events = append(events, access(i, base.Add(time.Duration(i)*200*time.Millisecond), fmt.Sprintf("%016x", i), "3333333333333333", status, "/catalog"))
	}
	if n := fired(run(New(Defaults()), events), "DET-05"); n != 0 {
		t.Fatal("minority errors flagged", n)
	}
}

func TestSensitiveRoute(t *testing.T) {
	e := New(Defaults())
	if fired(e.Observe(access(1, base, "", "", 200, "/admin/{segment}")), "DET-06") != 1 {
		t.Fatal("successful admin route not flagged")
	}
	if fired(e.Observe(access(2, base, "", "", 404, "/admin")), "DET-06") != 0 {
		t.Fatal("refused admin route flagged")
	}
	if fired(e.Observe(access(3, base, "", "", 200, "/administrator")), "DET-06") != 0 {
		t.Fatal("partial segment match flagged")
	}
}

func TestKeyCardinalityIsBoundedAndCounted(t *testing.T) {
	k := Defaults()
	k.MaxKeys = 16
	e := New(k)
	for i := 0; i < 100; i++ {
		e.Observe(access(i, base, fmt.Sprintf("%016x", i), "4444444444444444", 200, "/catalog"))
	}
	if len(e.keys) > 16 || e.Evicted.Load() == 0 {
		t.Fatal(len(e.keys), e.Evicted.Load())
	}
}

func TestIneligibleEventsIgnored(t *testing.T) {
	e := New(Defaults())
	ev := access(1, base, "aaaaaaaaaaaaaaaa", "", 200, "/admin")
	ev.Source = "coraza"
	if len(e.Observe(ev)) != 0 {
		t.Fatal("WAF record used by behavioural detector")
	}
	ev = access(2, base, "", "", 200, "/admin")
	ev.Status = nil
	if len(e.Observe(ev)) != 0 {
		t.Fatal("status-less record used")
	}
}
