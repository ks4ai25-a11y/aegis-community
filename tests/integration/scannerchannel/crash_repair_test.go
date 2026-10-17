//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineobserve"
	"aegis.local/alpha/reconcile"
	"aegis.local/alpha/workerchannel"
	"aegis.local/source/scanevidence"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedInspector stands in for the independent TLS observer. The observer's
// own exact-read rules are tested in engineobserve; here the plugin, journal,
// reconciler client and controller are real and talk over private Unix RPC.
type fixedInspector struct{ state engineobserve.ContainerState }

func (f fixedInspector) Inspect(context.Context, engineobserve.Target) (engineobserve.ContainerState, error) {
	return f.state, nil
}

// crashAfterAllow admits and allows a create, then loses the authorizer
// before any native response: the controller intent stays pending and the
// plugin journal keeps an unanswered create. The job then times out.
func crashAfterAllow(t *testing.T) (gateFixture, *workerchannel.ReconcilerClient, scanevidence.ReconcilerIdentity) {
	t.Helper()
	g := setupAdmittedEngineGate(t, false)
	if !g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("admitted create refused")
	}
	g.p.Close()
	if e := g.f.q.Cancel("owner-a", g.job); e != nil {
		t.Fatal(e)
	}
	later := time.Now().Add(20 * time.Second)
	g.f.q.Now = func() time.Time { return later }
	if e := g.f.q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	g.f.q.Now = time.Now
	var binding string
	if e := g.f.s.DB.QueryRow("SELECT digest FROM scanner_mutation_bindings WHERE state='active'").Scan(&binding); e != nil {
		t.Fatal(e)
	}
	credential := filepath.Join(filepath.Dir(g.credential), "reconciler.credential")
	v, e := g.f.auth.EnrollReconcilerFile("owner-a", "reconciler-a", 5, binding, credential)
	if e != nil {
		t.Fatal(e)
	}
	client, e := workerchannel.NewReconciler(g.f.socket, credential, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, g.f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return g, client, v
}

func generationOf(t *testing.T, g gateFixture) string {
	t.Helper()
	var id string
	if e := g.f.s.DB.QueryRow("SELECT id FROM scanner_allocation_generations WHERE job=?", g.job).Scan(&id); e != nil {
		t.Fatal(e)
	}
	return id
}

func activate(t *testing.T, p *engineauthz.Policy) {
	t.Helper()
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/Plugin.Activate", strings.NewReader("{}")))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "authz") {
		t.Fatal("plugin activation failed")
	}
}

func intentStates(t *testing.T, g gateFixture) map[string]string {
	t.Helper()
	rows, e := g.f.s.DB.Query("SELECT operation,state FROM scanner_mutation_intents")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var op, state string
		if e = rows.Scan(&op, &state); e != nil {
			t.Fatal(e)
		}
		out[op] = state
	}
	return out
}

func repairWith(t *testing.T, g gateFixture, client *workerchannel.ReconcilerClient, seen engineobserve.ContainerState) error {
	t.Helper()
	read := func(attempt string) (enginejournal.Evidence, error) {
		return enginejournal.ReadEvidence(g.cfg.JournalRoot, g.cfg.EngineDigest, attempt)
	}
	_, e := reconcile.Repair{Controller: client, Observer: fixedInspector{seen}, Journal: read, Namespace: g.cfg.Admitted.Namespace}.Run(context.Background(), g.job, generationOf(t, g))
	return e
}

func release(t *testing.T, g gateFixture, client *workerchannel.ReconcilerClient) scanevidence.CleanupConfirmation {
	t.Helper()
	s, e := client.Snapshot(context.Background(), g.job, generationOf(t, g))
	if e != nil {
		t.Fatal(e)
	}
	absent, e := scanevidence.RequiredAbsences(s.Membership)
	if e != nil {
		t.Fatal("repaired membership not releasable", e)
	}
	c, e := client.Confirm(context.Background(), s, absent)
	if e != nil || !c.Released {
		t.Fatal("release refused", e)
	}
	return c
}

func TestCrashRepairPresentCreateIsRemovedThroughQuarantineThenReleased(t *testing.T) {
	g, client, _ := crashAfterAllow(t)
	if p, e := engineauthz.Open(g.cfg); e == nil {
		p.Close()
		t.Fatal("admitted serving reopened an unfinished journal")
	}
	quarantine := g.cfg
	quarantine.Quarantine = true
	q, e := engineauthz.Open(quarantine)
	if e != nil {
		t.Fatal("quarantine refused", e)
	}
	defer q.Close()
	if _, e = os.Stat(filepath.Join(g.cfg.JournalRoot, "quarantine.1.json")); e != nil {
		t.Fatal("quarantine seal not written", e)
	}
	present := engineobserve.ContainerState{Present: true, ID: gateID}
	// Unfenced: no daemon has activated the quarantined plugin yet.
	if e = repairWith(t, g, client, present); e == nil {
		t.Fatal("repair accepted before a post-seal daemon activation")
	}
	if intentStates(t, g)["create"] != "pending" {
		t.Fatal("refused repair changed the controller")
	}
	activate(t, q)
	// Quarantine never allows a create or a start, and no removal before the
	// controller has retained a repair.
	if q.AuthorizeRequest(g.request).Allow || q.AuthorizeRequest(gateOperation("POST", "/start")).Allow || q.AuthorizeRequest(gateOperation("DELETE", "?force=1&v=1")).Allow {
		t.Fatal("quarantine allowed an engine write before repair")
	}
	if e = repairWith(t, g, client, present); e != nil {
		t.Fatal("present create not repaired", e)
	}
	if states := intentStates(t, g); states["create"] != "repaired" {
		t.Fatal("create not repaired", states)
	}
	if e = repairWith(t, g, client, present); e == nil {
		t.Fatal("repair repeated")
	}
	if q.AuthorizeRequest(g.request).Allow || q.AuthorizeRequest(gateOperation("POST", "/start")).Allow {
		t.Fatal("repaired create permitted a new create or start")
	}
	remove := gateOperation("DELETE", "?force=1&v=1")
	if !q.AuthorizeRequest(remove).Allow {
		t.Fatal("normal admitted removal of the repaired allocation refused")
	}
	if states := intentStates(t, g); states["remove"] != "pending" {
		t.Fatal("removal not admitted before Allow", states)
	}
	remove.ResponseStatusCode = 204
	if !q.AuthorizeResponse(remove).Allow {
		t.Fatal("removal response refused")
	}
	if states := intentStates(t, g); states["remove"] != "completed" {
		t.Fatal("removal not completed", states)
	}
	c := release(t, g, client)
	if a, ok := c.Absence(gateName); !ok || a.EngineID != gateID {
		t.Fatal("release did not require the repaired engine ID absent")
	}
	q.Close()
	reopened, e := engineauthz.Open(g.cfg)
	if e != nil {
		t.Fatal("settled journal did not return to admitted serving", e)
	}
	defer reopened.Close()
	if o := reopened.Observation(); o.Unfinished != 0 || o.Unresolved != 0 {
		t.Fatal("journal unsettled", o)
	}
}

func TestCrashRepairAbsentCreateReleasesByNameAndSettlesJournal(t *testing.T) {
	g, client, _ := crashAfterAllow(t)
	quarantine := g.cfg
	quarantine.Quarantine = true
	q, e := engineauthz.Open(quarantine)
	if e != nil {
		t.Fatal(e)
	}
	activate(t, q)
	if e = repairWith(t, g, client, engineobserve.ContainerState{}); e != nil {
		t.Fatal("absent create not repaired", e)
	}
	// Nothing was created, so nothing may be removed.
	if q.AuthorizeRequest(gateOperation("DELETE", "?force=1&v=1")).Allow {
		t.Fatal("removal allowed for a create repaired as not created")
	}
	c := release(t, g, client)
	if a, ok := c.Absence(gateName); !ok || a.EngineID != "" {
		t.Fatal("not-created release must observe the exact name only")
	}
	// Settle offline, holding the journal lock, then serve admitted again.
	if _, _, e = engineauthz.SettleQuarantine(g.cfg); e == nil {
		t.Fatal("settle ran while the quarantined plugin held the journal")
	}
	q.Close()
	observation, _, e := engineauthz.SettleQuarantine(g.cfg)
	if e != nil || observation.Unfinished != 0 || observation.Unresolved != 0 {
		t.Fatal("journal not settled from the retained repair", e, observation)
	}
	if _, e = os.Stat(filepath.Join(g.cfg.JournalRoot, gateName, "create.repair.json")); e != nil {
		t.Fatal("local repair record missing", e)
	}
	reopened, e := engineauthz.Open(g.cfg)
	if e != nil {
		t.Fatal("settled journal refused admitted serving", e)
	}
	reopened.Close()
	again := g.cfg
	again.Quarantine = true
	if p, e := engineauthz.Open(again); e == nil {
		p.Close()
		t.Fatal("quarantine opened a settled journal")
	}
}

func TestCrashRepairRefusesWithoutQuarantineOrWhileHeldByServing(t *testing.T) {
	g, client, _ := crashAfterAllow(t)
	// No quarantine seal at all.
	if e := repairWith(t, g, client, engineobserve.ContainerState{}); e == nil {
		t.Fatal("repair accepted without a sealed quarantine")
	}
	// A quarantine under any other admitted configuration is refused: the
	// sealed policy binds it to the original serving configuration.
	changed := g.cfg
	changed.Quarantine = true
	admitted := *g.cfg.Admitted
	admitted.RulesDigest = "sha256:" + strings.Repeat("1", 64)
	changed.Admitted = &admitted
	if p, e := engineauthz.Open(changed); e == nil {
		p.Close()
		t.Fatal("quarantine opened under a changed policy")
	}
	quarantine := g.cfg
	quarantine.Quarantine = true
	q, e := engineauthz.Open(quarantine)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	// The exclusive journal lock proves one serving process at a time.
	if p, e := engineauthz.Open(quarantine); e == nil {
		p.Close()
		t.Fatal("second plugin process served the quarantined journal")
	}
	activate(t, q)
	// A contradictory observation keeps quarantine: the journal records no
	// response, but the controller must not see a fabricated one either.
	if e = repairWith(t, g, client, engineobserve.ContainerState{Present: true, ID: strings.Repeat("9", 64)}); e != nil {
		t.Fatal("present-by-name create not repairable", e)
	}
	var engine string
	if e = g.f.s.DB.QueryRow("SELECT result_engine_id FROM scanner_mutation_intents WHERE operation='create'").Scan(&engine); e != nil || engine != strings.Repeat("9", 64) {
		t.Fatal("observed engine ID not retained exactly", e)
	}
	// The repaired engine ID must match the removal target exactly.
	if q.AuthorizeRequest(gateOperation("DELETE", "?force=1&v=1")).Allow {
		t.Fatal("removal of a different engine ID admitted")
	}
	if _, e = g.f.s.DB.Exec("DELETE FROM scanner_dispatch"); e == nil {
		t.Fatal("repair released the slot")
	}
}

// crashDuringRemove settles create and start, admits a removal after the job
// is cancelled and loses the authorizer before any removal response.
func crashDuringRemove(t *testing.T) (gateFixture, *workerchannel.ReconcilerClient) {
	t.Helper()
	g := setupAdmittedEngineGate(t, false)
	gateCreate(t, g)
	if e := g.f.q.Cancel("owner-a", g.job); e != nil {
		t.Fatal(e)
	}
	if !g.p.AuthorizeRequest(gateOperation("DELETE", "?force=1&v=1")).Allow {
		t.Fatal("tracked removal refused")
	}
	g.p.Close()
	later := time.Now().Add(20 * time.Second)
	g.f.q.Now = func() time.Time { return later }
	if e := g.f.q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	g.f.q.Now = time.Now
	var binding string
	if e := g.f.s.DB.QueryRow("SELECT digest FROM scanner_mutation_bindings WHERE state='active'").Scan(&binding); e != nil {
		t.Fatal(e)
	}
	credential := filepath.Join(filepath.Dir(g.credential), "reconciler.credential")
	v, e := g.f.auth.EnrollReconcilerFile("owner-a", "reconciler-a", 5, binding, credential)
	if e != nil {
		t.Fatal(e)
	}
	client, e := workerchannel.NewReconciler(g.f.socket, credential, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, g.f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return g, client
}

func TestCrashRepairPendingRemovalIsResumedOnlyUnderFenceOrRepairedWhenGone(t *testing.T) {
	t.Run("container still present", func(t *testing.T) {
		g, client := crashDuringRemove(t)
		quarantine := g.cfg
		quarantine.Quarantine = true
		q, e := engineauthz.Open(quarantine)
		if e != nil {
			t.Fatal(e)
		}
		defer q.Close()
		remove := gateOperation("DELETE", "?force=1&v=1")
		if q.AuthorizeRequest(remove).Allow {
			t.Fatal("pending removal resumed before a post-seal daemon activation")
		}
		activate(t, q)
		if e = repairWith(t, g, client, engineobserve.ContainerState{Present: true, ID: gateID}); e == nil {
			t.Fatal("present container repaired as removed")
		}
		var before int
		if e = g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&before); e != nil {
			t.Fatal(e)
		}
		if !q.AuthorizeRequest(remove).Allow {
			t.Fatal("admitted removal not resumed under the fence")
		}
		var after int
		if e = g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&after); e != nil || after != before {
			t.Fatal("resumed removal created another obligation", e)
		}
		remove.ResponseStatusCode = 204
		if !q.AuthorizeResponse(remove).Allow {
			t.Fatal("resumed removal response refused")
		}
		if states := intentStates(t, g); states["remove"] != "completed" {
			t.Fatal("resumed removal not completed natively", states)
		}
		release(t, g, client)
	})
	t.Run("container already gone", func(t *testing.T) {
		g, client := crashDuringRemove(t)
		quarantine := g.cfg
		quarantine.Quarantine = true
		q, e := engineauthz.Open(quarantine)
		if e != nil {
			t.Fatal(e)
		}
		activate(t, q)
		if e = repairWith(t, g, client, engineobserve.ContainerState{}); e != nil {
			t.Fatal("absent container not repaired as removed", e)
		}
		if states := intentStates(t, g); states["remove"] != "repaired" {
			t.Fatal(states)
		}
		release(t, g, client)
		q.Close()
		if o, _, e := engineauthz.SettleQuarantine(g.cfg); e != nil || o.Unfinished != 0 {
			t.Fatal("removal repair not settled locally", e, o)
		}
	})
}

func TestBrokerJournalSettlesOnlyFromRetainedConfirmation(t *testing.T) {
	g, client, _ := crashAfterAllow(t)
	// The broker's own unbound journal keeps its unanswered create too.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "broker-journal")
	j, e := enginejournal.Open(path, g.cfg.EngineDigest)
	if e != nil {
		t.Fatal(e)
	}
	a, e := j.Begin(gateName, "sha256:"+strings.Repeat("d", 64))
	if e == nil {
		_, e = a.Begin("create", "")
	}
	if e != nil {
		t.Fatal(e)
	}
	j.Close()
	j, e = enginejournal.OpenExisting(path, g.cfg.EngineDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if _, e = g.f.client.CleanupConfirmation(context.Background(), gateName); e == nil {
		t.Fatal("held allocation offered a confirmation")
	}
	quarantine := g.cfg
	quarantine.Quarantine = true
	q, e := engineauthz.Open(quarantine)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	activate(t, q)
	if e = repairWith(t, g, client, engineobserve.ContainerState{}); e != nil {
		t.Fatal(e)
	}
	release(t, g, client)
	c, e := g.f.client.CleanupConfirmation(context.Background(), gateName)
	if e != nil {
		t.Fatal("worker could not read its retained confirmation", e)
	}
	other := c
	other.Request.Absent = []scanevidence.CleanupAbsence{{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("1", 32)}}
	if j.SettleReleased(gateName, other) == nil {
		t.Fatal("confirmation for another container settled the attempt")
	}
	if e = j.SettleReleased(gateName, c); e != nil {
		t.Fatal(e)
	}
	if o := j.Observe(); o.Unfinished != 0 || o.Unresolved != 0 {
		t.Fatal("broker journal unsettled", o)
	}
	j.Close()
	reopened, e := enginejournal.OpenExisting(path, g.cfg.EngineDigest)
	if e != nil {
		t.Fatal("settled broker journal does not reload", e)
	}
	if o := reopened.Observe(); o.Unfinished != 0 || o.Unresolved != 0 || o.Attempts != 1 {
		t.Fatal("reloaded broker journal unsettled", o)
	}
	reopened.Close()
}
