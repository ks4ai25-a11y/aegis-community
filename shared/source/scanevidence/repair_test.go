// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func syntheticIntent(t *testing.T, operation string) MutationIntent {
	t.Helper()
	target := ""
	if operation != "create" {
		target = strings.Repeat("c", 64)
	}
	r := MutationRequest{Generation: strings.Repeat("a", 64), Job: "01890f3e-1c2d-7abc-8def-0123456789ab", Tool: "bandit", Operation: operation, Launch: source.Hash([]byte("launch")), Descriptor: source.Hash([]byte("descriptor " + operation)), EngineID: target}
	m, err := NewMutationIntent(r, source.Hash([]byte("workspace")), "aegis-scan-"+strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRepairedIntentNeverCarriesANativeStatus(t *testing.T) {
	create := syntheticIntent(t, "create")
	record := source.Hash([]byte("repair"))
	for _, tc := range []struct {
		m    MutationIntent
		want bool
	}{
		{MutationIntent{ID: create.ID, Request: create.Request, Workspace: create.Workspace, Container: create.Container, State: "repaired", Response: record, EngineID: strings.Repeat("e", 64)}, true},
		{MutationIntent{ID: create.ID, Request: create.Request, Workspace: create.Workspace, Container: create.Container, State: "repaired", Response: record}, true},
		{MutationIntent{ID: create.ID, Request: create.Request, Workspace: create.Workspace, Container: create.Container, State: "repaired", Response: record, Status: 201, EngineID: strings.Repeat("e", 64)}, false},
		{MutationIntent{ID: create.ID, Request: create.Request, Workspace: create.Workspace, Container: create.Container, State: "repaired", EngineID: strings.Repeat("e", 64)}, false},
		{MutationIntent{ID: create.ID, Request: create.Request, Workspace: create.Workspace, Container: create.Container, State: "completed", Response: record}, false},
	} {
		if tc.m.Valid() != tc.want || tc.m.Settled() != (tc.m.State != "pending") {
			t.Fatal("repaired create validity", tc.m.Status, tc.m.EngineID, tc.want)
		}
	}
	start := syntheticIntent(t, "start")
	repaired := RepairedIntent(start, MutationRepair{Digest: record, Resolution: MutationResolution{EngineID: start.Request.EngineID}})
	if !repaired.Valid() || repaired.Status != 0 {
		t.Fatal("repaired start invalid")
	}
	repaired.EngineID = strings.Repeat("e", 64)
	if repaired.Valid() {
		t.Fatal("repaired start retargeted to another container")
	}
}

func TestRepairRequestAndResolutionValidation(t *testing.T) {
	create := syntheticIntent(t, "create")
	remove := syntheticIntent(t, "remove")
	evidence := source.Hash([]byte("evidence"))
	fence := RepairFence{Policy: AdmittedJournalSeal(source.Hash([]byte("policy")), source.Hash([]byte("binding"))), Quarantine: source.Hash([]byte("q")), Activation: source.Hash([]byte("a"))}
	good := MutationResolution{Intent: create.ID, Operation: "create", Outcome: RepairCreated, EngineID: strings.Repeat("e", 64), Evidence: evidence}
	if !good.ValidFor(create) || good.ValidFor(remove) {
		t.Fatal("resolution scope")
	}
	for _, bad := range []MutationResolution{
		{Intent: create.ID, Operation: "create", Outcome: RepairCreated, Evidence: evidence},
		{Intent: create.ID, Operation: "create", Outcome: RepairNotCreated, EngineID: strings.Repeat("e", 64), Evidence: evidence},
		{Intent: create.ID, Operation: "create", Outcome: RepairRemoved, EngineID: strings.Repeat("e", 64), Evidence: evidence},
		{Intent: create.ID, Operation: "start", Outcome: RepairStarted, EngineID: strings.Repeat("c", 64), Evidence: evidence},
		{Intent: create.ID, Operation: "create", Outcome: RepairCreated, EngineID: strings.Repeat("e", 64)},
	} {
		if bad.ValidFor(create) {
			t.Fatal("bad resolution accepted", bad)
		}
	}
	if (MutationResolution{Intent: remove.ID, Operation: "remove", Outcome: RepairRemoved, EngineID: strings.Repeat("9", 64), Evidence: evidence}).ValidFor(remove) {
		t.Fatal("removal resolved for another container")
	}
	completed := create
	completed.State = "completed"
	if good.ValidFor(completed) {
		t.Fatal("settled intent repaired")
	}
	req := MutationRepairRequest{Job: create.Request.Job, Generation: create.Request.Generation, Membership: source.Hash([]byte("m")), Engine: source.Hash([]byte("e")), Namespace: source.Hash([]byte("n")), Fence: fence, Resolutions: []MutationResolution{good}}
	if !req.Valid() {
		t.Fatal("valid request refused")
	}
	for _, f := range []func(*MutationRepairRequest){
		func(r *MutationRepairRequest) { r.Resolutions = nil },
		func(r *MutationRepairRequest) { r.Fence.Activation = "" },
		func(r *MutationRepairRequest) { r.Resolutions = append(r.Resolutions, good) },
		func(r *MutationRepairRequest) { r.Resolutions[0].Outcome = "absent" },
		func(r *MutationRepairRequest) { r.Resolutions[0].Operation = "start" },
	} {
		x := req
		x.Resolutions = append([]MutationResolution(nil), req.Resolutions...)
		f(&x)
		if x.Valid() {
			t.Fatal("malformed repair request accepted")
		}
	}
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	rec := NewMutationRepair("reconciler-a", req, good, now)
	b, _ := json.Marshal(rec)
	decoded, err := DecodeMutationRepair(b)
	if err != nil || decoded.Digest != rec.Digest {
		t.Fatal("retained repair does not round-trip", err)
	}
	tampered := rec
	tampered.Resolution.Outcome = RepairNotCreated
	b, _ = json.Marshal(tampered)
	if _, err = DecodeMutationRepair(b); err == nil {
		t.Fatal("tampered repair accepted")
	}
	b, _ = json.Marshal(rec)
	if _, err = DecodeMutationRepair(append(b[:len(b)-1], []byte(`,"extra":1}`)...)); err == nil {
		t.Fatal("extended repair accepted")
	}
	intent := RepairedIntent(create, rec)
	read := NewAuthorizerIntentRead(true, intent, &rec)
	ask := AuthorizerIntentRequest{Generation: create.Request.Generation, Intent: create.ID}
	if !read.Valid(ask) {
		t.Fatal("repaired read refused")
	}
	other := rec
	other.Resolution.EngineID = strings.Repeat("9", 64)
	other.Digest = repairDigest(other)
	notFound := NewAuthorizerIntentRead(false, intent, nil)
	notFound.Intents = []MutationIntent{intent}
	if NewAuthorizerIntentRead(true, intent, &other).Valid(ask) || notFound.Valid(ask) || !NewAuthorizerIntentRead(false, MutationIntent{}, nil).Valid(ask) || (AuthorizerIntentRead{Schema: "1.0"}).Valid(ask) {
		t.Fatal("intent read validation")
	}
}
