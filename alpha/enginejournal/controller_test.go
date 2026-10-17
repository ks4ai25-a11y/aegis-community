//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
//
package enginejournal

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func controllerProposal(t *testing.T, operation, target, name string) scanevidence.MutationIntent {
	t.Helper()
	r := scanevidence.MutationRequest{Generation: strings.Repeat("a", 64), Job: "0198e0d0-0000-7000-8000-000000000001", Tool: "bandit", Operation: operation, Launch: source.Hash([]byte("launch")), Descriptor: source.Hash([]byte("native " + operation)), EngineID: target}
	m, e := scanevidence.NewMutationIntent(r, source.Hash([]byte("workspace")), name)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestBoundJournalRetainsExactControllerProposalAndDurableNativeResponse(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if e = j.RequirePolicy(source.Hash([]byte("selected admitted seal"))); e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-" + strings.Repeat("b", 32)
	id := strings.Repeat("c", 64)
	a, e := j.Begin(name, source.Hash([]byte("native create body")))
	if e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"create", "start", "remove"} {
		target := ""
		status := 201
		if op != "create" {
			target = id
			status = 204
		}
		proposal := controllerProposal(t, op, target, name)
		if op == "start" {
			if _, e = a.Begin(op, target); e == nil {
				t.Fatal("bound attempt downgraded to unbound journal")
			}
			changed := proposal.Request
			changed.Generation = strings.Repeat("f", 64)
			other, e := scanevidence.NewMutationIntent(changed, proposal.Workspace, name)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = a.BeginBound(op, target, other); e == nil {
				t.Fatal("different controller generation joined attempt")
			}
		}
		ticket, e := a.BeginBound(op, target, proposal)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := os.ReadFile(filepath.Join(path, name, op+".pending.json"))
		if e != nil {
			t.Fatal(e)
		}
		var pending envelope[intent]
		if json.Unmarshal(raw, &pending) != nil || pending.Document.Controller == nil || *pending.Document.Controller != proposal {
			t.Fatal("durable pending identity changed")
		}
		if _, e = ticket.ResponseDigest(); e == nil {
			t.Fatal("pending request claimed a native response")
		}
		if e = ticket.Confirm(status, id); e != nil {
			t.Fatal(e)
		}
		digest, e := ticket.ResponseDigest()
		if e != nil {
			t.Fatal(e)
		}
		raw, e = os.ReadFile(filepath.Join(path, name, op+".response.json"))
		if e != nil {
			t.Fatal(e)
		}
		var confirmed envelope[response]
		if json.Unmarshal(raw, &confirmed) != nil || confirmed.Digest != digest || confirmed.Document.Intent != pending.Digest {
			t.Fatal("controller acknowledgement lacks durable native response identity")
		}
	}
	if e = a.Finish(); e != nil {
		t.Fatal(e)
	}
	j.Close()
	reopened, e := OpenExisting(path, engine)
	if e != nil {
		t.Fatal("bound journal could not be validated on restart", e)
	}
	defer reopened.Close()
	if o := reopened.Observe(); o.Unresolved != 0 || o.Unfinished != 0 || o.CleanupAuthorized || o.ExclusiveOrigin {
		t.Fatal("bound journal invented cleanup authority")
	}
}
func TestBoundJournalCannotBeAddedToUnsealedOrLegacyAttempt(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		path, engine := journalFixture(t)
		j, e := Open(path, engine)
		if e != nil {
			t.Fatal(e)
		}
		if sealed {
			if e = j.RequirePolicy(source.Hash([]byte("legacy seal"))); e != nil {
				t.Fatal(e)
			}
		}
		name := "aegis-scan-" + strings.Repeat("b", 32)
		a, e := j.Begin(name, source.Hash([]byte("body")))
		if e != nil {
			t.Fatal(e)
		}
		if !sealed {
			if _, e = a.BeginBound("create", "", controllerProposal(t, "create", "", name)); e == nil {
				t.Fatal("unsealed bound request accepted")
			}
		} else {
			ticket, e := a.Begin("create", "")
			if e != nil {
				t.Fatal(e)
			}
			id := strings.Repeat("c", 64)
			if e = ticket.Confirm(201, id); e != nil {
				t.Fatal(e)
			}
			if _, e = a.BeginBound("start", id, controllerProposal(t, "start", id, name)); e == nil {
				t.Fatal("legacy attempt relabelled")
			}
		}
		j.Close()
	}
}
