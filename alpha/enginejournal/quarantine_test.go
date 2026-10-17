// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package enginejournal

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const crashedAttempt = "aegis-scan-00112233445566778899aabbccddeeff"

var testEngine = source.Hash([]byte("quarantine test engine"))

// crashedJournal leaves one attempt with an unanswered create, optionally
// under a sealed local policy as an admitted plugin journal has.
func crashedJournal(t *testing.T, policy bool) string {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "journal")
	j, e := Open(path, testEngine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if policy {
		if e = j.RequirePolicy(source.Hash([]byte("sealed admitted policy"))); e != nil {
			t.Fatal(e)
		}
	}
	a, e := j.Begin(crashedAttempt, source.Hash([]byte("descriptor")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Begin("create", ""); e != nil {
		t.Fatal(e)
	}
	return path
}

func reopen(t *testing.T, path string) *Journal {
	t.Helper()
	j, e := OpenExisting(path, testEngine)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(j.Close)
	return j
}

func TestQuarantineSealRequiresSealedPolicyAndUnfinishedAttempt(t *testing.T) {
	j := reopen(t, crashedJournal(t, false))
	if _, e := j.SealQuarantine(); e == nil {
		t.Fatal("unbound journal sealed in quarantine")
	}
	j = reopen(t, crashedJournal(t, true))
	first, e := j.SealQuarantine()
	if e != nil || first.Sequence != 1 || first.Activation != "" || len(first.Attempts) != 1 || first.Attempts[0] != crashedAttempt {
		t.Fatal("seal", first, e)
	}
	if again, e := j.SealQuarantine(); e != nil || again.Quarantine != first.Quarantine {
		t.Fatal("restart did not reuse the open seal", e)
	}
	if e = j.RecordRepair(crashedAttempt, "create", repairNotCreated, "", source.Hash([]byte("controller repair"))); e == nil {
		t.Fatal("repair recorded before a post-seal activation")
	}
	activated, e := j.RecordActivation()
	if e != nil || activated.Activation == "" {
		t.Fatal(e)
	}
	if again, e := j.RecordActivation(); e != nil || again.Activation != activated.Activation {
		t.Fatal("a later activation replaced the first", e)
	}
}

func TestRepairRecordsAnswerOnlyThePendingOperation(t *testing.T) {
	path := crashedJournal(t, true)
	j := reopen(t, path)
	if _, e := j.SealQuarantine(); e != nil {
		t.Fatal(e)
	}
	if _, e := j.RecordActivation(); e != nil {
		t.Fatal(e)
	}
	digest := source.Hash([]byte("controller repair"))
	for _, bad := range [][4]string{
		{"start", repairStarted, strings.Repeat("e", 64), digest},
		{"create", repairCreated, "", digest},
		{"create", repairNotCreated, strings.Repeat("e", 64), digest},
		{"create", repairNotAdmitted, "", digest},
		{"create", repairCreated, strings.Repeat("e", 64), ""},
		{"create", "absent", "", digest},
	} {
		if j.RecordRepair(crashedAttempt, bad[0], bad[1], bad[2], bad[3]) == nil {
			t.Fatal("invalid repair recorded", bad)
		}
	}
	if e := j.RecordRepair(crashedAttempt, "create", repairCreated, strings.Repeat("e", 64), digest); e != nil {
		t.Fatal(e)
	}
	if !j.KnownContainer(strings.Repeat("e", 64)) {
		t.Fatal("repaired engine ID not readable by exact observation")
	}
	if o := j.Observe(); o.Unresolved != 0 || o.Unfinished != 1 {
		t.Fatal("a created allocation still needs its removal", o)
	}
	if e := j.RecordRepair(crashedAttempt, "create", repairCreated, strings.Repeat("e", 64), digest); e == nil {
		t.Fatal("pending operation repaired twice")
	}
	j.Close()
	ev, e := ReadEvidence(path, testEngine, crashedAttempt)
	if e != nil || ev.Attempt.Known != strings.Repeat("e", 64) || ev.Attempt.Repairs["create"].Outcome != repairCreated || ev.Quarantine.Activation == "" {
		t.Fatal("lock-free evidence does not show the repair", e)
	}
	a := reopen(t, path)
	resumed, e := a.Resume(crashedAttempt)
	if e != nil || resumed.Container() != strings.Repeat("e", 64) || resumed.PendingTicket() != nil {
		t.Fatal("repaired attempt not resumable for removal", e)
	}
	ticket, e := resumed.Begin("remove", strings.Repeat("e", 64))
	if e != nil || ticket.Confirm(204, strings.Repeat("e", 64)) != nil || resumed.Finish() != nil {
		t.Fatal("normal removal after repair failed", e)
	}
	if o := a.Observe(); o.Unfinished != 0 || o.Unresolved != 0 {
		t.Fatal("removed attempt still unfinished", o)
	}
}

func TestQuarantineRecordsCannotBeForgedOrReordered(t *testing.T) {
	for _, kind := range []string{"activation without seal", "repair without activation", "release in admitted journal"} {
		t.Run(kind, func(t *testing.T) {
			path := crashedJournal(t, true)
			j := reopen(t, path)
			if _, e := j.SealQuarantine(); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "activation without seal":
				if _, e := j.RecordActivation(); e != nil {
					t.Fatal(e)
				}
				j.Close()
				if e := os.Rename(filepath.Join(path, "activation.1.json"), filepath.Join(path, "activation.2.json")); e != nil {
					t.Fatal(e)
				}
			case "repair without activation":
				j.Close()
				d := wrapped(repairRecord{Schema: "1.0", Intent: source.Hash([]byte("x")), Operation: "create", Outcome: repairNotCreated, Controller: source.Hash([]byte("c")), Created: "2026-10-17T00:00:00Z"})
				p, e := openPrivate(filepath.Join(path, crashedAttempt))
				if e != nil {
					t.Fatal(e)
				}
				if e = (&Journal{}).write(p, "create.repair.json", d); e != nil {
					t.Fatal(e)
				}
				p.close()
			case "release in admitted journal":
				c := scanevidence.CleanupConfirmation{Schema: "1.0", Released: true, Digest: source.Hash([]byte("c")), Request: scanevidence.CleanupConfirmationRequest{Job: "01890f3e-1c2d-7abc-8def-0123456789ab", Generation: strings.Repeat("a", 64), Membership: source.Hash([]byte("m")), Engine: testEngine, Namespace: source.Hash([]byte("n")), Absent: []scanevidence.CleanupAbsence{{Tool: "bandit", Container: crashedAttempt}}}}
				if j.SettleReleased(crashedAttempt, c) == nil {
					t.Fatal("plugin journal settled by a release record")
				}
				return
			}
			if j, e := OpenExisting(path, testEngine); e == nil {
				j.Close()
				t.Fatal("forged quarantine record accepted")
			}
		})
	}
}
