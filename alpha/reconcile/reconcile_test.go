// SPDX-License-Identifier: BUSL-1.1
package reconcile

import (
	"aegis.local/alpha/engineobserve"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeController struct {
	calls  *[]string
	s      scanevidence.ReconciliationSnapshot
	absent []scanevidence.CleanupAbsence
}

func (f *fakeController) Snapshot(ctx context.Context, job, generation string) (scanevidence.ReconciliationSnapshot, error) {
	*f.calls = append(*f.calls, "snapshot")
	return f.s, nil
}
func (f *fakeController) Confirm(ctx context.Context, s scanevidence.ReconciliationSnapshot, absent []scanevidence.CleanupAbsence) (scanevidence.CleanupConfirmation, error) {
	*f.calls = append(*f.calls, "confirm")
	f.absent = absent
	return scanevidence.CleanupConfirmation{Released: true}, nil
}

type fakeObserver struct {
	calls   *[]string
	fail    bool
	targets []engineobserve.Target
}

func (f *fakeObserver) VerifyAbsent(ctx context.Context, targets []engineobserve.Target) error {
	*f.calls = append(*f.calls, "observe")
	f.targets = targets
	if f.fail {
		return engineobserve.ErrUnconfirmed
	}
	return nil
}

func snapshot(t *testing.T) scanevidence.ReconciliationSnapshot {
	t.Helper()
	var s scanevidence.ReconciliationSnapshot
	b, err := os.ReadFile("../../contracts/samples/ScannerReconciliationSnapshotV1.json")
	if err != nil || json.Unmarshal(b, &s) != nil {
		t.Fatal("sample snapshot unavailable")
	}
	return s
}

func TestReleaseObservesUnderBarrierBeforeConfirming(t *testing.T) {
	for _, kind := range []string{"ok", "observer-fails", "barrier-refuses", "namespace", "unresolved", "uncreated"} {
		t.Run(kind, func(t *testing.T) {
			calls := []string{}
			s := snapshot(t)
			ns := s.Membership.Binding.Document.Namespace
			absent := []scanevidence.CleanupAbsence{{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("0", 32), EngineID: strings.Repeat("c", 64)}}
			if kind == "uncreated" {
				absent[0].EngineID = ""
			}
			c := &fakeController{calls: &calls, s: s}
			o := &fakeObserver{calls: &calls, fail: kind == "observer-fails"}
			barrier := func(ctx context.Context, path, namespace string, work func() error) error {
				if kind == "barrier-refuses" || namespace != ns || path != "/registry" {
					return errors.New("registry not empty")
				}
				calls = append(calls, "enter")
				err := work()
				calls = append(calls, "exit")
				return err
			}
			r := Release{Controller: c, Observer: o, Barrier: barrier, Registry: "/registry", Namespace: ns, Required: func(scanevidence.ReconciliationMembership) ([]scanevidence.CleanupAbsence, error) {
				if kind == "unresolved" {
					return nil, scanevidence.ErrNotReleasable
				}
				return absent, nil
			}}
			if kind == "namespace" {
				c.s.Membership.Binding.Document.Namespace = "sha256:" + strings.Repeat("1", 64)
			}
			out, err := r.Run(context.Background(), s.Membership.Job, s.Membership.Generation.ID)
			got := strings.Join(calls, ",")
			switch kind {
			case "ok", "uncreated":
				if err != nil || !out.Released || got != "enter,snapshot,observe,confirm,exit" || len(o.targets) != 1 || o.targets[0].Name != absent[0].Container || o.targets[0].ID != absent[0].EngineID || len(c.absent) != 1 {
					t.Fatal("release did not observe exact targets under the barrier", got, err)
				}
			default:
				if err == nil || strings.Contains(got, "confirm") {
					t.Fatal("release confirmed without a complete observation", got)
				}
			}
		})
	}
}
