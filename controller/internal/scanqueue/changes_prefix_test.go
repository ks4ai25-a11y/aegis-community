// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestRescanLiteralPrefixNeverSchedulesNearMatchSetting(t *testing.T) {
	q, input, _ := fixture(t)
	p := RescanPolicy{Schema: "1.0", Owner: "owner-a", Repository: input.Repository, Enabled: true, Tools: []string{"bandit"}, Duration: 120, BaselineDigest: input.MapDigest}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.S.Set("rescanXpolicy/owner-a/"+input.Repository, string(raw)); err != nil {
		t.Fatal(err)
	}
	called := false
	results, err := q.CheckChanges(context.Background(), func(context.Context, string, string) (string, error) {
		called = true
		return "changed", nil
	}, 10, 0)
	if err != nil || called || len(results) != 0 {
		t.Fatal("near-match setting gained automatic scan authority", err)
	}
}

func TestRescanLiteralPrefixCountExcludesUnrelatedSettings(t *testing.T) {
	q, input, _ := fixture(t)
	for n := 0; n < 100; n++ {
		if err := q.S.Set(fmt.Sprintf("rescanXpolicy/owner-a/unrelated-%d", n), "unrelated"); err != nil {
			t.Fatal(err)
		}
	}
	p, err := q.SetRescanPolicy("owner-a", input.Repository, true, []string{"bandit"}, 120)
	if err != nil || !p.Enabled {
		t.Fatal("unrelated settings consumed the owner's rescan quota", err)
	}
}

func TestRescanLiteralPrefixCountUsesCharacterLengthForUnicodeOwner(t *testing.T) {
	q, input, _ := fixture(t)
	owner := "owner-ä"
	if _, err := q.S.DB.Exec("INSERT INTO owners(id,password,created_at) SELECT ?,password,created_at FROM owners WHERE id='owner-a'", owner); err != nil {
		t.Fatal(err)
	}
	if _, err := q.S.DB.Exec("UPDATE repositories SET owner=? WHERE id=?", owner, input.Repository); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		if err := q.S.Set(fmt.Sprintf("rescan_policy/%s/reserved-%d", owner, n), "{}"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.SetRescanPolicy(owner, input.Repository, true, []string{"bandit"}, 120); err != ErrFull {
		t.Fatal("Unicode prefix escaped per-owner policy quota", err)
	}
}
