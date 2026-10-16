//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"testing"
)

func TestJournalBindingPrivateReadRefusesMissingScopeMutationAndRevocation(t *testing.T) {
	s, enrollment, _ := fixture(t)
	h := s.Handler()
	call(t, h, enrollment.Token, "engine-journal-binding", "{}", 404)
	if _, e := s.Q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))); e != nil {
		t.Fatal(e)
	}
	call(t, h, enrollment.Token, "engine-journal-binding", "{}", 404)
	bound, e := s.Q.BindJournal("owner-a", domain.Hash([]byte("root")), domain.Hash([]byte("namespace")))
	if e != nil {
		t.Fatal(e)
	}
	out := call(t, h, enrollment.Token, "engine-journal-binding", "{}", 200)
	if out["journal_binding_digest"] != bound.Digest {
		t.Fatal(out)
	}
	for _, body := range []string{`{"owner_id":"owner-b"}`, `{"journal_namespace_digest":"arbitrary"}`} {
		call(t, h, enrollment.Token, "engine-journal-binding", body, 400)
	}
	call(t, h, enrollment.Token, "engine-journal-binding/bind", "{}", 404)
	call(t, h, "", "engine-journal-binding", "{}", 401)
	if e = s.Auth.Revoke("owner-a", enrollment.Worker.ID); e != nil {
		t.Fatal(e)
	}
	call(t, h, enrollment.Token, "engine-journal-binding", "{}", 401)
}
