//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"testing"
)

func TestPrivateBrokerBindingReadRejectsMutationAndRevocation(t *testing.T) {
	s, enrollment, _ := fixture(t)
	h := s.Handler()
	call(t, h, enrollment.Token, "engine-broker-binding", "{}", 404)
	base, e := s.Q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry")))
	if e != nil {
		t.Fatal(e)
	}
	_ = base
	if _, e = s.Q.BindJournal("owner-a", domain.Hash([]byte("root")), domain.Hash([]byte("namespace"))); e != nil {
		t.Fatal(e)
	}
	bound, e := s.Q.BindBroker("owner-a", enrollment.Worker.ID)
	if e != nil {
		t.Fatal(e)
	}
	out := call(t, h, enrollment.Token, "engine-broker-binding", "{}", 200)
	if out["broker_binding_digest"] != bound.Digest {
		t.Fatal(out)
	}
	call(t, h, enrollment.Token, "engine-broker-binding", `{"worker_id":"other"}`, 400)
	call(t, h, enrollment.Token, "engine-broker-binding/bind", "{}", 404)
	call(t, h, "", "engine-broker-binding", "{}", 401)
	if e = s.Auth.Revoke("owner-a", enrollment.Worker.ID); e != nil {
		t.Fatal(e)
	}
	call(t, h, enrollment.Token, "engine-broker-binding", "{}", 401)
}
