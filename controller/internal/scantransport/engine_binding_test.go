//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"testing"
)

func TestEngineBindingPrivateWorkerReadHasNoProvisioningOrOwnerOverride(t *testing.T) {
	s, enrollment, _ := fixture(t)
	h := s.Handler()
	call(t, h, enrollment.Token, "engine-binding", "{}", 404)
	bound, e := s.Q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry")))
	if e != nil {
		t.Fatal(e)
	}
	out := call(t, h, enrollment.Token, "engine-binding", "{}", 200)
	if out["binding_digest"] != bound.Digest {
		t.Fatal("binding mismatch")
	}
	for _, body := range []string{`{"owner_id":"owner-b"}`, `{"engine_digest":"arbitrary"}`, `{"scope":{}}`} {
		call(t, h, enrollment.Token, "engine-binding", body, 400)
	}
	call(t, h, "", "engine-binding", "{}", 401)
	call(t, h, enrollment.Token, "engine-binding/bind", "{}", 404)
	s.Auth.Revoke("owner-a", enrollment.Worker.ID)
	call(t, h, enrollment.Token, "engine-binding", "{}", 401)
}
