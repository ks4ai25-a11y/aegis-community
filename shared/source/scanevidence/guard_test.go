// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"testing"
)

func TestGuardSetBindsProtocolArchitectureAndDigests(t *testing.T) {
	a, b := source.Hash([]byte("amd64")), source.Hash([]byte("arm64"))
	g, e := NewGuardSet(a, b)
	if e != nil || !g.Valid() || g.Architecture(a) != "amd64" || g.Architecture(b) != "arm64" || g.Architecture(source.Hash([]byte("other"))) != "" {
		t.Fatal("invalid guard set", g, e)
	}
	for _, kind := range []string{"hash", "schema", "protocol", "swapped", "same"} {
		bad := g
		switch kind {
		case "hash":
			bad.Digest = a
		case "schema":
			bad.Schema = "wrong"
		case "protocol":
			bad.Protocol = "relative-duration"
		case "swapped":
			bad.AMD64, bad.ARM64 = bad.ARM64, bad.AMD64
		case "same":
			bad.ARM64 = bad.AMD64
		}
		if bad.Valid() {
			t.Fatal("altered set accepted", kind)
		}
	}
	if _, e = NewGuardSet(a, a); e == nil {
		t.Fatal("indistinguishable architecture builds accepted")
	}
}
