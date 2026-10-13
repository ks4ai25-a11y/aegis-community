package scope

import (
	"testing"
	"time"
)

func TestScopeCannotExpandNetworkOrTargets(t *testing.T) {
	now := time.Now()
	g := Demo("owner", now.Add(time.Minute))
	if e := Validate(g, "owner", now); e != nil {
		t.Fatal(e)
	}
	g.Addresses = []string{"169.254.169.254:80"}
	if Validate(g, "owner", now) == nil {
		t.Fatal("metadata target accepted")
	}
	g = Demo("owner", now.Add(time.Minute))
	g.Mode = "production_intrusive"
	if Validate(g, "owner", now) == nil {
		t.Fatal("production mode accepted")
	}
}
func TestScopeExpiryAndOwnership(t *testing.T) {
	now := time.Now()
	g := Demo("owner", now.Add(time.Minute))
	if Validate(g, "other", now) == nil {
		t.Fatal("owner mismatch")
	}
	if Validate(g, "owner", now.Add(2*time.Minute)) == nil {
		t.Fatal("expired scope accepted")
	}
}
