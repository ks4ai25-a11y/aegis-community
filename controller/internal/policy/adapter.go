// SPDX-License-Identifier: BUSL-1.1
package policy

import (
	"aegis.local/controller/internal/domain"
	"context"
	"errors"
)

// Adapter is the enforcement-point contract every control location implements:
// the HTTP gateway today; application middleware, database policies or identity
// providers in extensions. It has exactly three verbs and three outcome classes:
// success, definitive refusal (nothing was attempted, e.g. ErrDeployerBusy or a
// validation error) and unknown (anything else), which callers must reconcile
// rather than retry blindly.
type Adapter interface {
	// Status returns the revision digest currently enforced.
	Status(ctx context.Context) (string, error)
	// Validate checks a candidate without changing enforcement and returns its digest.
	Validate(ctx context.Context, p domain.Policy) (string, error)
	// Apply enforces the candidate; it must refuse when the enforced revision is
	// not the candidate's parent (compare-and-swap).
	Apply(ctx context.Context, p domain.Policy) error
	// Capabilities declares what the adapter can enforce before it is used.
	Capabilities() Capability
}

// Capability is the manifest an adapter declares (Frontier manual D7 shape).
type Capability struct {
	Adapter     string           `json:"adapter"`
	Version     string           `json:"version"`
	Supports    []string         `json:"supports"`
	Requires    []string         `json:"requires"`
	Safety      CapabilitySafety `json:"safety"`
	Unsupported []string         `json:"unsupported"`
}

type CapabilitySafety struct {
	ReadOnlyDiscovery     bool   `json:"readOnlyDiscovery"`
	WriteRequiresApproval bool   `json:"writeRequiresApproval"`
	RollbackSupported     string `json:"rollbackSupported"`
}

// ErrUnknownOutcome classifies an apply whose effect could not be confirmed.
var ErrUnknownOutcome = errors.New("enforcement outcome unknown; reconcile before retrying")

// Definitive reports whether err proves nothing was changed.
func Definitive(err error) bool {
	return errors.Is(err, ErrDeployerBusy)
}

// GatewayAdapter exposes the Caddy/Coraza gateway through Manager.
type GatewayAdapter struct{ M *Manager }

func (g GatewayAdapter) Status(ctx context.Context) (string, error) { return g.M.Active(ctx) }
func (g GatewayAdapter) Validate(ctx context.Context, p domain.Policy) (string, error) {
	return g.M.Prepare(ctx, p)
}
func (g GatewayAdapter) Apply(ctx context.Context, p domain.Policy) error {
	if e := g.M.Reload(ctx, p); e != nil {
		if Definitive(e) {
			return e
		}
		return errors.Join(ErrUnknownOutcome, e)
	}
	return nil
}
func (GatewayAdapter) Capabilities() Capability {
	return Capability{
		Adapter: "caddy-coraza-gateway", Version: "1.1",
		Supports:    []string{"http-request-inspection", "crs-anomaly-blocking", "scoped-rule-exclusion", "per-client-rate-limit", "tls-termination", "host-routing"},
		Requires:    []string{"typed-policy-v1.1", "privileged-deployer-socket", "isolated-fixture-preview"},
		Safety:      CapabilitySafety{ReadOnlyDiscovery: true, WriteRequiresApproval: true, RollbackSupported: "full"},
		Unsupported: []string{"tenant-ownership-authorization", "transactional-business-invariants", "identity-provider-policy", "database-row-policy"},
	}
}

var _ Adapter = GatewayAdapter{}
