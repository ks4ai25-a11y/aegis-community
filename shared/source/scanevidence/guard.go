// SPDX-License-Identifier: BUSL-1.1
package scanevidence

const GuardProtocol = "absolute-deadline-v1"

// GuardSet identifies the two operator-provisioned guard builds. Its hash is
// local package identity, not publisher signing or runtime attestation.
type GuardSet struct {
	Schema   string `json:"schema_version"`
	Protocol string `json:"protocol"`
	AMD64    string `json:"linux_amd64"`
	ARM64    string `json:"linux_arm64"`
	Digest   string `json:"guard_set_digest"`
}

func NewGuardSet(amd64, arm64 string) (GuardSet, error) {
	g := GuardSet{Schema: "1.0", Protocol: GuardProtocol, AMD64: amd64, ARM64: arm64}
	if !hash.MatchString(amd64) || !hash.MatchString(arm64) || amd64 == arm64 {
		return GuardSet{}, ErrReceipt
	}
	g.Digest = digest(g)
	return g, nil
}
func (g GuardSet) Valid() bool {
	expected, e := NewGuardSet(g.AMD64, g.ARM64)
	return e == nil && expected == g
}
func (g GuardSet) Architecture(guard string) string {
	if !g.Valid() {
		return ""
	}
	if guard == g.AMD64 {
		return "amd64"
	}
	if guard == g.ARM64 {
		return "arm64"
	}
	return ""
}
