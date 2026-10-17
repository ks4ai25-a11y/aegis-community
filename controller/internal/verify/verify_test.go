// SPDX-License-Identifier: BUSL-1.1
package verify

import (
	"aegis.local/controller/internal/domain"
	"testing"
)

func TestVR003NoFalseGreen(t *testing.T) {
	for _, p := range [][2]int{{0, 0}, {200, 0}, {502, 403}, {200, 502}, {403, 403}} {
		if Classify(p[0], p[1], []string{"942100"}, "protect") == "PASS" {
			t.Fatal("false green", p)
		}
	}
	if Classify(200, 403, nil, "protect") == "PASS" {
		t.Fatal("denial without rule evidence accepted")
	}
	if Classify(200, 403, []string{"942100"}, "protect") != "PASS" {
		t.Fatal("valid control rejected")
	}
}

func TestSummaryWithoutControlsRejected(t *testing.T) {
	p := domain.Initial()
	r := domain.Report{Schema: "1.0", Fixture: Fixture, FixtureDigest: FixtureDigest(), Candidate: domain.Digest(p), Overall: "PASS"}
	if ValidateReport(r, p) == nil {
		t.Fatal("empty green report accepted")
	}
}
