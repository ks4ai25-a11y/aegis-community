// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"aegis.local/source/scanevidence"
	"fmt"
)

// Dedupe retains the standalone adapter's 10,000-claim budget. Controller
// suites use the shared implementation with a bounded six-tool aggregate.
func Dedupe(in []Finding) ([]Finding, error) {
	if len(in) > 10000 {
		return nil, fmt.Errorf("finding aggregation budget exceeded")
	}
	return scanevidence.Dedupe(in)
}
