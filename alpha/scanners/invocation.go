// SPDX-License-Identifier: BUSL-1.1
package scanners

import "aegis.local/source/scanevidence"

type Invocation = scanevidence.Invocation

// BuildInvocation exposes the same fixed data contract used at receipt validation.
func BuildInvocation(tool string) (Invocation, error) { return scanevidence.BuildInvocation(tool) }

func BuildDatabaseInvocation(tool string) (Invocation, error) {
	return scanevidence.BuildDatabaseInvocation(tool)
}
func DatabaseContainerPath(tool string) (string, error) {
	return scanevidence.DatabaseContainerPath(tool)
}
