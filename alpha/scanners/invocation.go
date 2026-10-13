// SPDX-License-Identifier: Apache-2.0
package scanners

import "aegis.local/source/scanevidence"

type Invocation = scanevidence.Invocation

// BuildInvocation exposes the same fixed data contract used at receipt validation.
func BuildInvocation(tool string) (Invocation, error) { return scanevidence.BuildInvocation(tool) }
