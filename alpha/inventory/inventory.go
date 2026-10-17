// SPDX-License-Identifier: BUSL-1.1
// Package inventory exposes the shared non-executing inventory layer.
package inventory

import "aegis.local/source"

const MaxBytes = source.MaxBytes
const MaxFileBytes = source.MaxFileBytes

type File = source.File
type Route = source.Route
type Map = source.Map

var Read = source.Read
var Hash = source.Hash
