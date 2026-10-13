// SPDX-License-Identifier: Apache-2.0
package main
import (
 caddycmd "github.com/caddyserver/caddy/v2/cmd"
 _ "github.com/caddyserver/caddy/v2/modules/standard"
 _ "github.com/corazawaf/coraza-caddy/v2"
 _ "aegis.local/gateway/telemetry"
)
func main(){ caddycmd.Main() }
