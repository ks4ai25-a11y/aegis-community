// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source/scanevidence"
	"context"
	"errors"
	"time"
)

// CleanupConfirmation reads the retained independent cleanup confirmation
// that covered one exact container this worker launched. A crashed worker
// uses it to close the matching attempt in its own journal (ADR 057). It is
// read-only and carries no engine, lease or release authority.
func (c *Client) CleanupConfirmation(ctx context.Context, container string) (scanevidence.CleanupConfirmation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, e := c.Identity(ctx); e != nil {
		return scanevidence.CleanupConfirmation{}, e
	}
	var out scanevidence.CleanupConfirmation
	if e := c.call(ctx, "cleanup-confirmation", map[string]string{"container_name": container}, &out, 16<<10); e != nil {
		return scanevidence.CleanupConfirmation{}, e
	}
	confirmed, e := time.Parse(time.RFC3339Nano, out.Confirmed)
	if e != nil || out.Schema != "1.0" || !out.Covers(container) || out.Digest != scanevidence.NewCleanupConfirmation(out.Reconciler, out.Request, confirmed).Digest {
		return scanevidence.CleanupConfirmation{}, errors.New("cleanup confirmation rejected")
	}
	return out, nil
}
