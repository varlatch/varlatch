// SPDX-License-Identifier: AGPL-3.0-or-later

package entry

import (
	"context"
	"errors"
	"testing"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

// Create bounds a link's life itself, whoever calls it: refused before
// anything is read or written.
func TestCreateBoundsTTL(t *testing.T) {
	for _, ttl := range []int64{-1, MinTTLSeconds - 1, MaxTTLSeconds + 1, 1 << 40} {
		_, _, err := (&Service{}).Create(context.Background(), Request{}, Input{Item: "NEW_KEY", TTLSeconds: ttl}, nil)
		var d *domainerr.Error
		if !errors.As(err, &d) || d.Code != "VALIDATION_FAILED" {
			t.Errorf("%d: %v", ttl, err)
		}
	}
}
