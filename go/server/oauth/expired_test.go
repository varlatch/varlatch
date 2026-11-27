// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth

import (
	"database/sql"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/db/query"
)

// A connection's environment expires at the millisecond a value write is
// refused at, not at the microsecond.
func TestExpiredAtTheMillisecond(t *testing.T) {
	at := func(us int64) *row {
		return &row{OAuthConnectionByIDRow: query.OAuthConnectionByIDRow{EnvironmentExpiresAt: sql.NullInt64{Int64: us, Valid: true}}}
	}
	const ms = int64(1_800_000_000_000) * 1000
	for _, x := range []struct {
		expires, now int64
		expired      bool
	}{
		{ms + 999, ms, true},
		{ms + 999, ms - 1, false},
		{ms, ms + 999, true},
		{ms + 1000, ms + 999, false},
	} {
		err := at(x.expires).expired(time.UnixMicro(x.now))
		if (err != nil) != x.expired {
			t.Errorf("expires %d, now %d: %v", x.expires, x.now, err)
		}
	}
	if err := (&row{}).expired(time.UnixMicro(1)); err != nil {
		t.Errorf("no expiry: %v", err)
	}
}
