// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestDeletionLimitsNeutralWording(t *testing.T) {
	const want = "  The database's old pages and write-ahead log, its replicas and snapshots of its volume, which keep the data for a while;"
	for _, org := range []bool{false, true} {
		lines := deletionLimits(org)
		joined := strings.Join(lines, "\n")
		if strings.Contains(joined, "PostgreSQL") {
			t.Errorf("organization=%v: deletionLimits still mentions PostgreSQL: %s", org, joined)
		}
		if !strings.Contains(joined, want) {
			t.Errorf("organization=%v: deletionLimits missing neutral storage line %q in:\n%s", org, want, joined)
		}
	}
}
