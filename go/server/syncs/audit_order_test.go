// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// A sync run's decryption follows the commit of sync.values_decrypted
// (docs/THREAT-MODEL.md): with every version unopenable, each run fails,
// pushes nothing and its event is there; with that event refused, nothing
// but the refusal is reported.
func TestSyncDecryptionFollowsItsAuditCommit(t *testing.T) {
	count := func(w *engineWorld) int64 {
		return paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'sync.values_decrypted'`)[0]["n"].(int64)
	}
	w := newEngineWorld(t)
	before := count(w)
	w.exec(`UPDATE value_versions SET payload = wrapped_dek WHERE payload IS NOT NULL`)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if n := count(w); n == before {
		t.Error("values were opened before their audit event committed")
	}
	for _, line := range w.fake.take() {
		if !strings.HasPrefix(line, "GET ") && !strings.Contains(line, "/api/query ") {
			t.Errorf("sent: %s", line)
		}
	}
	w = newEngineWorld(t)
	before = count(w)
	w.exec(`UPDATE value_versions SET payload = wrapped_dek WHERE payload IS NOT NULL`)
	w.exec(`CREATE TRIGGER refuse BEFORE INSERT ON audit_events WHEN NEW.event_type = 'sync.values_decrypted' BEGIN SELECT RAISE(ABORT, 'no audit today'); END`)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if count(w) != before {
		t.Error("the refused event is there")
	}
	for _, r := range w.targets() {
		if result, _ := r["last_result"].(string); r["failure_count"] != int64(0) && !strings.Contains(result, "no audit today") {
			t.Errorf("%v: %q: the run failed on something else first", r["canonical_destination"], result)
		}
	}
}
