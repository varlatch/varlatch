// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"context"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
)

// Every decryption follows the commit of the audit event that names its
// version (docs/THREAT-MODEL.md). A version that cannot be opened shows the
// order from outside: opened first, it would end the request with no event;
// here its event is there, and a referenced value's only once the Secret
// that names it was opened. With audit inserts refused, that refusal ends
// the request, before the version that cannot be opened was tried. Every
// operation of this package opens values through auditThenDecrypt.
func TestDecryptionFollowsItsAuditCommit(t *testing.T) {
	version := func(wd *world, item string) string {
		return paritytest.Rows(t, wd.store, `SELECT current_version_id AS v FROM env_values WHERE item_name = ?`, item)[0]["v"].(string)
	}
	exec := func(wd *world, q string, args ...any) {
		if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(context.Background(), q, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// prepared has SECRET, which refers to INNER, and broken's version
	// holding another version's ciphertext.
	prepared := func(broken string) *world {
		wd := newWorld(t)
		wd.contract([]string{"SECRET", "INNER", "OTHER"}, "SECRET")
		for item, v := range map[string]string{"SECRET": "x-${INNER}", "INNER": "inner", "OTHER": "other"} {
			wd.set("dev", item, v)
		}
		exec(wd, `UPDATE value_versions SET payload = (SELECT payload FROM value_versions WHERE id = ?) WHERE id = ?`, version(wd, "OTHER"), version(wd, broken))
		return wd
	}
	disclose := func(wd *world) error {
		_, err := wd.svc.Disclose(context.Background(), values.Request{Principal: alice(), RequestID: "req_test", Method: "POST",
			Route: "/v1/organizations/:org/projects/:project/environments/:environment/disclosures", Org: "acme", Project: "api", Environment: "dev"}, []byte(`{"items":["SECRET"]}`))
		return err
	}
	audited := func(wd *world, item string) bool {
		return paritytest.Rows(t, wd.store, `SELECT count(*) AS n FROM audit_events WHERE event_type IN ('secret.disclosed', 'value.disclosed') AND metadata LIKE ?`,
			"%"+item+"@"+version(wd, item)+"%")[0]["n"].(int64) == 1
	}
	for _, c := range []struct {
		broken        string
		secret, inner bool
	}{{"SECRET", true, false}, {"INNER", true, true}, {"OTHER", true, true}} {
		wd := prepared(c.broken)
		if err := disclose(wd); (err == nil) != (c.broken == "OTHER") {
			t.Errorf("%s broken: %v", c.broken, err)
		}
		if s, i := audited(wd, "SECRET"), audited(wd, "INNER"); s != c.secret || i != c.inner {
			t.Errorf("%s broken: audited SECRET %t, INNER %t, want %t, %t", c.broken, s, i, c.secret, c.inner)
		}
	}
	wd := prepared("SECRET")
	exec(wd, `CREATE TRIGGER refuse BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'no audit today'); END`)
	if err := disclose(wd); err == nil || !strings.Contains(err.Error(), "no audit today") {
		t.Errorf("with audit inserts refused: %v", err)
	}
}
