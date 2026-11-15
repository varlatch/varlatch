// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/values"
)

// Feature-parity decision 5, defect 2: in TypeScript an export under
// admin-step-up's report mode updates its counter before its audit insert
// locks the Organization and the exposure identities, so repeated exports
// in one counter bucket can deadlock in PostgreSQL and one is aborted. Here
// the count and the export's audit events are one job of the single
// writer, and no gate is taken inside a job: concurrent named and
// all-authorized exports in one bucket all succeed, and the counter is
// exact.
func TestConcurrentExportsUnderReportCountExactly(t *testing.T) {
	wd := newWorld(t)
	wd.contract([]string{"S", "T"}, "S", "T")
	wd.set("dev", "S", "s-value")
	wd.set("dev", "T", "t-value")
	ctx := context.Background()
	mode := security.Report
	if _, _, err := security.ChangeControl(ctx, wd.w, nil, security.ChangeInput{
		OrganizationID: wd.org, Control: security.AdminStepUp, Mode: &mode, Config: security.ConfigChange{Keep: true},
		Principal: alice(), RequestID: "req_test",
	}, time.Now); err != nil {
		t.Fatal(err)
	}
	const n = 24
	bodies := []string{`{"items":["S","T"],"purpose":"export"}`, `{"scope":"all-authorized-secrets","purpose":"export"}`}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := wd.svc.Disclose(ctx, values.Request{
				Principal: alice(), RequestID: "req_export", Method: "POST",
				Route: "/v1/organizations/:org/projects/:project/environments/:environment/secrets/disclose",
				Org:   "acme", Project: "api", Environment: "dev",
			}, []byte(bodies[i%2]))
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows := paritytest.Rows(t, wd.store, `SELECT sum(count) AS n FROM security_control_counters
		WHERE organization_id = ? AND control = 'admin-step-up' AND operation = 'secret.export' AND reason = 'no-approval'`, wd.org)
	if got := rows[0]["n"]; got != int64(n) {
		t.Fatalf("counted %v exports, want %d", got, n)
	}
	disclosed := paritytest.Rows(t, wd.store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'secret.disclosed' AND organization_id = ?`, wd.org)
	if got := disclosed[0]["n"]; got != int64(n) {
		t.Fatalf("%v disclosures audited, want %d", got, n)
	}
}
