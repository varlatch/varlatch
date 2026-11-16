// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
)

// A report count runs after its response, so it enters the maintenance
// admission on its own: dropped while a gate is open, and counted until
// its write has committed.
func TestReportCountEntersMaintenanceAdmission(t *testing.T) {
	wd := newWorld(t)
	report := auth.PendingReport{OrganizationID: wd.org, ActorIdentityID: "idn_a", ConfigVersion: 1, Reason: "no-evidence"}
	counted := func() int64 {
		rows := paritytest.Rows(t, wd.store, `SELECT coalesce(sum(count), 0) AS n FROM security_control_counters WHERE organization_id = ?`, wd.org)
		return rows[0]["n"].(int64)
	}
	closed := values.New(wd.store, wd.rootKEK, values.Options{Admit: func() (func(), bool) { return nil, false }})
	closed.QueueAccessCount(report, "project.read", time.Now().UnixMicro())
	closed.Settled()
	if n := counted(); n != 0 {
		t.Fatalf("counted %d during maintenance", n)
	}
	var mu sync.Mutex
	busy, atLeave := 0, int64(-1)
	open := values.New(wd.store, wd.rootKEK, values.Options{Admit: func() (func(), bool) {
		mu.Lock()
		busy++
		mu.Unlock()
		return func() { mu.Lock(); busy--; atLeave = counted(); mu.Unlock() }, true
	}})
	open.QueueAccessCount(report, "project.read", time.Now().UnixMicro())
	open.Settled()
	if busy != 0 || atLeave != 1 || counted() != 1 {
		t.Fatalf("busy %d, %d counted when it left, %d after", busy, atLeave, counted())
	}
}
