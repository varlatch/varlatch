// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps_test

import (
	"context"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/orgdeletion"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/security"
)

// TestOrganizationDeletionEndsTheApp: an Organization's deletion ends its
// GitHub App through this package. Scheduling deletes its unfinished
// registrations (pending keys with them); the run removes the App's local
// registration and key, after which the same App can be imported into
// another Organization (GitHub still has it).
func TestOrganizationDeletionEndsTheApp(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	if out, err := wd.importApp(); err != nil || !out.Registered {
		t.Fatalf("the import: %+v, %v", out, err)
	}
	wd.registration("fresh", time.Hour)
	wd.pending("waiting", false)

	scheduled, err := orgdeletion.Schedule(ctx, wd.w, orgdeletion.ScheduleRequest{Security: security.Request{Principal: alice, Approvals: wd.approvals}}, wd.org.ID, time.Now)
	if err != nil {
		t.Fatalf("scheduling: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM github_app_registrations WHERE organization_id = ?`, wd.org.ID); n != 0 {
		t.Fatalf("%d registrations left after scheduling", n)
	}
	id, _ := scheduled.View.Get("id")
	wd.exec(`UPDATE organization_deletions SET scheduled_at = scheduled_at - ?, run_after = ? WHERE id = ?`,
		(40 * 24 * time.Hour).Microseconds(), time.Now().Add(-time.Second).UnixMicro(), id)
	run := &orgdeletion.Service{Writer: wd.w, Approvals: wd.approvals, Now: time.Now}
	o, err := run.Finalize(ctx, id.(string), wd.org.ID)
	if err != nil || o == nil || !o.GitHubAppRemoved {
		t.Fatalf("the run: %+v, %v", o, err)
	}
	if n := wd.count(`SELECT count(*) FROM github_apps WHERE organization_id = ? AND (removed_at IS NULL OR key_envelope IS NOT NULL)`, wd.org.ID); n != 0 {
		t.Fatal("the App or its key is still there")
	}

	other, err := orgs.Create(ctx, wd.w, wd.s.RootKEK, "idn_a", "beta", "Beta")
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := wd.s.Import(ctx, githubapps.Request{Principal: alice, RequestID: "req_b"}, authz.Organization{ID: other.ID, Slug: "beta", Name: "Beta"}, 4004, wd.key)
	if err != nil || !out.Registered {
		t.Fatalf("importing the App into another Organization: %+v, %v", out, err)
	}
}
