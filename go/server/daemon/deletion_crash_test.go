// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint && !windows

package daemon

import (
	"bufio"
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/orgdeletion"
)

// G7 inside an Organization's deletion run (ADR-0059 step 4.12b; go test
// -tags crashpoint): varlatchd, a process of its own, finalizes acme's due
// deletion in its deletion loop and is killed with SIGKILL
//
//   - before the deletion's job (orgdeletion.CrashBeforeJob);
//   - inside the job, once every row and event is written, before the
//     commit (orgdeletion.CrashWritten);
//   - inside SQLite's commit of the batch holding that job, before its WAL
//     frames are written (the "commit" point, armed by CrashWritten);
//   - after the job committed (orgdeletion.CrashCommitted).
//
// Then varlatchd serves again on the same data; its loop runs at once. In
// every case acme ends deleted exactly once: one organization.deleted, one
// membership.removed and one removal per member, its tombstone and its
// request completed, every row the run ends ended, no gap in the audit
// positions, and a consistent database.

// deletionCrashInstall is g7Install with acme's deletion due: scheduled
// two days ago by one of its admins, due a day ago, no approval needed.
func deletionCrashInstall(t *testing.T) (install, string, string) {
	t.Helper()
	in, f := g7Install(t, t.TempDir())
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	org := f.Slugged("organizations", "acme", "")
	ctx := context.Background()
	err = store.Write(ctx, func(tx *storage.Tx) error {
		var admin string
		if err := tx.QueryRowContext(ctx, `SELECT identity_id FROM org_memberships WHERE organization_id = ? AND role = 'admin' AND removed_at IS NULL ORDER BY identity_id LIMIT 1`, org).Scan(&admin); err != nil {
			return err
		}
		now := time.Now()
		_, err := tx.ExecContext(ctx, `INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES (?, ?, ?, ?, ?, 0)`,
			ids.New(ids.OrganizationDeletion), org, admin, now.Add(-48*time.Hour).UnixMicro(), now.Add(-24*time.Hour).UnixMicro())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return in, org, f.Tokens["alice"]
}

// killDuringDeletion serves the install in a process of its own with env,
// waits until it logged "paused <point>", and kills it.
func killDuringDeletion(t *testing.T, in install, point string, env ...string) {
	t.Helper()
	log := filepath.Join(in.dir, "crashpoints-"+point+".log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillDuringDisclosuresLosesNoAuditRow$")
	cmd.Env = append(os.Environ(), append([]string{"G7_SERVE_CONF=" + in.conf, "VARLATCH_CRASHPOINT_LOG=" + log}, env...)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
		}
	}()
	paused := func() bool {
		b, _ := os.ReadFile(log)
		for _, l := range strings.Split(string(b), "\n") {
			if l == "paused "+point {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(60 * time.Second); !paused(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("varlatchd never paused at %s: %s", point, stderr.String())
		}
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

// deletedAfterRestart serves the install again, in this process, until
// acme is gone, and stops it.
func deletedAfterRestart(t *testing.T, in install, token string) {
	t.Helper()
	r := start(t, in)
	client := &http.Client{Timeout: 10 * time.Second}
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		req, _ := http.NewRequest("GET", "http://"+r.addr+"/v1/organizations/acme", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusNotFound {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("acme was not deleted after the restart: %s", r.stderr.String())
		}
	}
	r.signals <- syscall.SIGTERM
	if code := <-r.done; code != 0 {
		t.Fatalf("varlatchd exited %d: %s", code, r.stderr.String())
	}
}

// verifyDeletedOnce checks the database the runs left.
func verifyDeletedOnce(t *testing.T, in install, org string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	count := func(q string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}
	if events, last := count(`SELECT count(*) FROM audit_events`), count(`SELECT coalesce(max(event_order), 0) FROM audit_events`); events != last {
		t.Fatalf("%d audit events, the last at position %d: a gap", events, last)
	}
	removals := count(`SELECT count(*) FROM membership_removals WHERE organization_id = ?`, org)
	for _, c := range []struct {
		what      string
		got, want int64
	}{
		{"organization.deleted events", count(`SELECT count(*) FROM audit_events WHERE event_type = 'organization.deleted' AND organization_id = ?`, org), 1},
		{"finalization membership.removed events", count(`SELECT count(*) FROM audit_events WHERE event_type = 'membership.removed' AND organization_id = ? AND json_extract(metadata, '$.finalization')`, org), removals},
		{"live memberships", count(`SELECT count(*) FROM org_memberships WHERE organization_id = ? AND removed_at IS NULL`, org), 0},
		{"open or uncompleted requests", count(`SELECT count(*) FROM organization_deletions WHERE organization_id = ? AND completed_at IS NULL`, org), 0},
		{"a live Organization or a kept KEK", count(`SELECT count(*) FROM organizations WHERE id = ? AND (deleted_at IS NULL OR wrapped_org_kek IS NOT NULL)`, org), 0},
		{"live Projects", count(`SELECT count(*) FROM projects WHERE organization_id = ? AND deleted_at IS NULL`, org), 0},
		{"values with a version", count(`SELECT count(*) FROM env_values v JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
			WHERE p.organization_id = ? AND v.current_version_id IS NOT NULL`, org), 0},
		{"versions not erased", count(`SELECT count(*) FROM value_versions x JOIN env_values v ON v.id = x.value_id JOIN environments e ON e.id = v.environment_id
			JOIN projects p ON p.id = e.project_id WHERE p.organization_id = ? AND x.erased_at IS NULL`, org), 0},
		{"live machine credentials", count(`SELECT count(*) FROM credentials c JOIN identities i ON i.id = c.identity_id WHERE i.organization_id = ? AND c.revoked_at IS NULL`, org), 0},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", c.what, c.got, c.want)
		}
	}
	if removals == 0 {
		t.Error("no membership was ended")
	}
}

// deletedNow is whether acme's tombstone is in the database.
func deletedNow(t *testing.T, in install, org string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var deleted sql.NullInt64
	if err := db.QueryRow(`SELECT deleted_at FROM organizations WHERE id = ?`, org).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	return deleted.Valid
}

func TestKillDuringOrganizationDeletion(t *testing.T) {
	for _, c := range []struct {
		name, point string
		env         []string
		// committed: the killed run's deletion is in the database.
		committed bool
	}{
		{"before the job", orgdeletion.CrashBeforeJob, nil, false},
		{"inside the job", orgdeletion.CrashWritten, nil, false},
		{"inside its commit", "commit", []string{"VARLATCH_CRASHPOINT_ARM=" + filepath.Join(os.TempDir(), "never-"+ids.New(ids.Identity)), "VARLATCH_CRASHPOINT_ARM_ON=" + orgdeletion.CrashWritten}, false},
		{"after the commit", orgdeletion.CrashCommitted, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			in, org, token := deletionCrashInstall(t)
			killDuringDeletion(t, in, c.point, append([]string{"VARLATCH_CRASHPOINT_PAUSE=" + c.point}, c.env...)...)
			if got := deletedNow(t, in, org); got != c.committed {
				t.Fatalf("after the kill, acme deleted: %v, want %v", got, c.committed)
			}
			deletedAfterRestart(t, in, token)
			verifyDeletedOnce(t, in, org)
		})
	}
}
