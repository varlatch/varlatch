// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The conformance harness's probes (scripts/conformance README, "The
// target contract"): fixed, named reads of server state that /v1 does not
// show, which the go-binary target runs as `varlatchd admin
// conformance-probe <name> [args] --config <file>`, through the daemon
// (control.go) like every host command. Built only with the
// conformance build tag: a release has none of this.
//
//	expire-pending-device-sign-ins   every pending device sign-in expires now
//	device-sign-in-addresses <name>  [{"requesterIp": ...}] of the sign-ins requested under <name>
//	proxy-addresses                  [] (nothing stands in front of varlatchd)
//	deletion-due <odl_...>           the open deletion request made due now (as if scheduled
//	                                 40 days ago, due a second ago)
//	sync-repair-due <target id>      the Sync Target's last repair pass hours ago; answers
//	                                 {"needsSync", "nextAttemptAt"}, which it leaves as they are
//	sync-trigger-position            {"cursor", "latest"}: the converge engine's trigger scan's
//	                                 position, and the last audit event it reads (not sync.*)
//	sync-runs <snt_...>              read only: {"runs", "generations"}, the Sync Target's runs in
//	                                 progress (its sync_runs rows, by generation; a run deletes its
//	                                 own when it ends)
//	deletion-teardown <org_...>      read only: the Organization's Sync Targets, Platform
//	                                 Connections and webhooks, each {id, revoked}, and its
//	                                 GitHub Apps, each {id, removed, keyKept}, as stored
//	audit-export-drain-due <org_...>  a deleted Organization's draining audit export past its
//	                                 deadline (a second ago), so the deletion loop's next pass,
//	                                 within a minute, abandons it; true
//	github-app-pending-expired <ghr_...>  a pending GitHub App conversion's hour over (converted
//	                                 two hours ago, expired a second ago), so the registration
//	                                 sweep's next pass, within a minute, ends it; true

var (
	probeName    = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	deletionID   = regexp.MustCompile(`^odl_[a-z2-7]{26}$`)
	syncTargetID = regexp.MustCompile(`^snt_[a-z0-9]{26}$`)
	ghrID        = regexp.MustCompile(`^ghr_[a-z0-9]{26}$`)
	orgID        = regexp.MustCompile(`^org_[a-z0-9]{26}$`)
)

func init() {
	conformanceProbe = func(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
		fail := func(err error) int {
			fmt.Fprintf(stderr, "varlatchd admin conformance-probe: %v\n", err)
			return ExitFailure
		}
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "varlatchd admin conformance-probe: no probe")
			return 64
		}
		if rest[0] == "proxy-addresses" {
			fmt.Fprintln(stdout, "[]")
			return ExitOK
		}
		store := env.store
		var err error
		var out any
		switch rest[0] {
		case "sync-trigger-position":
			// Where the trigger scan stands: a change reaches the engine once
			// the scan's cursor passes its audit event.
			var pos struct {
				Cursor int64 `json:"cursor"`
				Latest int64 `json:"latest"`
			}
			err = store.Reader().QueryRowContext(ctx, `SELECT
				COALESCE((SELECT cursor_order FROM sync_cursor), 0),
				COALESCE((SELECT max(event_order) FROM audit_events WHERE substr(event_type, 1, 5) <> 'sync.'), 0)`).Scan(&pos.Cursor, &pos.Latest)
			out = pos
		case "sync-repair-due":
			// The sync suite's repair pass: the Target's last repair hours
			// ago, as six hours later, and nothing else changed, so that
			// only the periodic schedule can make it due. Answers what would
			// also have made it due, for the suite to see the Target was
			// settled.
			if len(rest) != 2 || !syncTargetID.MatchString(rest[1]) {
				return fail(fmt.Errorf("sync-repair-due: a Sync Target id"))
			}
			var settled struct {
				NeedsSync     bool   `json:"needsSync"`
				NextAttemptAt *int64 `json:"nextAttemptAt"`
			}
			err = store.Write(ctx, func(tx *storage.Tx) error {
				var next sql.NullInt64
				if err := tx.QueryRowContext(ctx, `UPDATE sync_targets SET last_repair_at = ? WHERE id = ? RETURNING needs_sync, next_attempt_at`,
					time.Now().Add(-7*time.Hour).UnixMicro(), rest[1]).Scan(&settled.NeedsSync, &next); err != nil {
					return err
				}
				if next.Valid {
					settled.NextAttemptAt = &next.Int64
				}
				return nil
			})
			out = settled
		case "sync-runs":
			if len(rest) != 2 || !syncTargetID.MatchString(rest[1]) {
				return fail(fmt.Errorf("sync-runs: a Sync Target id"))
			}
			generations := []int64{}
			var rows *sql.Rows
			if rows, err = store.Reader().QueryContext(ctx, `SELECT generation FROM sync_runs WHERE target_id = ? ORDER BY generation`, rest[1]); err == nil {
				for rows.Next() {
					var g int64
					if err = rows.Scan(&g); err != nil {
						break
					}
					generations = append(generations, g)
				}
				if err == nil {
					err = rows.Err()
				}
				rows.Close()
			}
			out = map[string]any{"runs": len(generations), "generations": generations}
		case "deletion-teardown":
			if len(rest) != 2 || !orgID.MatchString(rest[1]) {
				return fail(fmt.Errorf("deletion-teardown: an Organization id (org_...)"))
			}
			type row struct {
				ID      string `json:"id"`
				Revoked bool   `json:"revoked"`
			}
			type app struct {
				ID      string `json:"id"`
				Removed bool   `json:"removed"`
				KeyKept bool   `json:"keyKept"`
			}
			read := store.Reader()
			rows := func(sqlText string) ([]row, error) {
				r, err := read.QueryContext(ctx, sqlText, rest[1])
				if err != nil {
					return nil, err
				}
				defer r.Close()
				out := []row{}
				for r.Next() {
					var x row
					if err := r.Scan(&x.ID, &x.Revoked); err != nil {
						return nil, err
					}
					out = append(out, x)
				}
				return out, r.Err()
			}
			got := map[string]any{}
			for _, t := range []struct{ key, table string }{{"targets", "sync_targets"}, {"connections", "platform_connections"}, {"webhooks", "webhooks"}} {
				var rs []row
				if rs, err = rows(`SELECT id, revoked_at IS NOT NULL FROM ` + t.table + ` WHERE organization_id = ? ORDER BY id`); err != nil {
					break
				}
				got[t.key] = rs
			}
			if err == nil {
				var r *sql.Rows
				if r, err = read.QueryContext(ctx, `SELECT id, removed_at IS NOT NULL, key_envelope IS NOT NULL FROM github_apps WHERE organization_id = ? ORDER BY id`, rest[1]); err == nil {
					apps := []app{}
					for r.Next() {
						var a app
						if err = r.Scan(&a.ID, &a.Removed, &a.KeyKept); err != nil {
							break
						}
						apps = append(apps, a)
					}
					if err == nil {
						err = r.Err()
					}
					r.Close()
					got["githubApps"] = apps
				}
			}
			out = got
		case "audit-export-drain-due":
			if len(rest) != 2 || !orgID.MatchString(rest[1]) {
				return fail(fmt.Errorf("audit-export-drain-due: an Organization id (org_...)"))
			}
			err = store.Write(ctx, func(tx *storage.Tx) error {
				res, err := tx.ExecContext(ctx, `UPDATE audit_exports SET drain_deadline = ? WHERE organization_id = ? AND state = 'draining'`,
					time.Now().Add(-time.Second).UnixMicro(), rest[1])
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n == 0 {
					return fmt.Errorf("no draining audit export of %s", rest[1])
				}
				return nil
			})
			out = true
		case "github-app-pending-expired":
			// The pending conversion's material is written once, by a
			// trigger; the probe drops it for this one update and creates
			// it again from its own SQL, in the same transaction.
			if len(rest) != 2 || !ghrID.MatchString(rest[1]) {
				return fail(fmt.Errorf("github-app-pending-expired: a GitHub App registration id (ghr_...)"))
			}
			now := time.Now()
			err = store.Write(ctx, func(tx *storage.Tx) error {
				var trigger string
				if err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'github_app_registrations_pending_once'`).Scan(&trigger); err != nil {
					return fmt.Errorf("the pending_once trigger: %w", err)
				}
				if _, err := tx.ExecContext(ctx, `DROP TRIGGER github_app_registrations_pending_once`); err != nil {
					return err
				}
				res, err := tx.ExecContext(ctx, `UPDATE github_app_registrations SET converted_at = ?, pending_expires_at = ?
					WHERE id = ? AND converted_at IS NOT NULL AND ended_at IS NULL`,
					now.Add(-2*time.Hour).UnixMicro(), now.Add(-time.Second).UnixMicro(), rest[1])
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return fmt.Errorf("no pending GitHub App conversion %s", rest[1])
				}
				_, err = tx.ExecContext(ctx, trigger)
				return err
			})
			out = true
		case "expire-pending-device-sign-ins":
			err = store.Write(ctx, func(tx *storage.Tx) error {
				return query.New(tx).ExpirePendingDeviceSignIns(ctx, time.Now().Add(-time.Second).UnixMicro())
			})
			out = true
		case "deletion-due":
			if len(rest) != 2 || !deletionID.MatchString(rest[1]) {
				return fail(fmt.Errorf("deletion-due: a deletion request id (odl_...)"))
			}
			now := time.Now()
			err = store.Write(ctx, func(tx *storage.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE organization_deletions SET scheduled_at = scheduled_at - ?, run_after = ?
					WHERE id = ? AND cancelled_at IS NULL AND completed_at IS NULL`,
					(40 * 24 * time.Hour).Microseconds(), now.Add(-time.Second).UnixMicro(), rest[1])
				return err
			})
			out = true
		case "device-sign-in-addresses":
			if len(rest) != 2 || !probeName.MatchString(rest[1]) {
				return fail(fmt.Errorf("device-sign-in-addresses: name must be lower-case letters, digits and dashes"))
			}
			var ips []sql.NullString
			ips, err = query.New(store.Reader()).DeviceSignInRequesters(ctx, sql.NullString{String: rest[1], Valid: true})
			rows := []map[string]any{}
			for _, ip := range ips {
				var v any
				if ip.Valid {
					v = ip.String
				}
				rows = append(rows, map[string]any{"requesterIp": v})
			}
			out = rows
		default:
			fmt.Fprintf(stderr, "varlatchd admin conformance-probe: unknown probe %s\n", rest[0])
			return 64
		}
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
}
