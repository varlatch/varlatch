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

var (
	probeName    = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	deletionID   = regexp.MustCompile(`^odl_[a-z2-7]{26}$`)
	syncTargetID = regexp.MustCompile(`^snt_[a-z0-9]{26}$`)
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
