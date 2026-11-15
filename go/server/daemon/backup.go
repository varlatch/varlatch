// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/varlatch/varlatch/go/server/backups"
)

// The backup and maintenance host commands (ADR-0059 step 4.14), through
// the control socket like every host command (decision 11): in a running
// varlatchd they use its maintenance admission and its backup service, so
// a lease takes effect at once and a backup never runs beside a scheduled
// one; offline, under the data directory's lock, the command's own.
//
//	varlatchd admin backup run [--json]
//	varlatchd admin backup status
//	varlatchd admin maintenance begin --ttl <duration>
//	varlatchd admin maintenance end <lease id>
//	varlatchd admin maintenance status
//
// backup status and maintenance begin and status print JSON: the status
// getInstallationBackups answers, and the gate (maintenance.json's form,
// null when none is open).

// backupRunTimeout bounds `admin backup run` on the socket: the paced
// snapshot and sealing of a large database, its check and its upload.
const backupRunTimeout = 12 * time.Hour

// commandTimeout is how long the socket waits for a command.
func commandTimeout(args []string) time.Duration {
	if len(args) >= 2 && args[0] == "backup" && args[1] == "run" {
		return backupRunTimeout
	}
	return controlTimeout
}

const (
	backupUsage      = "Usage: varlatchd admin backup run [--json] | varlatchd admin backup status"
	maintenanceUsage = "Usage: varlatchd admin maintenance begin --ttl <duration> | varlatchd admin maintenance end <lease id> | varlatchd admin maintenance status"
)

// backupArgs checks `admin backup` and `admin maintenance`'s arguments
// (--config already taken out): "" when they are well formed, else the
// usage. ttl is maintenance begin's lease.
func backupArgs(sub string, rest []string) (ttl time.Duration, msg string) {
	if sub == "backup" {
		switch {
		case len(rest) == 1 && rest[0] == "run", len(rest) == 2 && rest[0] == "run" && rest[1] == "--json", len(rest) == 1 && rest[0] == "status":
			return 0, ""
		}
		return 0, backupUsage
	}
	switch {
	case len(rest) == 3 && rest[0] == "begin" && rest[1] == "--ttl":
		d, err := time.ParseDuration(rest[2])
		if err != nil {
			return 0, maintenanceUsage + " (a duration such as 30s or 10m)"
		}
		return d, ""
	case len(rest) == 2 && rest[0] == "end" && rest[1] != "", len(rest) == 1 && rest[0] == "status":
		return 0, ""
	}
	return 0, maintenanceUsage
}

func runBackupCommand(ctx context.Context, env *hostEnv, sub string, rest []string, stdout, stderr io.Writer) int {
	ttl, msg := backupArgs(sub, rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "varlatchd admin %s %s: %s\n", sub, rest[0], err.Error())
		return ExitFailure
	}
	printJSON := func(v any) int {
		b, err := json.Marshal(v)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	if sub == "maintenance" {
		switch rest[0] {
		case "begin":
			g, err := env.admission.Begin(ttl)
			if err != nil {
				return fail(err)
			}
			return printJSON(g)
		case "end":
			if err := env.admission.End(rest[1]); err != nil {
				return fail(err)
			}
			fmt.Fprintln(stdout, "Maintenance ended.")
			return ExitOK
		default:
			g, err := env.admission.Gate()
			if err != nil {
				return fail(err)
			}
			return printJSON(g)
		}
	}
	if rest[0] == "status" {
		st, err := env.backups.Status()
		if err != nil {
			return fail(err)
		}
		return printJSON(st)
	}
	res, err := env.backups.Run(ctx)
	if len(rest) == 2 {
		if res.ArchiveID != "" {
			printJSON(res)
		}
		if err != nil {
			return fail(err)
		}
		return ExitOK
	}
	if res.ArchiveID != "" {
		v := res.Verification
		fmt.Fprintf(stdout, "Archive created: %s (%s)\n", res.Path, res.ArchiveID)
		fmt.Fprintf(stdout, "Snapshot %.1f s, sealing %.1f s, %.1f MiB; checks: integrity %t, compatibility %t, Root KEK match %t.\n",
			float64(res.Capture.SnapshotHeldMs)/1000, float64(res.Capture.DumpMs)/1000, float64(res.Capture.DumpBytes)/(1<<20), v.Integrity, v.Compatibility, v.KeyMatch)
		if res.Delivery != nil {
			fmt.Fprintf(stdout, "Upload completed to %s; remote retrieval has not been verified.\n", res.Delivery.Destination)
		}
		if len(res.Removed) > 0 {
			fmt.Fprintf(stdout, "Removed %d archive(s) beyond backup_keep from this host.\n", len(res.Removed))
		}
	}
	if err != nil {
		return fail(err)
	}
	return ExitOK
}

// newBackups is the backup service of a host environment.
func newBackups(env *hostEnv) *backups.Service {
	return backups.New(backups.Options{Config: env.cfg, Store: env.store, RootKEK: env.rootKEK, Admission: env.admission, Log: env.log})
}
