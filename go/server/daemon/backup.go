// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
)

// The backup and maintenance host commands (ADR-0059 step 4.14), through
// the control socket like every host command (decision 11): in a running
// varlatchd they use its maintenance admission and its backup service, so
// a lease takes effect at once and a backup never runs beside a scheduled
// one; offline, under the data directory's lock, the command's own.
//
//	varlatchd admin backup run [--json]
//	varlatchd admin backup status
//	varlatchd admin backup test-bucket [--json]
//	varlatchd admin backup restore --in <archive> [--backup-key-file <file>]   (offline only)
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
	if len(args) >= 2 && args[0] == "backup" && args[1] == "test-bucket" {
		return time.Hour
	}
	if len(args) >= 2 && args[0] == "migrate" && args[1] == "barrier" {
		return barrierTimeout(args)
	}
	return controlTimeout
}

const (
	backupUsage      = "Usage: varlatchd admin backup run [--json [--verify-remote]] | varlatchd admin backup status | varlatchd admin backup restore --in <archive> [--backup-key-file <file>] | varlatchd admin backup test-bucket [--json]"
	maintenanceUsage = "Usage: varlatchd admin maintenance begin --ttl <duration> | varlatchd admin maintenance end <lease id> | varlatchd admin maintenance status"
)

// backupArgs checks `admin backup` and `admin maintenance`'s arguments
// (--config already taken out): "" when they are well formed, else the
// usage. ttl is maintenance begin's lease.
func backupArgs(sub string, rest []string) (ttl time.Duration, msg string) {
	if sub == "backup" {
		switch {
		case len(rest) == 1 && rest[0] == "run", len(rest) == 2 && rest[0] == "run" && rest[1] == "--json",
			len(rest) == 3 && rest[0] == "run" && rest[1] == "--json" && rest[2] == "--verify-remote", len(rest) == 1 && rest[0] == "status",
			len(rest) == 1 && rest[0] == "test-bucket", len(rest) == 2 && rest[0] == "test-bucket" && rest[1] == "--json":
			return 0, ""
		case len(rest) > 0 && rest[0] == "restore":
			if _, ok := restoreArgs(rest[1:]); ok {
				return 0, ""
			}
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
	if rest[0] == "test-bucket" {
		r, err := env.backups.TestBucket(ctx)
		if err != nil {
			return fail(err)
		}
		if len(rest) == 2 {
			printJSON(r)
		} else {
			mark := func(ok bool) string {
				if ok {
					return "ok"
				}
				return "FAILED"
			}
			fmt.Fprintf(stdout, "Bucket test with %s:\n", r.Key)
			fmt.Fprintf(stdout, "  delivery:       %s: %s\n", mark(r.Delivery.OK), r.Delivery.Detail)
			fmt.Fprintf(stdout, "  retention:      %s: %s\n", map[bool]string{true: "ok", false: "UNPROTECTED"}[r.Retention.Protected], r.Retention.Detail)
			fmt.Fprintf(stdout, "  recoverability: %s: %s\n", mark(r.Recoverability.OK), r.Recoverability.Detail)
		}
		if !r.Passed() {
			return ExitFailure
		}
		return ExitOK
	}
	if rest[0] == "status" {
		st, err := env.backups.Status()
		if err != nil {
			return fail(err)
		}
		return printJSON(st)
	}
	if len(rest) == 3 && !env.backups.HasDestination() {
		// Refused before an archive is made: only its remote copy counts.
		return fail(backups.ErrNoDestination)
	}
	res, err := env.backups.Run(ctx)
	if len(rest) == 3 && err == nil {
		// --verify-remote: the uploaded copy downloaded back and checked
		// (varlatch migrate --finish's final archive, which it trusts only
		// once its remote copy opens).
		v, verr := env.backups.VerifyRemote(ctx, res.ArchiveID)
		switch {
		case verr != nil:
			err = fmt.Errorf("the archive %s's remote copy could not be verified: %w", res.ArchiveID, verr)
		case res.Delivery != nil:
			res.Delivery.RemoteVerification = &v
		}
		if verr == nil && (!v.Integrity || !v.Compatibility || !v.KeyMatch) {
			err = fmt.Errorf("the archive %s's remote copy failed its check (integrity %t, compatibility %t, Root KEK match %t)", res.ArchiveID, v.Integrity, v.Compatibility, v.KeyMatch)
		}
	}
	if len(rest) >= 2 {
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
	o := backups.Options{Config: env.cfg, Store: env.store, RootKEK: env.rootKEK, Admission: env.admission, Log: env.log}
	if env.tune != nil {
		env.tune(&o)
	}
	return backups.New(o)
}

// restoreArgs reads `backup restore`'s flags: --in (required) and
// --backup-key-file.
func restoreArgs(rest []string) (map[string]string, bool) {
	v := map[string]string{}
	for i := 0; i < len(rest); i += 2 {
		if i+1 >= len(rest) || (rest[i] != "--in" && rest[i] != "--backup-key-file") || rest[i+1] == "" {
			return nil, false
		}
		v[rest[i]] = rest[i+1]
	}
	return v, v["--in"] != ""
}

// restoreOffline is `varlatchd admin backup restore`: never through the
// socket, since it replaces the database a running varlatchd holds. It
// takes the data directory's lock (a running varlatchd holds it, and is
// refused) and restores in this process, from the archive, the Backup
// Encryption Key (--backup-key-file, else backup_key_file) and the Root
// KEK (root_kek_file): the two keys held apart from the archive.
func restoreOffline(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	const what = "varlatchd admin backup restore"
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return status
	}
	args, _ := restoreArgs(rest)
	owner, id, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail(ExitConfig, "%v; nothing was written", err)
	}
	if conn, err := net.DialTimeout("unix", filepath.Join(cfg.DataDir, ControlSocket), 5*time.Second); err == nil {
		_ = conn.Close()
		return fail(ExitFailure, "varlatchd is running on %s: stop it before a restore; nothing was written", cfg.DataDir)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail(ExitFailure, "a varlatchd holds the data directory %s: stop it before a restore; nothing was written", cfg.DataDir)
	}
	if err != nil {
		return fail(ExitFailure, "cannot lock the data directory %s: %v", cfg.DataDir, err)
	}
	defer unlock()
	if owner >= 0 {
		if err := sameDir(cfg.DataDir, id); err != nil {
			return fail(ExitFailure, "%v; nothing was written", err)
		}
	}
	bekFile := args["--backup-key-file"]
	if bekFile == "" {
		bekFile = cfg.BackupKeyFile
	}
	if bekFile == "" {
		return fail(ExitConfig, "no Backup Encryption Key: give --backup-key-file, or set backup_key_file")
	}
	raw, err := os.ReadFile(bekFile)
	if err != nil {
		return fail(ExitFailure, "cannot read the Backup Encryption Key file: %v", err)
	}
	material, err := backup.ParseKey(string(raw))
	clear(raw)
	if err != nil {
		return fail(ExitConfig, "%v", err)
	}
	bek, err := backup.KeyBEK(material)
	clear(material)
	if err != nil {
		return fail(ExitConfig, "%v", err)
	}
	defer bek.Clear()
	raw, err = os.ReadFile(cfg.RootKEKFile)
	if err != nil {
		return fail(ExitFailure, "cannot read the Root KEK file: %v", err)
	}
	rootKEK, err := envelope.ParseRootKEK(string(raw))
	clear(raw)
	if err != nil {
		return fail(ExitConfig, "the Root KEK file does not hold a Root KEK: %v", err)
	}
	defer clear(rootKEK)
	res, err := backups.Restore(context.Background(), cfg, args["--in"], bek, rootKEK, nil)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	fmt.Fprintf(stdout, "Restore completed for %s from archive %s (created %s): the database is restored and its canary verified.\n", res.InstallationID, res.ArchiveID, res.CreatedAt)
	if len(res.Settings) > 0 {
		names := make([]string, 0, len(res.Settings))
		for k := range res.Settings {
			names = append(names, k)
		}
		slices.Sort(names)
		fmt.Fprintln(stdout, "The archive's settings, to compare with this host's varlatchd.conf:")
		for _, k := range names {
			fmt.Fprintf(stdout, "  %s = %s\n", k, res.Settings[k])
		}
	}
	fmt.Fprintln(stdout, "Next: start varlatchd, then take and check a fresh archive (`varlatchd admin backup run`).")
	return ExitOK
}
