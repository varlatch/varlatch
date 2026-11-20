// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
)

const schemaUsage = "Usage: varlatchd admin schema status|upgrade [--json] [--config <file>]"

// schemaArgs checks `admin schema ...`'s arguments (--config taken out).
func schemaArgs(rest []string) (cmd string, asJSON bool, msg string) {
	if len(rest) == 0 || rest[0] != "status" && rest[0] != "upgrade" {
		return "", false, schemaUsage
	}
	for _, a := range rest[1:] {
		if a != "--json" || asJSON {
			return "", false, schemaUsage
		}
		asJSON = true
	}
	return rest[0], asJSON, ""
}

// schemaJSON is a schema version as `admin schema` prints it.
type schemaJSON struct {
	SchemaVersion  int64 `json:"schemaVersion"`
	CompatibleFrom int64 `json:"compatibleFrom"`
}

// databaseJSON is the database's recorded schema.
type databaseJSON struct {
	SchemaVersion    int64  `json:"schemaVersion"`
	CompatibleFrom   int64  `json:"compatibleFrom"`
	CreatedByRelease string `json:"createdByRelease"`
	UpdatedByRelease string `json:"updatedByRelease"`
}

// runSchema is `varlatchd admin schema status|upgrade` (ADR-0059 Decision
// 8; internal docs/design/go-step6.md 6.6a). Neither goes through the
// control socket: status reads the database read-only, whether or not
// varlatchd runs; upgrade changes the schema, so it runs only offline,
// under the data directory's lock, and never during an unfinished restore.
// `varlatch upgrade` runs it on a copy of the database first.
//
//	status    this varlatchd's schema, the database's, and whether it opens
//	          it as it is (exit 0) or needs an upgrade (exit 0, said)
//	upgrade   db.Upgrade: every step to this varlatchd's schema in one
//	          write job; nothing to do for the same schema, or a newer one
//	          this varlatchd may open
func runSchema(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	cmd, asJSON, _ := schemaArgs(rest)
	what := "varlatchd admin schema " + cmd
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return status
	}
	binary := schemaJSON{db.SchemaVersion, db.CompatibleFrom}
	path := cfg.DatabasePath()
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if cmd == "upgrade" {
			return fail(ExitFailure, "there is no database at %s: nothing to upgrade (varlatchd creates it when it first starts)", path)
		}
		return printSchemaStatus(stdout, asJSON, binary, nil)
	}
	if cmd == "status" {
		d, err := readSchema(path)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		return printSchemaStatus(stdout, asJSON, binary, d)
	}

	owner, id, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail(ExitConfig, "%v; nothing was written", err)
	}
	if conn, err := net.DialTimeout("unix", filepath.Join(cfg.DataDir, ControlSocket), 5*time.Second); err == nil {
		_ = conn.Close()
		return fail(ExitFailure, "varlatchd is running on %s: stop it before an upgrade; nothing was written", cfg.DataDir)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail(ExitFailure, "a varlatchd holds the data directory %s: stop it before an upgrade; nothing was written", cfg.DataDir)
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
	if g, err := backup.ReadGate(cfg.DataDir); err != nil || g != nil && g.Kind == "restore" {
		return fail(ExitFailure, "a restore has not completed (%s): run varlatchd admin backup restore again first; nothing was written", filepath.Join(cfg.DataDir, backup.GateFile))
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		return fail(ExitFailure, "cannot open the database: %v", err)
	}
	up, err := db.Upgrade(ctx, store, buildinfo.Version)
	if cerr := store.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fail(ExitFailure, "%v; nothing was changed", err)
	}
	if asJSON {
		return printJSON(stdout, stderr, what, struct {
			Binary         schemaJSON `json:"binary"`
			From           int64      `json:"from"`
			To             int64      `json:"to"`
			CompatibleFrom int64      `json:"compatibleFrom"`
			Changed        bool       `json:"changed"`
		}{binary, up.From, up.To, up.CompatibleFrom, up.Changed})
	}
	switch {
	case up.Changed:
		fmt.Fprintf(stdout, "Upgraded the database's schema from version %d to %d (varlatchd of schema %d and later may open it).\n", up.From, up.To, up.CompatibleFrom)
	case up.From == db.SchemaVersion:
		fmt.Fprintf(stdout, "The database's schema is already version %d: nothing to do.\n", up.From)
	default:
		fmt.Fprintf(stdout, "The database's schema is version %d, newer than this varlatchd's %d, and this varlatchd may open it: nothing to do.\n", up.From, db.SchemaVersion)
	}
	return ExitOK
}

// readSchema reads the database's schema_version without changing
// anything: a read-only connection, beside a running varlatchd if there is
// one (WAL readers do not block its writer).
func readSchema(path string) (*databaseJSON, error) {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	conn, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var present int
	if err := conn.QueryRow("SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'").Scan(&present); err != nil {
		return nil, fmt.Errorf("cannot read the database: %v", err)
	}
	if present == 0 {
		return nil, db.ErrNotVarlatch
	}
	var d databaseJSON
	if err := conn.QueryRow("SELECT version, compatible_from, created_by_release, updated_by_release FROM schema_version WHERE singleton = 1").
		Scan(&d.SchemaVersion, &d.CompatibleFrom, &d.CreatedByRelease, &d.UpdatedByRelease); err != nil {
		return nil, fmt.Errorf("cannot read the schema version: %v", err)
	}
	return &d, nil
}

func printSchemaStatus(stdout io.Writer, asJSON bool, binary schemaJSON, d *databaseJSON) int {
	opens := d == nil || d.SchemaVersion == binary.SchemaVersion || d.SchemaVersion > binary.SchemaVersion && d.CompatibleFrom <= binary.SchemaVersion
	needsUpgrade := d != nil && d.SchemaVersion < binary.SchemaVersion
	if asJSON {
		return printJSON(stdout, io.Discard, "", struct {
			Binary       schemaJSON    `json:"binary"`
			Database     *databaseJSON `json:"database"`
			Opens        bool          `json:"opens"`
			NeedsUpgrade bool          `json:"needsUpgrade"`
		}{binary, d, opens, needsUpgrade})
	}
	fmt.Fprintf(stdout, "This varlatchd: schema version %d; a database it writes opens in varlatchd of schema %d and later.\n", binary.SchemaVersion, binary.CompatibleFrom)
	switch {
	case d == nil:
		fmt.Fprintln(stdout, "Database: none yet (varlatchd creates it when it first starts).")
	default:
		fmt.Fprintf(stdout, "Database: schema version %d, opens in varlatchd of schema %d and later; created by %s, last changed by %s.\n",
			d.SchemaVersion, d.CompatibleFrom, d.CreatedByRelease, d.UpdatedByRelease)
		switch {
		case needsUpgrade:
			fmt.Fprintln(stdout, "It needs an upgrade: run varlatch upgrade.")
		case opens:
			fmt.Fprintln(stdout, "This varlatchd opens it as it is.")
		default:
			fmt.Fprintf(stdout, "This varlatchd cannot open it: it needs varlatchd of schema %d or later.\n", d.CompatibleFrom)
		}
	}
	return ExitOK
}

func printJSON(stdout, stderr io.Writer, what string, v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", what, err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}
