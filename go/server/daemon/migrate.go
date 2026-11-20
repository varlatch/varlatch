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
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
)

// The migration's host commands (internal docs/design/go-step7.md decision
// 2, slice 7.3a), offline only, under the data directory's lock, with no
// varlatchd running:
//
//	varlatchd admin migrate import --in <bundle> [--json]
//	varlatchd admin migrate export --reverse --out <bundle> [--json]
//
// import builds a fresh database in the configured data directory, which
// must be empty, from the TypeScript server's export (a forward bundle,
// server/migration/bundle/BUNDLE.md), checked against the Root KEK. export
// --reverse writes the reverse bundle for the TypeScript release's own
// import, from a copy of the database; out is a new file, mode 0600. Both
// print what they did; --json as one object. Neither prints a value of
// the bundle.

const migrateUsage = "Usage: varlatchd admin migrate import --in <bundle> [--json] | varlatchd admin migrate export --reverse --out <bundle> [--json]"

type migrateArgs struct {
	sub, in, out string
	asJSON       bool
}

func parseMigrate(rest []string) (migrateArgs, string) {
	var a migrateArgs
	if len(rest) == 0 || (rest[0] != "import" && rest[0] != "export") {
		return a, migrateUsage
	}
	a.sub = rest[0]
	reverse := false
	for i := 1; i < len(rest); i++ {
		switch f := rest[i]; f {
		case "--json":
			a.asJSON = true
		case "--reverse":
			reverse = true
		case "--in", "--out":
			if i+1 >= len(rest) || rest[i+1] == "" {
				return a, migrateUsage
			}
			if f == "--in" {
				a.in = rest[i+1]
			} else {
				a.out = rest[i+1]
			}
			i++
		default:
			return a, migrateUsage
		}
	}
	switch {
	case a.sub == "import" && (a.in == "" || a.out != "" || reverse):
		return a, migrateUsage
	case a.sub == "export" && (a.out == "" || a.in != "" || !reverse):
		return a, migrateUsage
	}
	return a, ""
}

// runMigrate is `admin migrate`, in this process, the data directory held.
func runMigrate(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	a, _ := parseMigrate(rest)
	what := "varlatchd admin migrate " + a.sub
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return status
	}
	if a.sub == "import" {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			return fail(ExitFailure, "%v", err)
		}
	}
	owner, id, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail(ExitConfig, "%v; nothing was written", err)
	}
	if conn, err := net.DialTimeout("unix", filepath.Join(cfg.DataDir, ControlSocket), 5*time.Second); err == nil {
		_ = conn.Close()
		return fail(ExitFailure, "varlatchd is running on %s: stop it first; nothing was written", cfg.DataDir)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail(ExitFailure, "a varlatchd holds the data directory %s: stop it first; nothing was written", cfg.DataDir)
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
	o := migrate.Options{DataDir: cfg.DataDir, Ignore: []string{LockFile}, Release: buildinfo.Version}
	var res migrate.Result
	if a.sub == "import" {
		raw, err := os.ReadFile(cfg.RootKEKFile)
		if err != nil {
			return fail(ExitFailure, "cannot read the Root KEK file: %v", err)
		}
		o.RootKEK, err = envelope.ParseRootKEK(string(raw))
		clear(raw)
		if err != nil {
			return fail(ExitConfig, "the Root KEK file does not hold a Root KEK: %v", err)
		}
		defer clear(o.RootKEK)
		in, err := os.Open(a.in)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		defer in.Close()
		if res, err = migrate.Import(context.Background(), in, o); err != nil {
			return fail(ExitFailure, "%v; nothing was kept", err)
		}
	} else {
		out, err := os.OpenFile(a.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail(ExitFailure, "%v (the reverse bundle is a new file)", err)
		}
		res, err = migrate.ExportReverse(context.Background(), out, o)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = syncFile(a.out)
		}
		if err == nil {
			// The bundle's name in its directory, durable too.
			err = syncFile(filepath.Dir(a.out))
		}
		if err != nil {
			_ = os.Remove(a.out)
			return fail(ExitFailure, "%v; nothing was written", err)
		}
	}
	if a.asJSON {
		b, err := json.Marshal(res)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	if a.sub == "import" {
		fmt.Fprintf(stdout, "Imported the installation %s: %d tables, %d rows; %d browser sessions ended, %d browser credentials revoked; installation.migrated at position %d.\n",
			res.InstallationID, res.Tables, res.Rows, res.SessionsEnded, res.CredentialsRevoked, res.MigratedPosition)
	} else {
		fmt.Fprintf(stdout, "Wrote the reverse bundle of %s to %s: %d tables, %d rows; %d browser sessions ended in it, installation.migrated at position %d. The database is unchanged.\n",
			res.InstallationID, a.out, res.Tables, res.Rows, res.SessionsEnded, res.MigratedPosition)
	}
	return ExitOK
}

// syncFile makes a written file durable.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
