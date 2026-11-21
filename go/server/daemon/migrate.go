// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.org/x/term"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
)

// The migration's host commands (internal docs/design/go-step7.md decision
// 2, slices 7.3a, 7.3b and 7.6a), offline, under the data directory's lock,
// with no varlatchd running:
//
//	varlatchd admin migrate import --in <bundle> [--scratch <dir>] [--json]
//	varlatchd admin migrate check --in <bundle> [--scratch <dir>] [--reverse] [--json]  (the run key on stdin)
//	varlatchd admin migrate export --reverse --out <bundle> [--keep <dir>] [--json]
//	varlatchd admin migrate keys  (the keys on stdin; slice 7.4a)
//	varlatchd admin migrate state [--write]  (the journal on stdin with --write)
//	varlatchd admin migrate discard --id <migration>
//
// keys, state and discard are `varlatch migrate`'s (migratestate.go):
// the target's key files, the migration journal in the data directory, and
// the database an undone migration leaves. --scratch builds (import) or
// reads (check) a database in that directory instead of the data
// directory: the dry run's, which never touches the target's, or the
// reverse checks' kept copy. Those two take no lock and run beside a
// varlatchd too. So does the reverse export behind a migration barrier
// (migratebarrier.go: barrier, release, open go through the running
// varlatchd's control socket): it reads the barrier's frozen copy, a file
// nothing writes, never the database varlatchd holds.
//
// --keep keeps the reverse export's transformed copy, as varlatch.db in a
// new or empty directory, for the reverse checks: check --reverse holds
// that copy (--scratch) against the TypeScript release's export of the
// database it rebuilt from the reverse bundle (CHECKS.md, "The reverse
// checks").
//
// import builds a fresh database in the configured data directory, which
// must be empty, from the TypeScript server's export (a forward bundle,
// server/migration/bundle/BUNDLE.md), checked against the Root KEK. export
// --reverse writes the reverse bundle for the TypeScript release's own
// import, from a copy of the database; out is a new file, mode 0600. Both
// print what they did; --json as one object. Neither prints a value of
// the bundle.
//
// check holds the imported database against the bundle it was imported
// from (server/migration/check/CHECKS.md): every check runs, and the report
// names each fault's check, table or class. The run key, 64 hex digits on
// one line, comes on standard input (from `varlatch migrate`, on a pipe:
// never a file, an argument or the environment); the Root KEK from its
// file. Neither is printed, nor any value of the database. Exit 0 when
// every check passes, 1 when one fails.

const migrateUsage = "Usage: varlatchd admin migrate import --in <bundle> [--scratch <dir>] [--json] | " +
	"varlatchd admin migrate check --in <bundle> [--scratch <dir>] [--reverse] [--json] (the run key on stdin) | " +
	"varlatchd admin migrate export --reverse --out <bundle> [--keep <dir>] [--json] | varlatchd admin migrate keys (the keys on stdin) | " +
	"varlatchd admin migrate state [--write] (the journal on stdin) | varlatchd admin migrate discard --id <migration> | " +
	"varlatchd admin migrate open --id <migration> | varlatchd admin migrate barrier --id <migration> [--drain-seconds <n>] | " +
	"varlatchd admin migrate release --id <migration>"

type migrateArgs struct {
	sub, in, out, scratch, id, keep string
	asJSON, write, reverse          bool
	// drain is the barrier's wait for what it admitted (0: the default).
	drain time.Duration
}

// The barrier's drain: 60 seconds by default, at most an hour.
const (
	defaultDrain = 60 * time.Second
	maxDrain     = time.Hour
)

func parseMigrate(rest []string) (migrateArgs, string) {
	var a migrateArgs
	if len(rest) == 0 || !slices.Contains([]string{"import", "export", "check", "keys", "state", "discard", "open", "barrier", "release"}, rest[0]) {
		return a, migrateUsage
	}
	a.sub = rest[0]
	for i := 1; i < len(rest); i++ {
		switch f := rest[i]; f {
		case "--json":
			a.asJSON = true
		case "--reverse":
			a.reverse = true
		case "--write":
			a.write = true
		case "--in", "--out", "--scratch", "--id", "--keep", "--drain-seconds":
			if i+1 >= len(rest) || rest[i+1] == "" {
				return a, migrateUsage
			}
			switch v := rest[i+1]; f {
			case "--in":
				a.in = v
			case "--out":
				a.out = v
			case "--scratch":
				a.scratch = v
			case "--keep":
				a.keep = v
			case "--drain-seconds":
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || time.Duration(n)*time.Second > maxDrain {
					return a, migrateUsage
				}
				a.drain = time.Duration(n) * time.Second
			default:
				a.id = v
			}
			i++
		default:
			return a, migrateUsage
		}
	}
	other := a.in != "" || a.out != "" || a.scratch != "" || a.id != "" || a.keep != "" || a.reverse || a.write || a.drain != 0
	switch {
	case a.sub == "import" && (a.in == "" || a.out != "" || a.id != "" || a.keep != "" || a.reverse || a.write || a.drain != 0):
		return a, migrateUsage
	case a.sub == "check" && (a.in == "" || a.out != "" || a.id != "" || a.keep != "" || a.write || a.drain != 0 || a.reverse && a.scratch == ""):
		// The reverse checks read the transformed copy an export kept.
		return a, migrateUsage
	case a.sub == "export" && (a.out == "" || a.in != "" || a.scratch != "" || a.id != "" || a.write || !a.reverse || a.drain != 0):
		return a, migrateUsage
	case a.sub == "keys" && other:
		return a, migrateUsage
	case a.sub == "state" && (a.in != "" || a.out != "" || a.scratch != "" || a.id != "" || a.keep != "" || a.reverse || a.drain != 0):
		return a, migrateUsage
	case (a.sub == "discard" || a.sub == "open" || a.sub == "release") && (a.id == "" || a.in != "" || a.out != "" || a.scratch != "" || a.keep != "" || a.reverse || a.write || a.asJSON || a.drain != 0):
		return a, migrateUsage
	case a.sub == "barrier" && (a.id == "" || a.in != "" || a.out != "" || a.scratch != "" || a.keep != "" || a.reverse || a.write || a.asJSON):
		return a, migrateUsage
	case a.scratch != "" && !filepath.IsAbs(a.scratch), a.keep != "" && !filepath.IsAbs(a.keep):
		return a, migrateUsage
	}
	return a, ""
}

// runMigrate is `admin migrate`, in this process, the data directory held.
func runMigrate(cfg *config.Config, rest []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a, _ := parseMigrate(rest)
	what := "varlatchd admin migrate " + a.sub
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return status
	}
	// Reading the state writes nothing, not even the data directory (a
	// target not set up yet has none): it answers beside a running
	// varlatchd too, and says whether one runs.
	var journalIn []byte
	if a.sub == "state" && a.write {
		b, err := readLimited(stdin, 1<<20, "the journal")
		if err != nil {
			return fail(64, "%v", err)
		}
		journalIn = b
	}
	// Beside the varlatchd that serves under the transfer's gate (which
	// reads its journal only at start), a journal is written when the
	// write is the journal's word alone: the switch (the gate and the
	// database stay as they are), or the same migration's journal in the
	// phase it is in already (what it records of that phase: the
	// transfer's check, an undo begun). Open and released change the
	// gate, and a journal never goes back: those wait for it to stop,
	// but for open over open once no transfer gate stands, which changes
	// nothing but the journal (an upgrade's record that it ends the
	// rollback window).
	//
	// Beside the varlatchd a reverse migration reverses (go-step7 decision
	// 16), every write of its journal is the journal's word alone: from
	// open into the reverse's phases, on through them, or back to open
	// (the reverse undone). Its barrier is its own commands' (barrier,
	// release), never a state write's. Rolled back waits for varlatchd to
	// stop: from then it does not start. Finished (the rollback window
	// ended, from open) is the journal's word alone too.
	inert := false
	if journalIn != nil {
		if h, err := parseJournal(journalIn); err == nil && h.Phase != "released" {
			old, ok, oerr := readJournal(cfg.DataDir)
			same := oerr == nil && ok && old.ID == h.ID
			inert = h.Phase != "open" && (h.Phase == "switched" || same && old.Phase == h.Phase || same && old.Phase == "open" && h.Phase == "finished")
			if same && (old.Phase == "open" || slices.Contains(reversing, old.Phase)) && (h.Phase == "open" || slices.Contains(reversing, h.Phase)) {
				// Open over open changes the gate only by removing a
				// transfer gate that still stands; with none, it is the
				// journal's word alone (what it records of that phase:
				// an upgrade ending the rollback window, decision 17).
				inert = !(old.Phase == "open" && h.Phase == "open") || !transferGateStands(cfg.DataDir, h.ID)
			}
		}
	}
	if a.sub == "state" && (!a.write || inert) {
		if _, err := os.Stat(cfg.DataDir); err == nil {
			if _, _, err := checkClientDir(cfg.DataDir, os.Getuid()); err != nil {
				return fail(ExitConfig, "%v", err)
			}
		}
		return runMigrateState(cfg, a, journalIn, stdout, fail)
	}
	// Beside a varlatchd, and without the data directory: an import into a
	// scratch directory, and a check of one, use that directory only (the
	// dry run's database, the reverse checks' transformed copy); behind a
	// migration
	// barrier that froze the installation (paused), the reverse export
	// reads the barrier's frozen copy, a file nothing writes, never the
	// database varlatchd holds.
	var frozen *frozenCopy
	if a.sub == "export" {
		if _, _, err := checkClientDir(cfg.DataDir, os.Getuid()); err != nil {
			return fail(ExitConfig, "%v; nothing was written", err)
		}
		f, err := barrierCopy(cfg.DataDir)
		if err != nil {
			return fail(ExitFailure, "%v; nothing was written", err)
		}
		frozen = f
	}
	if frozen != nil || (a.sub == "check" || a.sub == "import") && a.scratch != "" {
		return migrateWork(cfg, a, frozen, stdin, stdout, fail)
	}
	if a.sub == "import" || a.sub == "keys" || a.sub == "state" {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			return fail(ExitFailure, "%v", err)
		}
	}
	owner, id, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail(ExitConfig, "%v; nothing was written", err)
	}
	if controlAnswers(cfg.DataDir, 5*time.Second) {
		if a.sub == "export" {
			return fail(ExitFailure, "varlatchd is running on %s: the reverse export reads the frozen copy its migration barrier makes (varlatchd admin migrate barrier), or a stopped varlatchd's database; nothing was written", cfg.DataDir)
		}
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
	if a.sub == "export" {
		// A barrier may have frozen the installation since the first look.
		if f, err := barrierCopy(cfg.DataDir); err != nil || f != nil {
			return fail(ExitFailure, "the data directory's gate changed while the export began (%v); run it again; nothing was written", err)
		}
	}
	switch a.sub {
	case "keys":
		return runMigrateKeys(cfg, stdin, stdout, fail)
	case "state":
		return runMigrateState(cfg, a, journalIn, stdout, fail)
	case "discard":
		return runMigrateDiscard(cfg, a, stdout, fail)
	}
	return migrateWork(cfg, a, nil, stdin, stdout, fail)
}

// migrateWork is import, check and export, once runMigrate has the data
// directory (or needs none: a scratch check, an export of a barrier's
// frozen copy).
func migrateWork(cfg *config.Config, a migrateArgs, frozen *frozenCopy, stdin io.Reader, stdout io.Writer, fail func(int, string, ...any) int) int {
	// The journal (`varlatch migrate`'s) is the one other name an import
	// leaves in the data directory.
	o := migrate.Options{DataDir: cfg.DataDir, Ignore: []string{LockFile, JournalFile}, Release: buildinfo.Version, Keep: a.keep}
	if frozen != nil {
		o.From, o.FrozenAt = frozen.path, frozen.position
		// The copy is made beside the bundle, never in the data
		// directory of the varlatchd that runs.
		abs, err := filepath.Abs(a.out)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		o.Work = filepath.Dir(abs)
	}
	if a.scratch != "" {
		if a.sub == "import" {
			if err := os.MkdirAll(a.scratch, 0o700); err != nil {
				return fail(ExitFailure, "%v", err)
			}
		}
		o.DataDir, o.Ignore = a.scratch, nil
	}
	if a.sub == "import" || a.sub == "check" {
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
	}
	if a.sub == "check" {
		return runCheck(cfg, a, o.DataDir, o.RootKEK, stdin, stdout, fail)
	}
	var res migrate.Result
	if a.sub == "import" {
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
		if a.keep != "" {
			fmt.Fprintf(stdout, "The transformed copy is kept in %s, for the reverse checks.\n", a.keep)
		}
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

// runCheck is `admin migrate check`: the run key read from stdin, the
// database opened read-only, the checks run, the report printed.
func runCheck(cfg *config.Config, a migrateArgs, dataDir string, rootKEK []byte, stdin io.Reader, stdout io.Writer, fail func(int, string, ...any) int) int {
	runKey, err := readRunKey(stdin)
	if err != nil {
		return fail(64, "%v", err)
	}
	defer clear(runKey)
	at := *cfg
	at.DataDir = dataDir
	db, err := openReadOnly(&at)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	if db == nil {
		return fail(ExitFailure, "the data directory %s holds no database: import first", dataDir)
	}
	defer db.Close()
	in, err := os.Open(a.in)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	defer in.Close()
	rep, err := check.Run(context.Background(), db, in, check.Options{RootKEK: rootKEK, RunKey: runKey, Reverse: a.reverse})
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	if a.asJSON {
		b, err := json.Marshal(rep)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprint(stdout, rep.Text())
	}
	if !rep.Passed {
		return ExitFailure
	}
	return ExitOK
}

// readRunKey reads the run key: one line of 64 lowercase hex digits, and
// nothing after it, from a pipe (or a file), never a terminal, where it
// would be typed and seen. The line is cleared once decoded; an error never
// quotes it.
func readRunKey(stdin io.Reader) ([]byte, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return nil, errors.New("the run key comes on a pipe; standard input is a terminal")
	}
	buf := make([]byte, 66)
	defer clear(buf)
	n, err := io.ReadFull(stdin, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("cannot read the run key from standard input: %v", err)
	}
	line := buf[:n]
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	key := make([]byte, 32)
	if len(line) != 64 || n == len(buf) {
		return nil, errors.New("standard input does not hold the run key: one line of 64 lowercase hex digits")
	}
	for _, c := range line {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, errors.New("standard input does not hold the run key: one line of 64 lowercase hex digits")
		}
	}
	if _, err := hex.Decode(key, line); err != nil {
		return nil, errors.New("standard input does not hold the run key: one line of 64 lowercase hex digits")
	}
	return key, nil
}
