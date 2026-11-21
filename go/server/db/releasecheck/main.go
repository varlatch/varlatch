// SPDX-License-Identifier: AGPL-3.0-or-later

// Command releasecheck checks a Go release's rollback-safety declaration
// (go/release/release.json) and writes its manifest (ADR-0059 Decision 8,
// G6; internal docs/design/go-step6.md decision 5). It is run from go/ by
// G6's CI job and the release; it is not shipped.
//
//	releasecheck declaration [--declaration <file>]
//	    the declaration's rules hold, and it matches this build's schema
//	    (db.SchemaVersion, db.CompatibleFrom)
//	releasecheck manifest --version <version> [--declaration <file>]
//	    the same checks, then the release's release.json on standard output
//	releasecheck schema --previous <schema.sql> [--current <schema.sql>] [--declaration <file>] [--json]
//	    the changes from the previous release's schema to this one's (or to
//	    --current), held against the declaration (schemadiff.Judge)
//
// The declaration defaults to release/release.json. Exit 0 when the checks
// pass, 1 when they fail, 64 on a usage error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/schemadiff"
)

const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 64
	declDefault = "release/release.json"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "releasecheck: %s\nUsage: releasecheck declaration|manifest|schema [flags] (see the package comment)\n", msg)
		return exitUsage
	}
	if len(args) == 0 {
		return usage("no command")
	}
	fs := flag.NewFlagSet("releasecheck "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	declPath := fs.String("declaration", declDefault, "")
	version := fs.String("version", "", "")
	previous := fs.String("previous", "", "")
	current := fs.String("current", "", "")
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err.Error())
	}
	if fs.NArg() > 0 {
		return usage("unexpected argument " + fs.Arg(0))
	}
	// Usage first: nothing is read for a command that cannot run.
	switch args[0] {
	case "declaration":
		if *version != "" || *previous != "" || *current != "" || *asJSON {
			return usage("declaration takes only --declaration")
		}
	case "manifest":
		if *version == "" {
			return usage("manifest needs --version")
		}
		if *previous != "" || *current != "" || *asJSON {
			return usage("manifest takes only --version and --declaration")
		}
	case "schema":
		if *previous == "" {
			return usage("schema needs --previous")
		}
		if *version != "" {
			return usage("schema does not take --version")
		}
	default:
		return usage("unknown command " + args[0])
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "releasecheck %s: "+format+"\n", append([]any{args[0]}, a...)...)
		return exitFailed
	}
	raw, err := os.ReadFile(*declPath)
	if err != nil {
		return fail("%v", err)
	}
	decl, err := release.ParseDeclaration(raw)
	if err != nil {
		return fail("%s: %v", *declPath, err)
	}
	matches := func() error {
		if decl.SchemaVersion != db.SchemaVersion || decl.CompatibleFrom != db.CompatibleFrom {
			return fmt.Errorf("%s declares schemaVersion %d and compatibleFrom %d; this varlatchd's schema is %d, compatible from %d",
				*declPath, decl.SchemaVersion, decl.CompatibleFrom, db.SchemaVersion, db.CompatibleFrom)
		}
		return nil
	}

	switch args[0] {
	case "declaration":
		if err := matches(); err != nil {
			return fail("%v", err)
		}
		fmt.Fprintf(stdout, "%s holds: schema %d, compatible from %d, rollback-safe %v, previous %s, %s\n",
			*declPath, decl.SchemaVersion, decl.CompatibleFrom, decl.RollbackSafe, previousName(decl), windowName(decl))
		return exitOK

	case "manifest":
		if err := matches(); err != nil {
			return fail("%v", err)
		}
		m, err := release.NewManifest(*version, decl)
		if err != nil {
			return fail("%v", err)
		}
		b, err := m.Bytes()
		if err != nil {
			return fail("%v", err)
		}
		_, _ = stdout.Write(b)
		return exitOK

	case "schema":
		older, err := os.ReadFile(*previous)
		if err != nil {
			return fail("%v", err)
		}
		newer := db.Schema()
		if *current != "" {
			b, err := os.ReadFile(*current)
			if err != nil {
				return fail("%v", err)
			}
			newer = string(b)
		} else if err := matches(); err != nil {
			return fail("%v", err)
		}
		changes, err := schemadiff.Diff(context.Background(), string(older), newer)
		if err != nil {
			return fail("%v", err)
		}
		problems, notes := schemadiff.Judge(changes, decl)
		if *asJSON {
			doc := struct {
				Previous string              `json:"previous"`
				Changes  []schemadiff.Change `json:"changes"`
				Problems []string            `json:"problems"`
				Notes    []string            `json:"notes"`
			}{previousName(decl), nonNil(changes), nonNil(problems), nonNil(notes)}
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(doc); err != nil {
				return fail("%v", err)
			}
		} else {
			fmt.Fprintf(stdout, "against %s: %d schema changes, rollback-safe %v\n", previousName(decl), len(changes), decl.RollbackSafe)
			for _, n := range notes {
				fmt.Fprintln(stdout, "  note: "+n)
			}
			for _, p := range problems {
				fmt.Fprintln(stdout, "  PROBLEM: "+p)
			}
		}
		if len(problems) > 0 {
			return fail("%d problems: the declaration does not hold", len(problems))
		}
		return exitOK
	}
	return exitUsage // not reached: the switch above took every command
}

// windowName is what the declaration says of a migration's rollback window
// (go-step7.md decision 17).
func windowName(d release.Declaration) string {
	if d.EndsRollbackWindow {
		return "ends the rollback window"
	}
	return "reversible to " + *d.ReversibleTo
}

func previousName(d release.Declaration) string {
	if d.Previous == nil {
		return "no previous release"
	}
	return fmt.Sprintf("%s (schema %d)", d.Previous.Version, d.Previous.SchemaVersion)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
