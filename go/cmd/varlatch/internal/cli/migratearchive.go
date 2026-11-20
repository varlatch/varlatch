// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch migrate --from-archive` (go-step7 decision 18, slice 7.7b): the
// backup converter, its own mode of `migrate`. It takes a TypeScript
// archive and writes a format 3 archive of the same installation
// (internal/migrate archive.go); it shares no option with the live
// migration's modes but the key files and --json.

const migrateArchiveUsage = `Usage:
  varlatch migrate --from-archive <archive> --kek-file <file> --bek-file <file> --out <archive>
                   [--ts-image <name@sha256:digest>] [--out-bek-file <file>] [--scratch-dir <dir>] [--json]
               (on a Linux or macOS host with Docker, one conversion at a time per host: the TypeScript
                archive is restored in an isolated PostgreSQL with no network, exported by the last
                TypeScript release's image, imported and checked by varlatchd, and sealed as a format 3
                archive at --out; --ts-image is required until this varlatch carries that release's digest;
                --out-bek-file when --bek-file holds a passphrase)`

// conversionSignals end a backup conversion with its cleanup (syscall
// names them on every platform; the mode itself runs on Linux and macOS).
var conversionSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

// fromArchive reports whether a command line is the converter's.
func fromArchive(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return a == "--from-archive" || strings.HasPrefix(a, "--from-archive=") })
}

type migrateArchiveOptions struct {
	archive, kekFile, bekFile, out, outBEKFile, tsImage, scratch string
	asJSON                                                       bool
}

// liveOnly are the live migration's options, refused in this mode.
var liveOnly = []string{"--from", "--config", "--backup-destination", "--read-credentials-file", "--destinations-file", "--ts-cli",
	"--max-downtime", "--drain", "--dry-run", "--resume", "--status"}

func parseMigrateArchiveOptions(args []string) (migrateArchiveOptions, error) {
	o := migrateArchiveOptions{}
	values := map[string]*string{"--from-archive": &o.archive, "--kek-file": &o.kekFile, "--bek-file": &o.bekFile, "--out": &o.out,
		"--out-bek-file": &o.outBEKFile, "--ts-image": &o.tsImage, "--scratch-dir": &o.scratch}
	usage := func(msg string) error {
		return UsageErrorWithUsage("varlatch migrate --from-archive: "+msg, "\n"+migrateArchiveUsage)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--json" {
			o.asJSON = true
			continue
		}
		name, val, inline := strings.Cut(a, "=")
		if slices.Contains(liveOnly, name) {
			return o, usage(name + " is the live migration's: --from-archive converts an archive and takes none of its options")
		}
		p, ok := values[name]
		if !ok {
			return o, usage("unknown option " + shownArgument(a))
		}
		if !inline {
			if i+1 >= len(args) {
				return o, usage(name + " needs a value")
			}
			val = args[i+1]
			i++
		}
		if val == "" {
			return o, usage(name + " needs a value")
		}
		if *p != "" {
			return o, usage(name + " is given twice")
		}
		*p = val
	}
	if o.archive == "" || o.kekFile == "" || o.bekFile == "" || o.out == "" {
		return o, usage("give --from-archive, --kek-file, --bek-file and --out")
	}
	return o, nil
}

func migrateArchiveCommand(r *Run) error {
	for _, a := range r.Args {
		if a == "--help" || a == "-h" {
			return r.println(migrateArchiveUsage)
		}
	}
	o, err := parseMigrateArchiveOptions(r.Args)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return Fail("varlatch migrate --from-archive: the converter runs on a Linux or macOS host with Docker", ExitFailure)
	}
	varlatchd, err := r.locateVarlatchd("varlatch migrate --from-archive")
	if err != nil {
		return err
	}
	// An interrupt (Ctrl-C, a terminal closed, a stop) ends the conversion
	// through its context, so its own cleanup runs: the containers holding
	// the restored Secret Plane removed, the decrypted scratch copy too. A
	// kill it cannot see is swept by the next conversion.
	ctx, stop := signal.NotifyContext(context.Background(), conversionSignals...)
	defer stop()
	allowLocal, _ := r.Env.LookupEnv("VARLATCH_ALLOW_LOCAL_TS_IMAGE")
	res, err := migrate.ConvertArchive(ctx, migrate.ArchiveOptions{
		Archive: o.archive, Out: o.out, KEKFile: o.kekFile, BEKFile: o.bekFile, OutBEKFile: o.outBEKFile,
		TSImage: o.tsImage, Varlatchd: varlatchd, Scratch: o.scratch, AllowLocalImage: allowLocal == "1",
		Run: migrate.ExecRunner{Env: environ(r)}, VarlatchdRun: migrate.ExecRunner{Env: varlatchdEnviron(r)},
		Say: func(s string) { _ = r.warn(s) },
	})
	cleanup := "cleaned up (its containers and scratch files removed)"
	if res.CleanupIncomplete {
		cleanup = "cleanup incomplete: the next conversion sweeps what is left"
	}
	if err != nil && ctx.Err() != nil {
		// What ended it is said too: a failure that came with the interrupt is not hidden behind it.
		return Fail("varlatch migrate --from-archive: interrupted ("+err.Error()+"): "+cleanup+"; nothing was written", ExitFailure)
	}
	if err != nil && res.CleanupIncomplete {
		return Fail("varlatch migrate --from-archive: "+err.Error()+"; "+cleanup, ExitFailure)
	}
	if res.CleanupIncomplete {
		_ = r.warn("varlatch migrate --from-archive: " + cleanup)
	}
	if err != nil {
		var refused *migrate.ErrArchive
		if errors.As(err, &refused) {
			return Fail("varlatch migrate --from-archive: "+err.Error()+"; nothing was written", ExitFailure)
		}
		return Fail("varlatch migrate --from-archive: "+err.Error(), ExitFailure)
	}
	if o.asJSON {
		b, err := json.Marshal(res)
		if err != nil {
			return err
		}
		doc, err := jsjson.Parse(b)
		if err != nil {
			return err
		}
		return r.printJSON(doc)
	}
	return r.out(fmt.Sprintf("Converted archive %s (format %d, release %s) of installation %s: %d tables, %d rows imported; every check passed.\nWrote %s: archive %s (format 3, %d bytes), sealed with %s.\n",
		res.Source.ArchiveID, res.Source.Format, res.Source.Release, res.Source.InstallationID, res.Copy.Tables, res.Copy.Rows,
		res.Output.Path, res.Output.ArchiveID, res.Output.Bytes, outKey(o)))
}

func outKey(o migrateArchiveOptions) string {
	if o.outBEKFile != "" {
		return o.outBEKFile
	}
	return o.bekFile
}
