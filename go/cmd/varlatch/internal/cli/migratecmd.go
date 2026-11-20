// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch migrate` (ADR-0059 Decision 9; internal docs/design/
// go-step7.md slice 7.4a): from the last TypeScript release's Compose
// installation to a host install of varlatchd, the phases journalled in
// both (internal/migrate). A Go-only host command: the TypeScript CLI has
// none, so it is outside the parity table (goOnlyCommands).

const migrateUsage = `Usage:
  varlatch migrate --ingress public|proxy|coolify --config <varlatchd.conf> --bek-file <file>
                   --backup-destination <name> --read-credentials-file <file> [--from <compose directory>]
                   [--dry-run] [--max-downtime <duration>] [--drain <duration>] [--transfer-timeout <duration>]
                   [--unit <systemd unit>] [--kek-file <file>] [--destinations-file <file>] [--ts-cli <program>] [--json]
  varlatch migrate --resume (the same options)
  varlatch migrate --abort (the same options): undo a migration not yet switched
  varlatch migrate --status [--from <compose directory>] [--json]
               (on the installation's host, as root: --from is the Compose installation of the last
                TypeScript release, the current directory by default; --config the target's varlatchd.conf;
                --ingress the source's: its own Caddy (public), your reverse proxy (proxy), or Coolify's)`

// goOnlyCommands are the Go CLI's commands the TypeScript CLI does not
// have: host commands of a migration to a Go installation. They are not
// in the parity table (commands.go) or its inventory.
var goOnlyCommands = map[string]func(*Run) error{
	"migrate": migrateCommand,
}

type migrateOptions struct {
	from, config, bekFile, destination, readCredentials, destinationsFile, kekFile, tsCLI, ingress, unit string
	maxDowntime, drain, transferTimeout                                                                  time.Duration
	dryRun, resume, abort, status, asJSON                                                                bool
}

func parseMigrateOptions(args []string) (migrateOptions, error) {
	o := migrateOptions{}
	values := map[string]*string{"--from": &o.from, "--config": &o.config, "--bek-file": &o.bekFile, "--backup-destination": &o.destination,
		"--read-credentials-file": &o.readCredentials, "--destinations-file": &o.destinationsFile, "--kek-file": &o.kekFile, "--ts-cli": &o.tsCLI,
		"--ingress": &o.ingress, "--unit": &o.unit}
	durations := map[string]*time.Duration{"--max-downtime": &o.maxDowntime, "--drain": &o.drain, "--transfer-timeout": &o.transferTimeout}
	flags := map[string]*bool{"--dry-run": &o.dryRun, "--resume": &o.resume, "--abort": &o.abort, "--status": &o.status, "--json": &o.asJSON}
	usage := func(msg string) error { return UsageErrorWithUsage("varlatch migrate: "+msg, "\n"+migrateUsage) }
	for i := 0; i < len(args); i++ {
		a := args[i]
		if p, ok := flags[a]; ok {
			*p = true
			continue
		}
		name, val, inline := strings.Cut(a, "=")
		if p, ok := values[name]; ok {
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
			*p = val
			continue
		}
		if p, ok := durations[name]; ok {
			if !inline {
				if i+1 >= len(args) {
					return o, usage(name + " needs a duration")
				}
				val = args[i+1]
				i++
			}
			d, err := time.ParseDuration(val)
			if err != nil || d <= 0 {
				return o, usage(name + " takes a duration such as 10m or 90s")
			}
			*p = d
			continue
		}
		return o, usage("unknown option " + shownArgument(a))
	}
	switch {
	case o.status && (o.resume || o.abort || o.dryRun || o.config != "" || o.bekFile != "" || o.destination != ""):
		return o, usage("--status takes --from and --json only")
	case (o.resume || o.abort) && o.dryRun:
		return o, usage("--resume does what the interrupted run was asked, --abort undoes it; neither takes --dry-run")
	case o.resume && o.abort:
		return o, usage("--resume or --abort, not both")
	case o.unit != "" && !migrate.ValidUnit(o.unit):
		return o, usage("--unit takes a systemd unit's name (such as varlatchd), not an option or a path")
	case !o.status && !o.resume && !o.abort && !slices.Contains([]string{"public", "proxy", "coolify"}, o.ingress):
		return o, usage("--ingress is public, proxy or coolify: the source's ingress (its own Caddy, your reverse proxy, or Coolify's)")
	case !o.status && (o.config == "" || o.bekFile == "" || o.destination == "" || o.readCredentials == ""):
		return o, usage("give --config, --bek-file, --backup-destination and --read-credentials-file")
	}
	return o, nil
}

func migrateCommand(r *Run) error {
	for _, a := range r.Args {
		if a == "--help" || a == "-h" {
			return r.println(migrateUsage)
		}
	}
	o, err := parseMigrateOptions(r.Args)
	if err != nil {
		return err
	}
	if o.from == "" {
		o.from, err = os.Getwd()
		if err != nil {
			return Fail("varlatch migrate: "+err.Error(), ExitFailure)
		}
	}
	if o.from, err = filepath.Abs(o.from); err != nil {
		return Fail("varlatch migrate: "+err.Error(), ExitFailure)
	}
	if o.status {
		j, err := migrate.Status(o.from)
		if err != nil {
			return Fail("varlatch migrate: "+err.Error(), ExitFailure)
		}
		if j == nil {
			if o.asJSON {
				return r.printJSON(nil)
			}
			return r.out("No migration was started from " + o.from + ".\n")
		}
		return r.showJournal(j, o.asJSON)
	}
	bek, err := os.ReadFile(o.bekFile)
	if err != nil {
		return Fail("varlatch migrate: the Backup Encryption Key file: "+err.Error(), ExitFailure)
	}
	defer clear(bek)
	if len(bytes.TrimSpace(bek)) == 0 {
		return Fail("varlatch migrate: the Backup Encryption Key file "+Printable(o.bekFile)+" is empty: a migration copies the source's BEK, so give its file", ExitFailure)
	}
	varlatchd, err := r.locateVarlatchd("varlatch migrate")
	if err != nil {
		return err
	}
	run := migrate.ExecRunner{Env: environ(r)}
	e := &migrate.Engine{
		Source: &migrate.Compose{Directory: o.from, Run: run, TSCLI: o.tsCLI, KEKFile: o.kekFile, BEKFile: o.bekFile,
			Destination: o.destination, DestinationsFile: o.destinationsFile, ReadCredentialsFile: o.readCredentials},
		Target: &migrate.Host{Varlatchd: varlatchd, Config: o.config, Run: migrate.ExecRunner{Env: varlatchdEnviron(r)}, Unit: o.unit},
		Options: migrate.Options{MaxDowntime: o.maxDowntime, Drain: o.drain, TransferTimeout: o.transferTimeout, Ingress: migrate.Ingress(o.ingress),
			Say: func(s string) { _ = r.warn(s) }},
		BEK:    bek,
		Prober: migrate.HTTPProber{},
	}
	var j *migrate.Journal
	switch {
	case o.resume:
		j, err = e.Resume(context.Background())
	case o.abort:
		j, err = e.Abort(context.Background())
	default:
		j, err = e.Run(context.Background(), o.dryRun)
	}
	if j != nil {
		if serr := r.showJournal(j, o.asJSON); serr != nil {
			return serr
		}
	}
	if errors.Is(err, migrate.ErrAwaitingOperator) {
		// The Coolify shape's stop: the instruction was said; --resume
		// goes on once the domain is moved (EX_TEMPFAIL).
		return ExitWith(75)
	}
	if err != nil {
		return Fail("varlatch migrate: "+err.Error(), ExitFailure)
	}
	return nil
}

// showJournal writes the journal: as JSON, or its phase and reports in
// lines. It holds no key (internal/migrate.Journal), and goes through the
// fail-safe either way.
func (r *Run) showJournal(j *migrate.Journal, asJSON bool) error {
	if asJSON {
		b, err := j.Encode()
		if err != nil {
			return err
		}
		doc, err := jsjson.Parse(b)
		if err != nil {
			return err
		}
		return r.printJSON(doc)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Migration %s: phase %s", j.ID, j.Phase)
	if j.Stopped {
		b.WriteString(" (stopped there)")
	}
	fmt.Fprintf(&b, ".\nSource: %s (%s %s, %s).\nTarget: %s (data directory %s).\n", j.Source.Dir, j.Source.Kind, j.Source.Release, j.Source.Digest, j.Target.Config, j.Target.DataDir)
	if p := j.Preflight; p != nil {
		fmt.Fprintf(&b, "Preflight: backup %s verified after its download; the target's Root KEK file %s, its Backup Encryption Key file %s.\n", p.ArchiveID, p.RootKEK, p.BEK)
	}
	if d := j.DryRun; d != nil {
		verdict := "fits"
		if !d.Fits {
			verdict = "EXCEEDS"
		}
		transfer := ms(d.TransferMs) + " (estimated for " + string(d.Ingress) + " ingress, the target's restart included; included in the projection)"
		if d.TransferMeasured {
			transfer = ms(d.TransferMs)
		}
		fmt.Fprintf(&b, "Dry run: %d tables, %d rows; checks passed %v.\n", d.Copy.Tables, d.Copy.Rows, d.Checks != nil && d.Checks.Passed)
		fmt.Fprintf(&b, "Projected downtime %s %s the budget of %s: drain up to %s, export %s, import %s, checks %s, address transfer %s.\n",
			ms(d.ProjectedMs), verdict, ms(d.MaxDowntimeMs), ms(d.DrainMs), ms(d.ExportMs), ms(d.ImportMs), ms(d.CheckMs), transfer)
	}
	if bar := j.Barrier; bar != nil && bar.GateID != "" {
		fmt.Fprintf(&b, "Barrier: gate %s, frozen at audit position %s.\n", bar.GateID, bar.AuditPosition)
	}
	if c := j.Copy; c != nil {
		fmt.Fprintf(&b, "Final copy: installation %s, %d tables, %d rows; %d sessions ended, %d browser credentials revoked.\n",
			c.InstallationID, c.Tables, c.Rows, c.SessionsEnded, c.CredsRevoked)
		if c.Checks != nil {
			fmt.Fprintf(&b, "Checks passed: %v.\n", c.Checks.Passed)
		}
	}
	if tr := j.Transfer; tr != nil && (j.Phase == migrate.Transfer || tr.VerifiedAt != "") {
		state := "waiting for the public URL to answer from the target"
		if tr.VerifiedAt != "" {
			state = "the public URL answered from the target at " + tr.VerifiedAt
		} else if tr.Asked {
			state = "waiting for the domain move in Coolify (then varlatch migrate --resume)"
		}
		fmt.Fprintf(&b, "Address %s (%s ingress): %s.\n", tr.Origin, j.Ingress, state)
	}
	if u := j.Undone; u != nil {
		fmt.Fprintf(&b, "Undone from phase %s: %s.\n", u.From, u.Why)
	}
	return r.out(b.String())
}

func ms(n int64) string { return (time.Duration(n) * time.Millisecond).Round(time.Second).String() }
