// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/setup"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/tailcontrol"
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
                   [--tailscale-oauth-client-file <file> --tailnet-auth-key-file <file> [--accept-rollback-certificate]]
                   [--headscale-url <https://IP[:port]> --headscale-api-key-file <file> | --headscale-cli <path>]
               (a source serving a tailnet address: the name moves to the target's node; the OAuth client has the
                devices:core scope only, the file {"clientId": ..., "clientSecret": ...}; the auth key is reusable,
                with the node's tags; both from files, never an argument; --accept-rollback-certificate goes on
                when the old node's certificate cannot be renewed to last the rollback window: a rollback after
                it ends then needs a new one, about 40 s of downtime.
                On a self-hosted control server (Headscale), its authority instead of the OAuth client: its API
                at its IP address with a key from headscale apikeys create --expiration 1h (expired when the run
                ends: each run takes a new one; a run that is killed leaves its key live until it expires, up to
                an hour: expire it with headscale apikeys expire --prefix <prefix>, which the next run names), or
                its CLI's absolute path when migrate runs on the control server; the auth key is a reusable
                pre-auth key tagged with the node's tags; no HTTPS overlay)
  varlatch migrate ... --config /etc/varlatch/varlatchd.conf, not there yet: migrate makes the target with setup's steps
                   (as root; the varlatch user, the data directory, the configuration from the source's answers, the
                   unit enabled; never keys: they are the source's), removed again if the migration is undone:
                   [--acme-email <address>] [--listen <host:port>] [--accept-existing-user]
  varlatch migrate ... --to-data <dir> --to-keys <dir> --to-config <file> --to-image <ref:tag@sha256:...> --to-service <name>
                   (instead of --config and --unit: the Go image's service, created in setup mode with nothing listening,
                    its bind paths on this host; you start and stop it when migrate asks)
  varlatch migrate --resume (the same options)
  varlatch migrate --abort (the same options): undo a migration not yet switched, or a reverse before it records a start of the rebuilt TypeScript release
  varlatch migrate --abort --forget-target (the same options): after an undo whose removal of the target migrate made
                   kept failing and you removed what was left by hand (--status names each item), clear its record
  varlatch migrate --rollback [--from <compose directory>] (--config <varlatchd.conf> | --to-data ... as above)
                   [--drain <duration>] [--transfer-timeout <duration>]
               (within 30 days of the switch: back to the last TypeScript release, rebuilt on a fresh database
                from the Go installation, which keeps running until the address moves back)
  varlatch migrate --finish [--delete-old-data] [--from <compose directory>] (--config <varlatchd.conf> | --to-data ... as above)
                   [--bek-file <file> --backup-destination <name> --read-credentials-file <file>]
               (ends the rollback window: the TypeScript installation's containers and old node state removed, or
                after a rollback Go's copy kept; --delete-old-data, never implied, removes the old data too, after a
                final archive of it is made and verified: the backup options above are the final archive's)
  varlatch migrate --status [--from <compose directory>] [--json]
  varlatch migrate --from-archive <archive> ... (the backup converter: varlatch migrate --from-archive --help)
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
	oauthClientFile, tailnetAuthKeyFile, headscaleURL, headscaleKeyFile, headscaleCLI                    string
	toData, toKeys, toConfig, toImage, toService, acmeEmail, listen                                      string
	maxDowntime, drain, transferTimeout                                                                  time.Duration
	dryRun, resume, abort, status, asJSON, rollback, finish, deleteOldData, acceptExistingUser, forget   bool
	acceptRollbackCertificate                                                                            bool
}

func parseMigrateOptions(args []string) (migrateOptions, error) {
	o := migrateOptions{}
	values := map[string]*string{"--from": &o.from, "--config": &o.config, "--bek-file": &o.bekFile, "--backup-destination": &o.destination,
		"--read-credentials-file": &o.readCredentials, "--destinations-file": &o.destinationsFile, "--kek-file": &o.kekFile, "--ts-cli": &o.tsCLI,
		"--ingress": &o.ingress, "--unit": &o.unit, "--to-data": &o.toData, "--to-keys": &o.toKeys, "--to-config": &o.toConfig,
		"--to-image": &o.toImage, "--to-service": &o.toService, "--acme-email": &o.acmeEmail, "--listen": &o.listen,
		"--tailscale-oauth-client-file": &o.oauthClientFile, "--tailnet-auth-key-file": &o.tailnetAuthKeyFile,
		"--headscale-url": &o.headscaleURL, "--headscale-api-key-file": &o.headscaleKeyFile, "--headscale-cli": &o.headscaleCLI}
	durations := map[string]*time.Duration{"--max-downtime": &o.maxDowntime, "--drain": &o.drain, "--transfer-timeout": &o.transferTimeout}
	flags := map[string]*bool{"--dry-run": &o.dryRun, "--resume": &o.resume, "--abort": &o.abort, "--status": &o.status, "--json": &o.asJSON, "--rollback": &o.rollback, "--accept-rollback-certificate": &o.acceptRollbackCertificate,
		"--finish": &o.finish, "--delete-old-data": &o.deleteOldData, "--accept-existing-user": &o.acceptExistingUser, "--forget-target": &o.forget}
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
	case o.forget && (!o.abort || o.config == ""):
		return o, usage("--forget-target goes with --abort and --config only: it clears the record of a target migrate made, once you removed what was left of it by hand")
	case (o.acmeEmail != "" || o.listen != "" || o.acceptExistingUser) && (o.config == "" || o.rollback || o.finish || o.status):
		return o, usage("--acme-email, --listen and --accept-existing-user are the answers of a host target migrate makes (--config): not with --rollback, --finish, --status or --to-*")
	case o.acceptRollbackCertificate && o.oauthClientFile == "":
		return o, usage("--accept-rollback-certificate goes with --tailscale-oauth-client-file: it is the tailnet handoff's")
	case (o.status || o.finish) && (o.oauthClientFile != "" || o.tailnetAuthKeyFile != "" || o.headscaleURL != "" || o.headscaleKeyFile != "" || o.headscaleCLI != ""):
		return o, usage("the tailnet's authority and --tailnet-auth-key-file go with a migration, its --resume and --abort, and --rollback")
	case (o.headscaleURL != "") != (o.headscaleKeyFile != ""):
		return o, usage("--headscale-url and --headscale-api-key-file go together: Headscale's API and its key")
	case o.headscaleURL != "" && o.headscaleCLI != "":
		return o, usage("--headscale-url or --headscale-cli, not both: Headscale's API, or its CLI on the control server")
	case o.oauthClientFile != "" && (o.headscaleURL != "" || o.headscaleCLI != ""):
		return o, usage("one tailnet authority: --tailscale-oauth-client-file (Tailscale's) or --headscale-url/--headscale-cli (a self-hosted control server's)")
	case o.headscaleURL != "" && headscaleURLRefusal(o.headscaleURL) != "":
		return o, usage("--headscale-url " + shownArgument(o.headscaleURL) + ": " + headscaleURLRefusal(o.headscaleURL))
	case o.headscaleCLI != "" && !filepath.IsAbs(o.headscaleCLI):
		return o, usage("--headscale-cli is the headscale command's absolute path")
	case o.deleteOldData && !o.finish:
		return o, usage("--delete-old-data goes with --finish only: it removes the old side's data, after a verified final archive")
	case o.finish && (o.resume || o.abort || o.rollback || o.dryRun || o.status || o.ingress != "" || o.maxDowntime != 0 || o.drain != 0 || o.transferTimeout != 0):
		return o, usage("--finish takes --from, the target (--config, or --to-*), --delete-old-data and the final archive's backup options only")
	case o.finish && o.config == "" && o.toData == "":
		return o, usage("--finish needs the target: --config, or --to-data, --to-keys, --to-config, --to-image and --to-service")
	case o.rollback && (o.resume || o.abort || o.dryRun || o.status || o.ingress != "" || o.bekFile != "" || o.destination != "" || o.readCredentials != "" || o.maxDowntime != 0):
		return o, usage("--rollback takes --from, the target (--config, or --to-*), --drain and --transfer-timeout: the rest is the migration's journal's; --resume and --abort go on with an interrupted reverse")
	case o.rollback && o.config == "" && o.toData == "":
		return o, usage("--rollback needs the target: --config, or --to-data, --to-keys, --to-config, --to-image and --to-service")
	case o.unit != "" && !migrate.ValidUnit(o.unit):
		return o, usage("--unit takes a systemd unit's name (such as varlatchd), not an option or a path")
	case !o.status && !o.resume && !o.abort && !o.rollback && !o.finish && !slices.Contains([]string{"public", "proxy", "coolify"}, o.ingress):
		return o, usage("--ingress is public, proxy or coolify: the source's ingress (its own Caddy, your reverse proxy, or Coolify's)")
	case o.config != "" && (o.toData != "" || o.toKeys != "" || o.toConfig != "" || o.toImage != "" || o.toService != ""):
		return o, usage("--config is a host install's target, --to-* the image's: give one of them")
	case (o.toData != "" || o.toKeys != "" || o.toConfig != "" || o.toImage != "" || o.toService != "") &&
		(o.toData == "" || o.toKeys == "" || o.toConfig == "" || o.toImage == "" || o.toService == ""):
		return o, usage("the image target takes --to-data, --to-keys, --to-config, --to-image and --to-service, all of them")
	case o.toData != "" && o.unit != "":
		return o, usage("--unit is a host install's: the image's service is started and stopped by you")
	case (o.resume || o.abort) && o.config == "" && o.toData == "":
		return o, usage("--resume and --abort need the target: --config, or --to-data, --to-keys, --to-config, --to-image and --to-service")
	case !o.status && !o.rollback && !o.finish && !o.resume && !o.abort && ((o.config == "" && o.toData == "") || o.bekFile == "" || o.destination == "" || o.readCredentials == ""):
		return o, usage("give the target (--config, or --to-data, --to-keys, --to-config, --to-image and --to-service), --bek-file, --backup-destination and --read-credentials-file")
	}
	return o, nil
}

// imageFailure is the image target's refusal; --to-image's form, which
// the fail-safe would mask whole, follows as this binary's constant.
func imageFailure(err error) error {
	var re *migrate.ImageRefError
	if errors.As(err, &re) {
		return &exitError{message: "varlatch migrate: " + err.Error(), constant: " (the form: " + migrate.ImageRefForm + ")", code: ExitFailure}
	}
	return Fail("varlatch migrate: "+err.Error(), ExitFailure)
}

func migrateCommand(r *Run) error {
	if fromArchive(r.Args) {
		return migrateArchiveCommand(r)
	}
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
	// Everything this command writes on stderr from here goes through one
	// writer, which nothing waits for; and a pipe whose reader went away
	// ends no migration half way: a write to it fails, and is ignored. For
	// the rest of the process, so that what is printed last cannot end it
	// either, with another status than the result's.
	_ = ignoreBrokenPipe()
	lines := migrate.NewLines(func(s string) { _ = r.warn(s) })
	err = r.migrateRun(o, lines)
	// Its failure is its last line, and does not wait for a reader either.
	var e *exitError
	if errors.As(err, &e) && !e.silent && e.constant == "" && e.usage == "" {
		lines.Say(e.message)
		err = ExitWith(e.code)
	}
	lines.Close(migrateLastWait)
	return err
}

// migrateLastWait bounds what a migration waits for its reader at its end.
const migrateLastWait = 5 * time.Second

// migrateRun is a run that may change something.
func (r *Run) migrateRun(o migrateOptions, lines *migrate.Lines) (err error) {
	// --resume and --abort read the BEK when given: a migration redone
	// from its preflight needs it (its backup refuses without it), a
	// reverse never.
	var bek []byte
	if !o.rollback && (o.bekFile != "" || (!o.resume && !o.abort && !o.finish)) {
		bek, err = os.ReadFile(o.bekFile)
		if err != nil {
			return Fail("varlatch migrate: the Backup Encryption Key file: "+err.Error(), ExitFailure)
		}
		defer clear(bek)
		if len(bytes.TrimSpace(bek)) == 0 {
			return Fail("varlatch migrate: the Backup Encryption Key file "+Printable(o.bekFile)+" is empty: a migration copies the source's BEK, so give its file", ExitFailure)
		}
	}
	// The tailnet handoff's authority and the new node's auth key, from
	// files only (never an argument or the environment).
	var tailnetOptions *migrate.TailnetOptions
	if o.oauthClientFile != "" || o.headscaleURL != "" || o.headscaleCLI != "" {
		var cp tailcontrol.ControlPlane
		server := ""
		switch {
		case o.oauthClientFile != "":
			cp, err = tailscaleControl(o.oauthClientFile)
		case o.headscaleURL != "":
			server, _ = tailcontrol.CanonicalControlURL(o.headscaleURL)
			cp, err = headscaleAPIControl(server, o.headscaleKeyFile)
		default:
			server = migrate.CLIAuthority(o.headscaleCLI)
			cp, err = headscaleCLIControl(o.headscaleCLI)
		}
		if err != nil {
			return Fail("varlatch migrate: "+err.Error(), ExitFailure)
		}
		api, _ := cp.(*tailcontrol.HeadscaleAPI)
		if api != nil {
			// A run killed before it closed its key left it live: said, with
			// its prefix. This run's is recorded until it is closed.
			if note := unclosedKeyNote(o.from); note != "" {
				lines.Say(note)
			}
			markKeyOpen(o.from, api.KeyPrefix(), time.Now())
		}
		// The authority ends with the run, whatever its outcome: a
		// Headscale API key is expired (a later run takes a new one).
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			prefix := ""
			if api != nil {
				prefix = api.KeyPrefix()
			}
			if err := cp.Close(ctx); err != nil {
				lines.Say("varlatch migrate: " + err.Error() + "; it expires on its own within the hour, or expire it now: headscale apikeys expire --prefix " + cmp.Or(prefix, "<its prefix>"))
				return
			}
			if api != nil {
				markKeyClosed(o.from)
			}
		}()
		tailnetOptions = &migrate.TailnetOptions{Control: cp, AcceptRollbackCertificate: o.acceptRollbackCertificate, Server: server}
	}
	var tailnetAuthKey []byte
	if o.tailnetAuthKeyFile != "" {
		key, err := secretinput.ReadFile(o.tailnetAuthKeyFile)
		if err != nil {
			return Fail("varlatch migrate: the tailnet auth key file: "+err.Error(), ExitFailure)
		}
		tailnetAuthKey = []byte(strings.TrimSpace(key))
		defer clear(tailnetAuthKey)
	}
	varlatchd, err := r.locateVarlatchd("varlatch migrate")
	if err != nil {
		return err
	}
	run := migrate.ExecRunner{Env: environ(r)}
	e := &migrate.Engine{
		Source: &migrate.Compose{Directory: o.from, Run: run, Env: run.Env, TSCLI: o.tsCLI, KEKFile: o.kekFile, BEKFile: o.bekFile,
			Destination: o.destination, DestinationsFile: o.destinationsFile, ReadCredentialsFile: o.readCredentials},
		Target: &migrate.Host{Varlatchd: varlatchd, Config: o.config, Run: migrate.ExecRunner{Env: targetCredentials(varlatchdEnviron(r), o.config)}, Unit: o.unit},
		Options: migrate.Options{MaxDowntime: o.maxDowntime, Drain: o.drain, TransferTimeout: o.transferTimeout, Ingress: migrate.Ingress(o.ingress),
			Say: lines.Say},
		BEK:     bek,
		Prober:  migrate.HTTPProber{},
		Tailnet: tailnetOptions,
	}
	if !o.asJSON {
		e.Options.Progress = lines.Progress
	}
	host := e.Target.(*migrate.Host)
	host.TailnetAuthKey = tailnetAuthKey
	e.Options.StageAs = func(ctx context.Context) (*migrate.Owner, string, error) {
		owner, err := host.DataOwner(ctx)
		if err != nil || owner == nil {
			return nil, "", err
		}
		base, err := migrate.StageBase(o.from)
		return owner, base, err
	}
	if o.config != "" {
		if err := r.targetMaker(e, o, varlatchd, lines); err != nil {
			return err
		}
	}
	if o.toData != "" {
		img := &migrate.Image{Host: &migrate.Host{Varlatchd: varlatchd, Run: migrate.ExecRunner{Env: varlatchdEnviron(r), As: &migrate.ImageUser}},
			Service: o.toService, Ref: o.toImage, DataDir: o.toData, KeysDir: o.toKeys, ServiceConfig: o.toConfig, User: migrate.ImageUser}
		base, err := migrate.StageBase(o.from)
		if err != nil {
			return Fail("varlatch migrate: "+err.Error(), ExitFailure)
		}
		cleanup, err := migrate.PrepareImage(context.Background(), img, base, !o.resume && !o.abort && !o.rollback && !o.finish)
		defer cleanup()
		if err != nil {
			return imageFailure(err)
		}
		img.Host.TailnetAuthKey = tailnetAuthKey
		e.Target = img
		e.Options.StageAs = nil
		e.Options.Stage, e.Options.StageBase, e.Options.StageKeep = &migrate.ImageUser, base, filepath.Dir(img.Host.Config)
	}
	var j *migrate.Journal
	switch {
	case o.resume:
		j, err = e.Resume(context.Background())
	case o.abort && o.forget:
		j, err = e.ForgetTarget(context.Background())
	case o.abort:
		j, err = e.Abort(context.Background())
	case o.rollback:
		j, err = e.Rollback(context.Background())
	case o.finish:
		j, err = e.Finish(context.Background(), o.deleteOldData)
	default:
		j, err = e.Run(context.Background(), o.dryRun)
	}
	lines.Flush(time.Second)
	// What the journal records, read back: a refusal's request (such as
	// --delete-old-data refused before anything was done) is not shown as
	// done.
	if j != nil {
		if disk, rerr := migrate.Status(o.from); rerr == nil && disk != nil {
			j = disk
		}
		// A journal nobody reads is no other result: stdout may be a pipe
		// that is full, and is not waited for longer than stderr is.
		shown := make(chan error, 1)
		go func() { shown <- r.showJournal(j, o.asJSON) }()
		select {
		case serr := <-shown:
			if serr != nil && err == nil && !errors.Is(serr, syscall.EPIPE) {
				return serr
			}
		case <-time.After(migrateLastWait):
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
		headroom := ""
		if d.HeadroomMs > 0 {
			headroom = ", with headroom " + ms(d.HeadroomMs)
		}
		fmt.Fprintf(&b, "Dry run: %d tables, %d rows; checks passed %v.\n", d.Copy.Tables, d.Copy.Rows, d.Checks != nil && d.Checks.Passed)
		fmt.Fprintf(&b, "Projected downtime %s %s the budget of %s%s: drain up to %s, export %s, import %s, checks %s, address transfer %s.\n",
			ms(d.ProjectedMs), verdict, ms(d.MaxDowntimeMs), headroom, ms(d.DrainMs), ms(d.ExportMs), ms(d.ImportMs), ms(d.CheckMs), transfer)
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
	if rb := j.Rollback; rb != nil {
		fmt.Fprintf(&b, "Reverse, begun %s:", rb.StartedAt)
		if bar := rb.Barrier; bar != nil {
			fmt.Fprintf(&b, " Go's barrier froze it at audit position %s;", bar.AuditPosition)
		}
		if ex := rb.Export; ex != nil {
			fmt.Fprintf(&b, " the reverse bundle %d tables, %d rows, %d sessions ended;", ex.Tables, ex.Rows, ex.SessionsEnded)
		}
		if rr := rb.Rebuild; rr != nil {
			fmt.Fprintf(&b, " fresh volumes %s;", strings.Join(rr.Volumes, ", "))
		}
		if im := rb.Import; im != nil {
			fmt.Fprintf(&b, " imported by the TypeScript release up to audit position %s;", im.AuditPosition)
		}
		if c := rb.Checks; c != nil {
			fmt.Fprintf(&b, " reverse checks passed %v;", c.Passed)
		}
		if rb.ServedAt != "" {
			fmt.Fprintf(&b, " a start of the rebuilt TypeScript release was recorded at %s (it may have accepted writes since: forward only);", rb.ServedAt)
		}
		if len(rb.KeptVolumes) > 0 {
			fmt.Fprintf(&b, " its undo does not delete the fresh volumes %s (check which still exist before reconciling them: they may hold writes the TypeScript installation does not have; then remove them by hand);", strings.Join(rb.KeptVolumes, ", "))
		}
		if rb.VerifiedAt != "" {
			fmt.Fprintf(&b, " the public URL answered from the TypeScript release at %s;", rb.VerifiedAt)
		} else if rb.Asked {
			b.WriteString(" waiting for your step (then varlatch migrate --resume);")
		}
		if u := rb.Undone; u != nil {
			fmt.Fprintf(&b, " undone from phase %s: %s", u.From, u.Why)
			if rb.Unrestored != "" {
				fmt.Fprintf(&b, "; the TypeScript installation is not put back (%s), its server stopped: do not start it, varlatch migrate --resume puts it back", rb.Unrestored)
			}
		}
		b.WriteString("\n")
		for _, a := range rb.Archives {
			fmt.Fprintf(&b, "Go archive made since the switch (migrate deletes none; its local file follows backup_keep): %s (release %s, %s).\n", a.ArchiveID, a.Release, a.CreatedAt)
		}
	}
	if c := j.Created; c != nil {
		state := "kept"
		switch {
		case c.Forgotten:
			state = "removed by hand, its record cleared " + Printable(c.Undone)
		case c.Undone != "":
			state = "removed again " + Printable(c.Undone)
		case j.Phase == migrate.Released:
			state = "removal pending: varlatch migrate --abort removes it"
		}
		fmt.Fprintf(&b, "Target made by migrate: %s (%s).\n", Printable(strings.Join(c.Made, ", ")), state)
		if c.Undone == "" && j.Phase == migrate.Released {
			// Each item's place, for removing it by hand (the journal's
			// config is setup's, or a test root's: checked as it is read).
			root := strings.TrimSuffix(c.Config, setup.ConfigFile)
			for _, item := range c.Made {
				fmt.Fprintf(&b, "  %s: %s\n", Printable(item), Printable(setup.ItemPlace(func(p string) string { return root + p }, item)))
			}
		}
	}
	if f := j.Finish; f != nil {
		data := "the old data kept"
		switch {
		case f.DeleteOldData && f.DoneAt != "":
			data = "the old data deleted"
		case f.DeleteOldData:
			data = "the old data to be deleted (--delete-old-data)"
		}
		fmt.Fprintf(&b, "Finish (after %s), begun %s; %s.", f.After, f.StartedAt, data)
		if f.ArchiveID != "" {
			fmt.Fprintf(&b, " Final archive %s (format %d), verified %s.", f.ArchiveID, f.ArchiveFormat, f.VerifiedAt)
		}
		switch {
		case f.DoneAt != "":
			fmt.Fprintf(&b, " Removed: %s.", strings.Join(f.Removed, ", "))
		case j.Phase == migrate.Finished:
			b.WriteString(" Not done yet: varlatch migrate --resume finishes it.")
		default:
			// Before finished (killed before the window closed): --finish
			// again, which keeps a verified final archive.
			again := "varlatch migrate --finish"
			if f.DeleteOldData {
				again += " --delete-old-data"
			}
			b.WriteString(" Not finished: run " + again + " again.")
		}
		b.WriteString("\n")
	}
	return r.out(b.String())
}

// tailscaleControl is the tailnet's control plane from the operator's
// OAuth client file ({"clientId": ..., "clientSecret": ...}; O4: the
// devices:core scope only, checked at every token exchange), with this
// CLI's own client.
func tailscaleControl(path string) (tailcontrol.ControlPlane, error) {
	text, err := secretinput.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the Tailscale OAuth client file: %w", err)
	}
	var c struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Tailnet      string `json:"tailnet"`
	}
	if err := json.Unmarshal([]byte(text), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("the Tailscale OAuth client file %s is not {\"clientId\": ..., \"clientSecret\": ...}", Printable(path))
	}
	return tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: tailscaleAPIOverride, Tailnet: c.Tailnet, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		HTTP: tailscaleHTTPClient()})
}

// headscaleURLRefusal is why --headscale-url is refused, "" when it is
// not: lib/tailcontrol's rule, tailnet_control_url's, so the server is
// spelled as varlatchd.conf spells it (https on an IP address).
func headscaleURLRefusal(v string) string {
	_, why := tailcontrol.CanonicalControlURL(v)
	return why
}

// headscaleKeyMark is the Compose directory's record of the Headscale API
// key a run opened and has not closed yet: its prefix and when, never the
// key. A run killed before Close leaves its key live until the key
// expires; the next run says so, naming the prefix to expire.
const headscaleKeyMark = "migration-headscale-key.json"

type keyMark struct {
	Prefix   string    `json:"prefix"`
	OpenedAt time.Time `json:"openedAt"`
}

// unclosedKeyNote is what to say about a key an earlier run left open.
func unclosedKeyNote(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, headscaleKeyMark))
	if err != nil {
		return ""
	}
	var m keyMark
	if json.Unmarshal(b, &m) != nil || m.Prefix == "" {
		return ""
	}
	return fmt.Sprintf("varlatch migrate: an earlier run opened the Headscale API key %s at %s and did not close it (it was stopped): the key stays live until it expires, up to an hour after it was made. Expire it now: headscale apikeys expire --prefix %s",
		m.Prefix, m.OpenedAt.UTC().Format(time.RFC3339), m.Prefix)
}

func markKeyOpen(dir, prefix string, at time.Time) {
	b, _ := json.Marshal(keyMark{Prefix: prefix, OpenedAt: at.UTC()})
	_ = os.WriteFile(filepath.Join(dir, headscaleKeyMark), append(b, '\n'), 0o600)
}

func markKeyClosed(dir string) { _ = os.Remove(filepath.Join(dir, headscaleKeyMark)) }

// headscaleAPIControl is a self-hosted control server's API with the
// operator's key, read from its file and checked (Headscale lists it, and
// it expires within the hour) before anything else is done.
func headscaleAPIControl(base, keyFile string) (tailcontrol.ControlPlane, error) {
	key, err := secretinput.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("the Headscale API key file: %w", err)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("the Headscale API key file %s is empty", Printable(keyFile))
	}
	h, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{BaseURL: base, APIKey: key, HTTP: tailscaleHTTPClient()})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := h.Open(ctx); err != nil {
		return nil, err
	}
	return h, nil
}

// headscaleCLIControl is the control server's own headscale command, for a
// migration run on that server: no key leaves it.
func headscaleCLIControl(path string) (tailcontrol.ControlPlane, error) {
	h := &tailcontrol.HeadscaleCLI{Binary: path}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return h, nil
}

func ms(n int64) string { return (time.Duration(n) * time.Millisecond).Round(time.Second).String() }

// targetNeedsRoot is why migrate may change the host target at setup's
// place ("" when it will not): its configuration is missing (migrate makes
// it) or cannot be read (it may be missing), or the journal records a
// target migrate made and has not removed, before its switch (an undo
// removes it, a run goes on making it; from the switch on it is kept).
func targetNeedsRoot(statErr error, j *migrate.Journal) string {
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		return setup.ConfigFile + " does not exist: migrate makes the target there"
	case statErr != nil:
		return setup.ConfigFile + " cannot be read (" + Printable(statErr.Error()) + "): migrate may make the target there"
	case j != nil && j.TargetMayChange():
		return "the migration " + j.ID + " made the target at " + setup.ConfigFile + " and has not removed it: migrate may change it"
	}
	return ""
}

// targetMaker sets the engine's maker of the host target (slice 7.4e) when
// --config is setup's place: migrate makes the target there when it is
// missing (as root, on a systemd host), and undoes what it made. Another
// place must be a prepared target.
func (r *Run) targetMaker(e *migrate.Engine, o migrateOptions, varlatchd string, lines *migrate.Lines) error {
	host, seam := targetHost(varlatchd, varlatchdEnviron(r))
	_, statErr := os.Stat(o.config)
	missing := errors.Is(statErr, fs.ErrNotExist)
	if filepath.Clean(o.config) != host.Path(setup.ConfigFile) {
		if missing {
			return Fail("varlatch migrate: --config "+Printable(o.config)+" does not exist: migrate makes the target at setup's place only ("+setup.ConfigFile+"), or give a prepared target's configuration", ExitFailure)
		}
		return nil
	}
	j, _ := migrate.Status(e.Source.Dir()) // unreadable: the engine says so
	if why := targetNeedsRoot(statErr, j); why != "" && !seam && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		return Fail("varlatch migrate: "+why+", which needs root on a systemd host (sudo varlatch migrate ...)", ExitFailure)
	}
	e.Maker = &setupMaker{host: host, given: setup.Answers{ACMEEmail: o.acmeEmail, Listen: o.listen}, accept: o.acceptExistingUser,
		say: func(s string) error { lines.Say(s); return nil }}
	return nil
}
