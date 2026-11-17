// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/freeze"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Admin runs `varlatchd admin ...` (ADR-0010, ADR-0020): host exec
// authority, the Infrastructure Operator's front door. Every command goes
// through the running daemon's control socket, or runs offline under the
// data directory's lock when no daemon runs (control.go, decision 11).
// bootstrap and recover print exactly what the TypeScript server's admin
// CLI prints (src/cli.ts), which the conformance harness parses: an
// enrollment URL on a line of its own, or, with --cli-credential, a
// one-time CLI credential on the last line.
//
//	varlatchd admin bootstrap [--cli-credential [--name <name>]] [--config <file>]
//	varlatchd admin recover (--identity <id> [--enable] | --new-admin) [--cli-credential [--name <name>]] [--config <file>]
//
// They refuse with the wrong Root KEK. Exit 0 on success, 1 on a refusal
// or failure, 64 on a usage error, 78 on a configuration error.
func Admin(args []string, stdout, stderr io.Writer) int { return admin(args, stdout, stderr) }

func admin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return adminUsage(stderr, "no command")
	}
	sub := args[0]
	conformance := sub == "conformance-probe" && conformanceProbe != nil ||
		sub == "conformance-fixture" && conformanceFixture != nil
	operator := sub == "security" || sub == "unfreeze"
	backup := sub == "backup" || sub == "maintenance"
	keys := sub == "kek" || sub == "custody"
	if sub != "bootstrap" && sub != "recover" && sub != "outbound" && sub != "audit-export" && sub != "tailnet" && !conformance && !operator && !backup && !keys {
		return adminUsage(stderr, "unknown command "+sub)
	}
	// The one probe that needs no installation: nothing stands in front
	// of varlatchd.
	if sub == "conformance-probe" && len(args) > 1 && args[1] == "proxy-addresses" {
		fmt.Fprintln(stdout, "[]")
		return ExitOK
	}
	path := config.DefaultPath
	var rest []string
	for i := 1; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			path = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	switch {
	case sub == "outbound":
		if _, msg := outboundArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "kek":
		if len(rest) == 0 || !slices.Contains([]string{"verify", "export", "restore", "split", "combine"}, rest[0]) {
			fmt.Fprintln(stderr, kekUsage)
			return 64
		}
	case sub == "audit-export":
		if _, msg := auditExportArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "tailnet":
		if _, msg := tailnetArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "custody":
		if _, _, msg := custodyArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case backup:
		if _, msg := backupArgs(sub, rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case operator:
		// Checked here, so a usage error never reaches the daemon.
		if msg := operatorUsage(sub, rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case !conformance && sub != "kek" && sub != "outbound":
		if _, msg := parseAdmin(sub, rest); msg != "" {
			return adminUsage(stderr, msg)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			fmt.Fprintf(stderr, "varlatchd admin %s: the configuration file %s is not valid: %v\n", sub, path, err)
			return ExitConfig
		}
		fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, err.Error())
		return ExitFailure
	}
	switch {
	case sub == "outbound":
		return runOutboundCheck(cfg, rest, stdout, stderr)
	case sub == "kek":
		return runKek(cfg, rest, os.Stdin, stdout, stderr)
	case sub == "custody" && rest[0] == "status":
		return runCustodyStatus(cfg, stdout, stderr)
	case sub == "backup" && rest[0] == "restore":
		return restoreOffline(cfg, rest[1:], stdout, stderr)
	}
	return route(cfg, append([]string{sub}, rest...), stdout, stderr)
}

func adminUsage(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "varlatchd admin: %s\nUsage: varlatchd admin bootstrap [--cli-credential] [--name <name>] | "+
		"varlatchd admin recover --identity <id> [--enable] | --new-admin [--cli-credential] [--name <name>] | "+
		"varlatchd admin security reset ... | varlatchd admin unfreeze ... | varlatchd admin backup run|status|restore|test-bucket | varlatchd admin maintenance begin|end|status | "+
		"varlatchd admin kek verify|export|restore|split|combine | varlatchd admin custody attest|status | varlatchd admin outbound check | "+
		"varlatchd admin audit-export discard-plan --export <id> --reason <expired|unsupported-format> | varlatchd admin tailnet repin [--yes [--adopt]] [--json]  (each with [--config <file>])\n", msg)
	return 64
}

// operatorUsage checks `admin security reset` and `admin unfreeze`'s
// arguments (--config already taken out): "" when they are well formed,
// else what the TypeScript admin CLI prints for them.
func operatorUsage(sub string, rest []string) string {
	if sub == "unfreeze" {
		_, msg := freeze.ParseUnfreezeArgs(rest)
		return msg
	}
	if len(rest) == 0 || rest[0] != "reset" {
		return security.ResetUsage
	}
	_, msg := security.ParseResetArgs(rest[1:])
	return msg
}

// runOperator runs the host operator's two commands that write through the
// Organization's gate (feature-parity decision 11): `security reset`
// (ADR-0054 Decision 10) and `unfreeze` (ADR-0055 Decision 2). In the
// daemon they take its gates, so each waits for an external effect of the
// Organization held open meanwhile and commits after it; offline, under
// the lock, nothing else runs. Each prints the TypeScript admin CLI's
// lines, or its outcome as JSON with --json.
func runOperator(ctx context.Context, env *hostEnv, sub string, rest []string, stdout, stderr io.Writer) int {
	if msg := operatorUsage(sub, rest); msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	w := &write.Writer{Store: env.store, Gates: env.gates}
	approvals := auth.New(env.store, auth.Options{PublicURL: env.cfg.PublicURL, RootKEK: env.rootKEK, PersonGate: env.gates.PersonGate})
	var lines []string
	var js jsvalue.Object
	var asJSON bool
	var err error
	if sub == "security" {
		a, _ := security.ParseResetArgs(rest[1:])
		asJSON = a.JSON
		var out security.ResetOutcome
		if out, err = security.ResetControls(ctx, w, approvals, a.Organization, a.Controls, time.Now); err == nil {
			lines, js = out.Lines(), out.JS()
		}
	} else {
		a, _ := freeze.ParseUnfreezeArgs(rest)
		asJSON = a.JSON
		var out freeze.OperatorOutcome
		if out, err = freeze.OperatorUnfreeze(ctx, w, approvals, a.Organization, a.Confirm, time.Now); err == nil {
			lines, js = out.Lines(), out.JS()
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, err.Error())
		return ExitFailure
	}
	if asJSON {
		fmt.Fprintln(stdout, string(jsvalue.Stringify(js)))
	} else {
		fmt.Fprintln(stdout, strings.Join(lines, "\n"))
	}
	return ExitOK
}

type adminArgs struct {
	values map[string]string
	flags  map[string]bool
}

// parseAdmin reads bootstrap's and recover's arguments (--config already
// taken out); a non-empty message is a usage error.
func parseAdmin(sub string, args []string) (adminArgs, string) {
	a := adminArgs{values: map[string]string{}, flags: map[string]bool{}}
	valued := map[string]bool{"--name": true, "--identity": true}
	allowed := map[string]bool{"--name": true, "--cli-credential": true}
	if sub == "recover" {
		allowed["--identity"], allowed["--enable"], allowed["--new-admin"] = true, true, true
	}
	for rest := args; len(rest) > 0; {
		f := rest[0]
		if !allowed[f] {
			return a, sub + ": unknown argument " + f
		}
		if valued[f] {
			if len(rest) < 2 {
				return a, sub + ": " + f + " needs a value"
			}
			a.values[f], rest = rest[1], rest[2:]
			continue
		}
		a.flags[f], rest = true, rest[1:]
	}
	if sub == "recover" && (a.values["--identity"] == "") == !a.flags["--new-admin"] {
		return a, "Usage: varlatchd admin recover --identity <id> [--enable] | --new-admin"
	}
	return a, ""
}

// openOffline opens the installation for a command run offline, under the
// lock: the Root KEK, the database (its schema and installation created if
// this is the first use, as serve would), and the canary checked.
func openOffline(cfg *config.Config, what string, stderr io.Writer) (*hostEnv, int) {
	material, err := os.ReadFile(cfg.RootKEKFile)
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the Root KEK file: %v\n", what, err)
		return nil, ExitFailure
	}
	rootKEK, err := envelope.ParseRootKEK(string(material))
	clear(material)
	if err != nil {
		fmt.Fprintf(stderr, "%s: the Root KEK file does not hold a Root KEK: %v\n", what, err)
		return nil, ExitConfig
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: cfg.DatabasePath()})
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot open the database: %v\n", what, err)
		return nil, ExitFailure
	}
	fail := func(status int, format string, args ...any) (*hostEnv, int) {
		_ = store.Close()
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return nil, status
	}
	if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
		return fail(ExitFailure, "%s", err.Error())
	}
	inst, _, err := ensureInstallation(ctx, store, rootKEK)
	if err != nil {
		return fail(ExitFailure, "%s", err.Error())
	}
	if !verify(rootKEK, inst) {
		return fail(ExitConfig, "the configured Root KEK does not open this installation's canary")
	}
	env := &hostEnv{cfg: cfg, store: store, rootKEK: rootKEK, gates: write.NewGates(), admission: maintenance.Open(cfg.DataDir, nil), log: slog.New(slog.NewTextHandler(stderr, nil))}
	env.backups = newBackups(env)
	return env, ExitOK
}

// MaintenanceRefusal is the TypeScript admin CLI's refusal of an ordinary
// command during installation maintenance (cli.ts).
const MaintenanceRefusal = "Installation is in maintenance; ordinary admin operations are blocked"

// writes reports whether a host command may write the installation: all
// but the backup and maintenance commands, which take the admission their
// own way (backup run enters it; maintenance manages it; backup status
// only reads).
func writes(sub string) bool { return sub != "backup" && sub != "maintenance" }

// runHost runs one host command, in the daemon or offline, with env. A
// command that writes enters the maintenance admission first, before any
// gate or job, and is counted until it ends; while a gate is open it is
// refused, as the TypeScript admin CLI refuses it.
func runHost(ctx context.Context, env *hostEnv, args []string, stdout, stderr io.Writer) int {
	sub, rest := args[0], args[1:]
	if writes(sub) && env.admission != nil {
		leave, ok := env.admission.Enter()
		if !ok {
			fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, MaintenanceRefusal)
			return ExitFailure
		}
		defer leave()
	}
	switch {
	case sub == "conformance-probe" && conformanceProbe != nil:
		return conformanceProbe(ctx, env, rest, stdout, stderr)
	case sub == "conformance-fixture" && conformanceFixture != nil:
		return conformanceFixture(ctx, env, rest, stdout, stderr)
	case sub == "security" || sub == "unfreeze":
		return runOperator(ctx, env, sub, rest, stdout, stderr)
	case sub == "backup" || sub == "maintenance":
		return runBackupCommand(ctx, env, sub, rest, stdout, stderr)
	case sub == "custody":
		return runCustodyAttest(ctx, env, rest, stdout, stderr)
	case sub == "audit-export":
		return runAuditExport(ctx, env, rest, stdout, stderr)
	case sub == "tailnet":
		return runTailnetRepin(ctx, env, rest, stdout, stderr)
	case sub != "bootstrap" && sub != "recover":
		return adminUsage(stderr, "unknown command "+sub)
	}
	a, msg := parseAdmin(sub, rest)
	if msg != "" {
		return adminUsage(stderr, msg)
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, err.Error())
		return ExitFailure
	}
	svc := auth.New(env.store, auth.Options{PublicURL: env.cfg.PublicURL})
	base := issuer(env.cfg)
	name := a.values["--name"]
	if name == "" {
		name = "Installation Admin"
	}
	out := func(lines ...string) int {
		fmt.Fprint(stdout, strings.Join(lines, "\n")+"\n")
		return ExitOK
	}

	if sub == "bootstrap" {
		grant, err := svc.IssueBootstrapGrant(ctx)
		if err != nil {
			return fail(err)
		}
		if a.flags["--cli-credential"] {
			// Headless fallback: consume at once, issue a CLI credential.
			consumed, issued, err := svc.ConsumeForCLICredential(ctx, grant.Token, name, "bootstrap credential")
			if err != nil {
				return fail(err)
			}
			return out("Installation bootstrapped.",
				"Installation Admin identity: "+consumed.IdentityID,
				"One-time CLI credential (store it now; it is not retrievable):",
				issued.Token)
		}
		return out("Open this one-time enrollment URL in your browser to create",
			"the first Installation Admin's passkey (ADR-0006):",
			"  "+base+"/enroll#"+grant.Token,
			"Expires: "+auth.ISO(grant.ExpiresAt)+". If it lapses, run bootstrap again.")
	}

	// The subject's gate, as issueRecoveryGrant locks it (domain/
	// bootstrap.ts): exclusive when --enable may change the person,
	// shared otherwise; held across the grant and, with --cli-credential,
	// its consumption (which takes the subject shared). Taken before any
	// job is queued, from the daemon's gates (offline, the command's own).
	if id := a.values["--identity"]; id != "" {
		mode := write.Shared
		if a.flags["--enable"] {
			mode = write.Exclusive
		}
		var release func()
		var err error
		if ctx, release, err = env.gates.Acquire(ctx, write.Person(id, mode)); err != nil {
			return fail(err)
		}
		defer release()
	}
	grant, err := svc.IssueRecoveryGrant(ctx, auth.Recovery{IdentityID: a.values["--identity"], Enable: a.flags["--enable"], NewAdmin: a.flags["--new-admin"]})
	if err != nil {
		return fail(err)
	}
	if a.flags["--cli-credential"] {
		consumed, issued, err := svc.ConsumeForCLICredential(ctx, grant.Token, name, "recovery credential")
		if err != nil {
			return fail(err)
		}
		return out("Recovery completed for "+consumed.IdentityID+".",
			"One-time CLI credential (store it now; it is not retrievable):",
			issued.Token)
	}
	return out("Open this one-time recovery URL to enroll a new passkey:",
		"  "+base+"/enroll#"+grant.Token,
		"Expires: "+auth.ISO(grant.ExpiresAt)+".")
}

// conformanceProbe is `varlatchd admin conformance-probe`, in a build with
// the conformance tag only (probe_conformance.go); nil otherwise.
var conformanceProbe func(ctx context.Context, env *hostEnv, args []string, stdout, stderr io.Writer) int

// conformanceWarnings logs a conformance build's warnings at startup
// (redirect_conformance.go); nil in a release.
var conformanceWarnings func(log *slog.Logger)

// conformanceFixture is `varlatchd admin conformance-fixture`, in a build
// with the conformance tag only (fixture_conformance.go); nil otherwise.
var conformanceFixture func(ctx context.Context, env *hostEnv, args []string, stdout, stderr io.Writer) int

// issuer is the base of the enrollment URLs: the public URL as configured,
// else http://localhost and the listener's port, as the TypeScript
// server's issuer.
func issuer(cfg *config.Config) string {
	if cfg.PublicURL != nil {
		return strings.TrimSuffix(cfg.PublicURL.String(), "/")
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		port = "8686"
	}
	return "http://localhost:" + port
}
