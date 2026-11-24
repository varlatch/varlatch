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
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/freeze"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/servecli"
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
//	varlatchd admin bootstrap [--cli-credential [--name <name>]] [--revoke-unused] [--config <file>]
//	varlatchd admin recover (--identity <id> [--enable] | --new-admin) [--cli-credential [--name <name>]] [--revoke-unused] [--config <file>]
//
// --revoke-unused (setup's reissue) first revokes the bootstrap and recovery
// links issued before and never used, in the same write job; the issued
// event's metadata counts them (revokedUnused).
//
// They refuse with the wrong Root KEK. Exit 0 on success, 1 on a refusal
// or failure, 64 on a usage error, 78 on a configuration error.
func Admin(args []string, stdout, stderr io.Writer) int { return admin(args, stdout, stderr) }

func admin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return adminUsage(stderr, "no command")
	}
	sub := args[0]
	if conformanceSignRelease != nil {
		if code, handled := conformanceSignRelease(args, stdout, stderr); handled {
			return code
		}
	}
	conformance := sub == "conformance-probe" && conformanceProbe != nil ||
		sub == "conformance-fixture" && conformanceFixture != nil
	operator := sub == "security" || sub == "unfreeze"
	backup := sub == "backup" || sub == "maintenance"
	keys := sub == "kek" || sub == "custody"
	move := isMoveCommand(sub) || sub == "config"
	if sub != "bootstrap" && sub != "recover" && sub != "outbound" && sub != "audit-export" && sub != "tailnet" && sub != "doctor" && sub != "bootstrap-status" && sub != "schema" && sub != "migrate" && sub != "certificate" && sub != "status" && sub != "release-check" && !conformance && !operator && !backup && !keys && !move {
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
	// Run by hand outside the unit, as root: the keys beside the
	// configuration, as the unit hands them (config.HostEnv).
	env := config.HostEnv(os.Getenv, path, adminAsRoot())
	// In the single-container image, admin refuses a key in its
	// environment as serve does (lib/keyenv): the keys the configuration
	// loads, as far as they can be read (those it names, and the
	// credentials directory's), and the key variable names.
	if os.Getenv(keyenv.ImageMarker) != "" {
		keys := keyenv.Configured(path, env("CREDENTIALS_DIRECTORY"))
		why := keyenv.Refusal(os.Environ(), keys...)
		for _, k := range keys {
			clear(k.Bytes)
		}
		if why != "" {
			fmt.Fprintln(stderr, "varlatchd admin: "+why)
			return ExitConfig
		}
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
	case sub == "bootstrap-status":
		if len(rest) != 0 {
			fmt.Fprintln(stderr, "Usage: varlatchd admin bootstrap-status [--config <file>]")
			return 64
		}
	case sub == "doctor":
		if _, msg := doctorArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "schema":
		if _, _, msg := schemaArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "status":
		if _, msg := statusArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "release-check":
		if _, msg := releaseCheckArgs(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "migrate":
		if _, msg := parseMigrate(rest); msg != "" {
			fmt.Fprintln(stderr, msg)
			return 64
		}
	case sub == "certificate":
		if _, msg := certificateArgs(rest); msg != "" {
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
	case sub == "config":
		if len(rest) != 1 || rest[0] != "check" {
			fmt.Fprintln(stderr, configCheckUsage)
			return 64
		}
	case move:
		// Checked here, so a usage error never reaches the daemon.
		if msg := moveUsage(sub, rest); msg != "" {
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
	cfg, err := config.LoadHost(path, env)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			fmt.Fprintf(stderr, "varlatchd admin %s: the configuration file %s is not valid: %v\n", sub, path, err)
			return ExitConfig
		}
		fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, err.Error())
		return ExitFailure
	}
	if status, started := withRootsOutput(cfg, sub, rest, stdout, stderr); started {
		return status
	}
	if !staysRoot(cfg, sub, rest) {
		if err := becomeOwner(cfg, func() { keepForOwner(cfg, sub, rest) }, stderr); err != nil {
			fmt.Fprintf(stderr, "varlatchd admin %s: %v\n", sub, err)
			return ExitConfig
		}
	}
	// As the user the command goes on as, and before any command opens the
	// database (storage.Open refuses, with the reason, when there is no
	// place; a command that only reads goes on). Not root's files in another
	// user's data directory: a command that stays root has the place of the
	// database it opens (storage.Open), if it opens one.
	if ownDataDir(cfg) {
		_, _ = storage.PrepareTemp(cfg.DataDir)
	}
	switch {
	case sub == "config":
		return runConfigCheck(cfg, stdout, stderr)
	case sub == "outbound":
		return runOutboundCheck(cfg, path, rest, stdout, stderr)
	case sub == "kek":
		return runKek(cfg, rest, os.Stdin, stdout, stderr)
	case sub == "custody" && rest[0] == "status":
		return runCustodyStatus(cfg, stdout, stderr)
	case sub == "certificate" && rest[0] == "issuances":
		return runCertificateIssuances(cfg, rest, time.Now(), stdout, stderr)
	case sub == "tailnet" && rest[0] == "probe-name":
		return runTailnetProbe(cfg, rest, stdout, stderr)
	case sub == "tailnet" && (rest[0] == "enroll" || rest[0] == "reaches" || rest[0] == "take-name"):
		c, _ := nodeArgs(rest)
		switch c.op {
		case "enroll":
			return runTailnetEnroll(cfg, c, stdout, stderr)
		case "take-name":
			return runTailnetTakeName(cfg, c, stdout, stderr)
		}
		return runTailnetReaches(cfg, c, stdout, stderr)
	case sub == "bootstrap-status":
		return runBootstrapStatus(cfg, stdout, stderr)
	case sub == "doctor":
		asJSON, _ := doctorArgs(rest)
		return runDoctor(cfg, path, asJSON, stdout, stderr)
	case sub == "backup" && rest[0] == "restore":
		return restoreOffline(cfg, rest[1:], stdout, stderr)
	case sub == "schema":
		return runSchema(cfg, rest, stdout, stderr)
	case sub == "migrate" && (rest[0] == "open" || rest[0] == "barrier" || rest[0] == "release"):
		// The live open, and the reverse's barrier: through the running
		// daemon, whose admission holds the migration's gate; offline, on
		// the data directory.
		return route(cfg, append([]string{sub}, rest...), stdout, stderr)
	case sub == "migrate":
		return runMigrate(cfg, rest, os.Stdin, stdout, stderr)
	case sub == "status":
		return statusOnline(cfg, rest, stdout, stderr)
	case sub == "release-check":
		return runReleaseCheck(cfg, rest, stdout, stderr)
	}
	return route(cfg, append([]string{sub}, rest...), stdout, stderr)
}

// adminAsRoot is whether admin runs as root (never on Windows, where
// os.Geteuid is -1); a variable so the tests can be root.
var adminAsRoot = func() bool { return os.Geteuid() == 0 }

func adminUsage(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "varlatchd admin: %s\nUsage: varlatchd admin bootstrap [--cli-credential] [--name <name>] [--revoke-unused] | varlatchd admin bootstrap-status | "+
		"varlatchd admin recover --identity <id> [--enable] | --new-admin [--cli-credential] [--name <name>] [--revoke-unused] | "+
		"varlatchd admin security reset ... | varlatchd admin unfreeze ... | varlatchd admin backup run|status|restore|test-bucket | varlatchd admin maintenance begin|end|status | "+
		"varlatchd admin kek verify|export|restore|split|combine | varlatchd admin custody attest|status | varlatchd admin outbound check | "+
		"varlatchd admin audit-export discard-plan --export <id> --reason <expired|unsupported-format> | varlatchd admin tailnet repin [--yes [--adopt] [--offer <token>]] [--json] | "+
		"varlatchd admin schema status|upgrade [--json] [--database <file>] | varlatchd admin doctor [--json] | varlatchd admin certificate issuances [--all] [--json]|record --attempts <json> | "+
		"varlatchd admin migrate import|check|export --reverse|keys|state|discard|open|barrier|release | "+
		"varlatchd admin status [--json] | varlatchd admin release-check record --repo <owner/name> (--version <version> [--published-at <time>] | --failed <reason>) | "+
		"varlatchd admin reenroll (--all | --identity <id>...) [--hours <1-168>] [--json] | varlatchd admin public-url-changed --from <url> | "+
		"varlatchd admin move-facts | varlatchd admin config check  (each with [--config <file>])\n", msg)
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
	allowed := map[string]bool{"--name": true, "--cli-credential": true, "--revoke-unused": true}
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
	material, err := preread.ReadFile(cfg.RootKEKFile)
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
// only reads), doctor and status (which only read), migrate (which
// manages its own gate), and move-facts, which only reads.
func writes(sub string) bool {
	return sub != "backup" && sub != "maintenance" && sub != "doctor" && sub != "status" && sub != "migrate" && sub != "move-facts"
}

// runHost runs one host command, in the daemon or offline, with env. A
// command that writes enters the maintenance admission first, before any
// gate or job, and is counted until it ends; while a gate is open it is
// refused, as the TypeScript admin CLI refuses it.
func runHost(ctx context.Context, env *hostEnv, args []string, stdout, stderr io.Writer) int {
	sub, rest := args[0], args[1:]
	// The node's handoff commands write no installation data, and run under
	// the migration's gate, which they are part of.
	if writes(sub) && !isNodeCmd(rest) && env.admission != nil {
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
	case sub == "tailnet" && isNodeCmd(rest):
		return runTailnetNode(ctx, env, rest, stdout, stderr)
	case sub == "tailnet":
		return runTailnetRepin(ctx, env, rest, stdout, stderr)
	case sub == "doctor":
		return runDoctorLive(ctx, env, rest, stdout, stderr)
	case sub == "status":
		return runStatus(ctx, env, rest, stdout, stderr)
	case sub == "migrate" && len(rest) > 0 && rest[0] == "barrier":
		return runMigrateBarrier(ctx, env, rest, stdout, stderr)
	case sub == "migrate" && len(rest) > 0 && rest[0] == "release":
		return runMigrateRelease(env, rest, stdout, stderr)
	case sub == "migrate":
		return runMigrateOpen(env, rest, stdout, stderr)
	case sub == "certificate":
		return runCertificateRecord(ctx, env, rest, stdout, stderr)
	case isMoveCommand(sub):
		return runMoveCommand(ctx, env, sub, rest, stdout, stderr)
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
		grant, err := svc.IssueBootstrapGrantRevoking(ctx, a.flags["--revoke-unused"])
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
	grant, err := svc.IssueRecoveryGrant(ctx, auth.Recovery{IdentityID: a.values["--identity"], Enable: a.flags["--enable"], NewAdmin: a.flags["--new-admin"], RevokeUnused: a.flags["--revoke-unused"]})
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

// conformanceCLIRelease, set only in a conformance build, points
// serve_cli at a release the harness signed with a test Sigstore
// (VARLATCH_CONFORMANCE_CLI_RELEASE) instead of github.com's.
var conformanceCLIRelease func(o *servecli.Options, log *slog.Logger)

// conformanceSignRelease is `varlatchd admin conformance-sign-release`,
// in a conformance build only (servecli_conformance.go): it needs no
// installation. It answers whether args name it (the command's name is
// the conformance file's alone, so a release binary does not hold it).
var conformanceSignRelease func(args []string, stdout, stderr io.Writer) (code int, handled bool)

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
