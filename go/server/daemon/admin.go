// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
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
func Admin(args []string, stdout, stderr io.Writer) int { return admin(args, os.Stdin, stdout, stderr) }

func admin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return adminUsage(stderr, "no command")
	}
	sub := args[0]
	conformance := sub == "conformance-probe" && conformanceProbe != nil ||
		sub == "conformance-fixture" && conformanceFixture != nil ||
		sub == "conformance-seed" && conformanceSeed != nil
	if sub != "bootstrap" && sub != "recover" && !conformance {
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
	if !conformance {
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
	var input []byte
	if sub == "conformance-seed" {
		if input, err = io.ReadAll(io.LimitReader(stdin, 1<<16)); err != nil {
			fmt.Fprintf(stderr, "varlatchd admin %s: %v\n", sub, err)
			return ExitFailure
		}
		defer clear(input)
	}
	return route(cfg, append([]string{sub}, rest...), input, stdout, stderr)
}

func adminUsage(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "varlatchd admin: %s\nUsage: varlatchd admin bootstrap [--cli-credential] [--name <name>] | "+
		"varlatchd admin recover --identity <id> [--enable] | --new-admin [--cli-credential] [--name <name>]  (each with [--config <file>])\n", msg)
	return 64
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
	return &hostEnv{cfg: cfg, store: store, rootKEK: rootKEK, gates: write.NewGates()}, ExitOK
}

// runHost runs one host command, in the daemon or offline, with env.
func runHost(ctx context.Context, env *hostEnv, args []string, stdin []byte, stdout, stderr io.Writer) int {
	sub, rest := args[0], args[1:]
	switch {
	case sub == "conformance-probe" && conformanceProbe != nil:
		return conformanceProbe(ctx, env, rest, stdout, stderr)
	case sub == "conformance-fixture" && conformanceFixture != nil:
		return conformanceFixture(ctx, env, rest, stdout, stderr)
	case sub == "conformance-seed" && conformanceSeed != nil:
		return conformanceSeed(ctx, env, rest, stdin, stdout, stderr)
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

// conformanceFixture is `varlatchd admin conformance-fixture`, in a build
// with the conformance tag only (fixture_conformance.go); nil otherwise.
var conformanceFixture func(ctx context.Context, env *hostEnv, args []string, stdout, stderr io.Writer) int

// conformanceSeed is `varlatchd admin conformance-seed`, in a build with the
// conformance tag only (seed_conformance.go); nil otherwise.
var conformanceSeed func(ctx context.Context, env *hostEnv, args []string, stdin []byte, stdout, stderr io.Writer) int

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
