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
)

// Admin runs `varlatchd admin bootstrap|recover` (ADR-0010, ADR-0020): host
// exec authority, the Infrastructure Operator's front door. Each prints
// exactly what the TypeScript server's admin CLI prints (src/cli.ts), which
// the conformance harness parses: an enrollment URL on a line of its own,
// or, with --cli-credential, a one-time CLI credential on the last line.
//
//	varlatchd admin bootstrap [--cli-credential [--name <name>]] [--config <file>]
//	varlatchd admin recover (--identity <id> [--enable] | --new-admin) [--cli-credential [--name <name>]] [--config <file>]
//
// They open the database next to a running varlatchd (SQLite's own
// locking orders the two writers), and refuse with the wrong Root KEK.
// Exit 0 on success, 1 on a refusal or failure, 64 on a usage error, 78 on
// a configuration error.
func Admin(args []string, stdout, stderr io.Writer) int {
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "varlatchd admin: %s\nUsage: varlatchd admin bootstrap [--cli-credential] [--name <name>] | "+
			"varlatchd admin recover --identity <id> [--enable] | --new-admin [--cli-credential] [--name <name>]  (each with [--config <file>])\n", msg)
		return 64
	}
	if len(args) == 0 {
		return usage("no command")
	}
	sub := args[0]
	if sub != "bootstrap" && sub != "recover" {
		return usage("unknown command " + sub)
	}
	path := config.DefaultPath
	values := map[string]string{}
	flags := map[string]bool{}
	valued := map[string]bool{"--config": true, "--name": true, "--identity": true}
	allowed := map[string]bool{"--config": true, "--name": true, "--cli-credential": true}
	if sub == "recover" {
		allowed["--identity"], allowed["--enable"], allowed["--new-admin"] = true, true, true
	}
	for rest := args[1:]; len(rest) > 0; {
		a := rest[0]
		if !allowed[a] {
			return usage(sub + ": unknown argument " + a)
		}
		if valued[a] {
			if len(rest) < 2 {
				return usage(sub + ": " + a + " needs a value")
			}
			values[a], rest = rest[1], rest[2:]
			continue
		}
		flags[a], rest = true, rest[1:]
	}
	if p, ok := values["--config"]; ok {
		path = p
	}
	if sub == "recover" && (values["--identity"] == "") == !flags["--new-admin"] {
		return usage("Usage: varlatchd admin recover --identity <id> [--enable] | --new-admin")
	}

	fail := func(err error) int {
		fmt.Fprintf(stderr, "varlatchd admin %s: %s\n", sub, err.Error())
		return ExitFailure
	}
	cfg, err := config.Load(path)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			fmt.Fprintf(stderr, "varlatchd admin %s: the configuration file %s is not valid: %v\n", sub, path, err)
			return ExitConfig
		}
		return fail(err)
	}
	material, err := os.ReadFile(cfg.RootKEKFile)
	if err != nil {
		return fail(fmt.Errorf("cannot read the Root KEK file: %w", err))
	}
	rootKEK, err := envelope.ParseRootKEK(string(material))
	clear(material)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin %s: the Root KEK file does not hold a Root KEK: %v\n", sub, err)
		return ExitConfig
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: cfg.DatabasePath()})
	if err != nil {
		return fail(fmt.Errorf("cannot open the database: %w", err))
	}
	defer store.Close()
	if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
		return fail(err)
	}
	inst, _, err := ensureInstallation(ctx, store, rootKEK)
	if err != nil {
		return fail(err)
	}
	if !verify(rootKEK, inst) {
		fmt.Fprintf(stderr, "varlatchd admin %s: the configured Root KEK does not open this installation's canary\n", sub)
		return ExitConfig
	}
	svc := auth.New(store, auth.Options{PublicURL: cfg.PublicURL})
	base := issuer(cfg)
	name := values["--name"]
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
		if flags["--cli-credential"] {
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

	grant, err := svc.IssueRecoveryGrant(ctx, auth.Recovery{IdentityID: values["--identity"], Enable: flags["--enable"], NewAdmin: flags["--new-admin"]})
	if err != nil {
		return fail(err)
	}
	if flags["--cli-credential"] {
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
