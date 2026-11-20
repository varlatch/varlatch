// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/setup"
)

// `varlatch setup` (internal docs/design/go-step6.md, decision 7, slice
// 6.4a): a Go installation on this host, from an empty one to a running
// unit. It changes the host (a user, /etc/varlatch, /var/lib/varlatch,
// the unit), so it runs as root and says so before anything. The work is
// package setup's; this reads the command line and the answers file, asks
// on a terminal, and shows the keys there.
//
// A Compose installation's setup is the TypeScript CLI's (decision 11):
// --dir names one, and is refused with the command to use.

// setupUsage is the Go installation's setup: what `varlatch help setup`
// prints (an accepted difference, go/README.md: the TypeScript usage is a
// Compose installation's).
const setupUsage = `Usage:
  sudo varlatch setup [--answers <file>] [--ingress public|proxy|localhost|tailnet] [--public-url <url>]
                      [--listen <host:port>] [--trusted-proxies <list>]
                      [--listen-https <host:port>] [--listen-http-redirect <host:port>|off]
                      [--acme-email <address>] [--acme-ca <url>] [--acme-ca-root <file>]
                      [--tailnet-hostname <name>] [--tailnet-tags <tags>] [--tailnet-port <port>]
                      [--tailnet-auth-key-file <file>]
                      [--backups host|bucket] [--backup-destinations-file <file>] [--backup-destination <name>]
                      [--root-kek-out <file> --backup-key-out <file>] [--accept-slow-disk] [--accept-existing-user]
               (a Go installation on this host: the varlatch user, /etc/varlatch/varlatchd.conf, the Root KEK and
                the backup key (root, 0600; shown once on a terminal, or, without one, written to the files
                --root-kek-out and --backup-key-out name), the data directory after an fsync probe of its disk, and
                the varlatchd unit started. Every question has its flag (--name value or --name=value); --answers
                names a JSON file of them (the same names, as publicUrl). A varlatch user that exists already must
                be a system account, or --accept-existing-user uses it anyway. A rerun continues where setup stopped
                and changes nothing once done; its journal is /etc/varlatch/setup.json. A Compose installation's
                setup is the TypeScript CLI's, varlatch-ts)`

// SetupHelp is setupUsage, for the transcripts' accepted difference.
const SetupHelp = setupUsage

// setupArgs is setup's command line.
type setupArgs struct {
	given                  setup.Answers
	kekOut, bekOut         string
	acceptSlow, acceptUser bool
}

// parseSetupArgs reads setup's command line and the answers file it names.
func parseSetupArgs(argv []string) (setupArgs, error) {
	var p setupArgs
	var answersFile string
	usage := func(msg string) error { return UsageErrorWithUsage("varlatch setup: "+msg, "\n"+setupUsage) }
	for i := 0; i < len(argv); i++ {
		// --name=value is --name value, split at the first "=", as the
		// other commands' options are.
		a, attached, hasValue := argv[i], "", false
		if strings.HasPrefix(a, "--") {
			if name, v, ok := strings.Cut(a, "="); ok {
				a, attached, hasValue = name, v, true
			}
		}
		value := func() (string, error) {
			if hasValue {
				if attached == "" {
					return "", usage(a + " needs a value")
				}
				return attached, nil
			}
			if i+1 >= len(argv) || argv[i+1] == "" {
				return "", usage(a + " needs a value")
			}
			i++
			return argv[i], nil
		}
		switch {
		case a == "--dir":
			return p, UsageError("varlatch setup: --dir names a Compose installation, which the Go CLI does not set up; run varlatch-ts setup --dir <directory> for one")
		case a == "--restore":
			return p, UsageError("varlatch setup --restore is not in this build of the Go CLI yet (slice 6.4c)")
		case (a == "--accept-slow-disk" || a == "--accept-existing-user") && hasValue:
			return p, usage(a + " takes no value")
		case a == "--accept-slow-disk":
			p.acceptSlow = true
		case a == "--accept-existing-user":
			p.acceptUser = true
		case a == "--answers" || a == "--root-kek-out" || a == "--backup-key-out":
			v, err := value()
			if err != nil {
				return p, err
			}
			switch a {
			case "--answers":
				answersFile = v
			case "--root-kek-out":
				p.kekOut = v
			default:
				p.bekOut = v
			}
		case strings.HasPrefix(a, "--"):
			f, ok := setup.FlagNamed(strings.TrimPrefix(a, "--"))
			if !ok {
				return p, usage("unknown option " + shownArgument(argv[i]))
			}
			v, err := value()
			if err != nil {
				return p, err
			}
			f.Set(&p.given, v)
		default:
			return p, usage("unexpected argument " + shownArgument(a))
		}
	}
	if answersFile != "" {
		fromFile, err := readAnswers(answersFile)
		if err != nil {
			return p, err
		}
		// A flag wins over the file; the two never disagree silently.
		if differ := p.given.Merge(fromFile); len(differ) > 0 {
			return p, usage("--" + strings.Join(differ, ", --") + " differs from the answers file " + answersFile)
		}
	}
	if (p.kekOut == "") != (p.bekOut == "") {
		return p, usage("--root-kek-out and --backup-key-out go together")
	}
	return p, nil
}

// setupCommand is `setup`'s partial: every form of it.
func setupCommand(r *Run) (bool, error) {
	args, err := parseSetupArgs(r.Args)
	if err != nil {
		return true, err
	}
	if runtime.GOOS != "linux" {
		return true, Fail("varlatch setup: a Go installation is set up on a Linux host with systemd", ExitFailure)
	}
	if os.Geteuid() != 0 {
		return true, Fail("varlatch setup changes this host (the varlatch user, /etc/varlatch, /var/lib/varlatch, the unit): run it as root: sudo varlatch setup", ExitDenied)
	}
	varlatchd, err := r.locateVarlatchd("varlatch setup")
	if err != nil {
		return true, err
	}
	o := setup.Options{
		Host:  setup.SystemHost{Varlatchd: varlatchd, Env: varlatchdEnviron(r)},
		Given: args.given, RootKEKOut: args.kekOut, BackupKeyOut: args.bekOut, AcceptSlowDisk: args.acceptSlow, AcceptExistingUser: args.acceptUser,
		Say:       func(line string) error { return r.out(line + "\n") },
		StopAfter: r.Getenv("VARLATCH_SETUP_STOP_AFTER"),
	}
	if isTerminal(r.Stdin) && isTerminal(r.Stdout) {
		o.Ask = setupAsker{newTerminalPrompter(r)}
		o.ShowKeys = func(kek, bek []byte) error { return r.showKeys(kek, bek) }
	}
	err = setup.Run(context.Background(), o)
	var usageErr *setup.UsageError
	switch {
	case err == nil:
		return true, r.out("Setup is done: the installation runs. The first administrator comes next.\n")
	case errors.Is(err, setup.ErrStopped):
		return true, Fail("varlatch setup: stopped after "+o.StopAfter+" (VARLATCH_SETUP_STOP_AFTER); run setup again to continue", ExitTempfail)
	case errors.As(err, &usageErr), errors.Is(err, setup.ErrNotAnswered):
		return true, UsageError("varlatch " + strings.TrimPrefix(err.Error(), "setup: "))
	case errors.Is(err, errInputEnded):
		return true, Fail("varlatch setup: the input ended before an answer; run setup again to continue", ExitFailure)
	default:
		return true, Fail("varlatch "+strings.TrimPrefix(err.Error(), "setup: "), ExitFailure)
	}
}

// readAnswers reads an answers file: a JSON object of answers, nothing
// else.
func readAnswers(path string) (setup.Answers, error) {
	var a setup.Answers
	raw, err := os.ReadFile(path)
	if err != nil {
		return a, Fail("varlatch setup: cannot read the answers file "+filepath.Clean(path)+": "+err.Error(), ExitFailure)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, UsageError("varlatch setup: the answers file " + filepath.Clean(path) + " is not a JSON object of answers: " + err.Error())
	}
	return a, nil
}

// showKeys shows the two keys on the terminal, once, with what to do with
// them (setup checks they are kept with 6.4b).
func (r *Run) showKeys(kek, bek []byte) error {
	return r.out("\nThe installation's two keys. Store each in your password manager now, off this host: without them,\n" +
		"no backup of this installation can ever be restored. They are shown this once; setup keeps no other copy\n" +
		"than the unit's own, root-only, in /etc/varlatch.\n\n" +
		"  Root KEK:   " + string(kek) + "\n" +
		"  Backup key: " + string(bek) + "\n\n")
}

// setupAsker is the terminal prompter as package setup asks.
type setupAsker struct{ p *terminalPrompter }

func (a setupAsker) Choose(q string, options []string, preselected int) (int, error) {
	return a.p.choose(q, options, preselected)
}
func (a setupAsker) Confirm(q string, defaultYes bool) (bool, error) {
	return a.p.confirm(q, defaultYes)
}
func (a setupAsker) Text(q, defaultValue string) (string, error) { return a.p.text(q, defaultValue) }
