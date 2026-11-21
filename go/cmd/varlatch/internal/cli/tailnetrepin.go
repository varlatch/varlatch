// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch tailnet repin` (internal docs/design/go-step6.md, slice 6.2b):
// the host's re-pin of the tailnet node's pin, a front for `varlatchd admin
// tailnet repin` as the `admin` forms are (hostadmin.go). It always asks
// varlatchd for its JSON answer and shows the same text varlatchd shows:
// the pinned and the observed tailnet and what it did or offers. On a
// terminal, without --yes, an offered re-pin (or, with --adopt, an
// adoption) is confirmed with a question, then done with --yes; varlatchd
// records each re-pin as the audit event tailnet.repinned.

const repinUsage = "Usage: varlatch tailnet repin [--yes] [--adopt] [--json] [--config <file>]"

// repinTerminal is whether the run may ask (stdin and stdout are a
// terminal); a variable so the tests can answer.
var repinTerminal = func(r *Run) bool { return isTerminal(r.Stdin) && isTerminal(r.Stdout) }

// tailnetRepin is `tailnet repin`: tailnetCommand (slice 5.7a's) runs it
// first, and it says whether the command line is that form.
func tailnetRepin(r *Run) (bool, error) {
	if len(r.Args) == 0 || r.Args[0] != "repin" {
		return false, nil
	}
	var yes, adopt, asJSON bool
	config := ""
	args := r.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--yes":
			yes = true
		case "--adopt":
			adopt = true
		case "--json":
			asJSON = true
		case "--config":
			if i+1 >= len(args) || args[i+1] == "" {
				return true, UsageErrorWithUsage("varlatch tailnet repin: --config needs a file", "\n"+repinUsage)
			}
			config = args[i+1]
			i++
		case "--dir":
			return true, composeRefusal(r, "tailnet repin")
		default:
			if strings.HasPrefix(a, "-") {
				return true, UsageErrorWithUsage("varlatch tailnet repin: unknown option "+shownArgument(a), "\n"+repinUsage)
			}
			return true, UsageErrorWithUsage("varlatch tailnet repin: unexpected argument "+shownArgument(a), "\n"+repinUsage)
		}
	}
	doc, code, err := r.repinOnce(yes, adopt, "", config)
	if err != nil {
		return true, err
	}
	if !yes && !asJSON && repinTerminal(r) {
		if handled, err := r.confirmRepin(doc, code, adopt, config); handled {
			return true, err
		}
	}
	if asJSON {
		if err := r.printJSON(doc); err != nil {
			return true, err
		}
		if code != 0 {
			return true, ExitWith(code)
		}
		return true, nil
	}
	return true, r.showRepin(doc, code, false)
}

// repinQuestion is the question for an offer in doc, "" when it offers
// nothing to ask about (an adoption is asked about only with --adopt).
func repinQuestion(doc jsjson.Object, adopt bool) string {
	offer, _ := doc.Value("offer").(string)
	if offer == "" {
		return ""
	}
	missing, _ := doc.Value("missing").(bool)
	switch {
	case !missing:
		return "Re-pin the tailnet now and reopen tailnet access?"
	case adopt:
		return "Adopt the observed tailnet as the pin and open tailnet access?"
	}
	return ""
}

// confirmRepin asks about the offer varlatchd showed and, when confirmed,
// runs the re-pin bound to that offer (--offer): varlatchd acts only while
// the pin and the observed tailnet are what was shown. When they changed
// in between (offer-changed), the new ones are shown and asked about once
// more; a second change stops. false when there is nothing to ask.
func (r *Run) confirmRepin(doc jsjson.Object, code int, adopt bool, config string) (bool, error) {
	question := repinQuestion(doc, adopt)
	if question == "" {
		return false, nil
	}
	prompter := newTerminalPrompter(r)
	for asked := 0; ; asked++ {
		// The pinned and the observed tailnet, and what varlatchd says of
		// its offer, whatever its status: an adoption (adoption-needed,
		// status 1) carries the caveat the question rests on.
		if err := r.showRepinLines(doc); err != nil {
			return true, err
		}
		if msg, _ := doc.Value("message").(string); msg != "" {
			if err := r.out(msg + "\n"); err != nil {
				return true, err
			}
		}
		ok, err := prompter.confirm(question, false)
		if err != nil {
			return true, err
		}
		if !ok {
			return true, r.out("Nothing was re-pinned.\n")
		}
		offer, _ := doc.Value("offer").(string)
		if doc, code, err = r.repinOnce(true, adopt, offer, config); err != nil {
			return true, err
		}
		if outcome, _ := doc.Value("outcome").(string); outcome != "offer-changed" {
			return true, r.showRepin(doc, code, true)
		}
		if msg, _ := doc.Value("message").(string); msg != "" {
			if err := r.warn("varlatch tailnet repin: " + msg); err != nil {
				return true, err
			}
		}
		if question = repinQuestion(doc, adopt); question == "" || asked >= 1 {
			// Nothing to offer now, or a second change: what it is now.
			if err := r.showRepinLines(doc); err != nil {
				return true, err
			}
			return true, Fail("varlatch tailnet repin: nothing was re-pinned; run it again to see the tailnet as it is then", code)
		}
		doc = withoutMessage(doc)
	}
}

// withoutMessage is doc without its message: after offer-changed, the
// lines are shown again with the question, not the refusal twice.
func withoutMessage(doc jsjson.Object) jsjson.Object {
	out := make(jsjson.Object, 0, len(doc))
	for _, m := range doc {
		if m.Key != "message" {
			out = append(out, m)
		}
	}
	return out
}

// repinOnce runs `varlatchd admin tailnet repin --json [--yes [--adopt]
// [--offer <token>]]` and returns its answer and status. --adopt reaches
// varlatchd only with --yes: without it, varlatchd shows whether an
// adoption is offered. Without an offer, --yes acts on the observation at
// that moment (scripted use).
func (r *Run) repinOnce(yes, adopt bool, offer, config string) (jsjson.Object, int, error) {
	args := []string{"admin", "tailnet", "repin", "--json"}
	if yes {
		args = append(args, "--yes")
		if adopt {
			args = append(args, "--adopt")
		}
		if offer != "" {
			args = append(args, "--offer", offer)
		}
	}
	answer, said, code, err := r.varlatchd("varlatch tailnet repin", args, config)
	if err != nil {
		return nil, 0, err
	}
	doc, perr := jsjson.Parse(bytes.TrimSpace(answer))
	obj, ok := doc.(jsjson.Object)
	if perr != nil || !ok {
		// No answer to read (varlatchd refused before it: offline, its
		// usage, its configuration): what it said, and its status.
		if err := r.out(string(answer)); err != nil {
			return nil, 0, err
		}
		if err := r.warnLines(said); err != nil {
			return nil, 0, err
		}
		if code == 0 {
			code = ExitFailure
		}
		return nil, 0, ExitWith(code)
	}
	if err := r.warnLines(said); err != nil {
		return nil, 0, err
	}
	return obj, code, nil
}

// showRepin writes varlatchd's text from its answer: the pinned and the
// observed tailnet (left out after a confirmed re-pin, shown before the
// question), then the message, on stderr when the status is not 0.
func (r *Run) showRepin(doc jsjson.Object, code int, afterConfirm bool) error {
	text := func(key string) string { s, _ := doc.Value(key).(string); return s }
	if !afterConfirm {
		if err := r.showRepinLines(doc); err != nil {
			return err
		}
	}
	if msg := text("message"); msg != "" {
		if code != 0 {
			return Fail("varlatch tailnet repin: "+msg, code)
		}
		if err := r.out(msg + "\n"); err != nil {
			return err
		}
	}
	if code != 0 {
		return ExitWith(code)
	}
	return nil
}

// showRepinLines writes the pinned and the observed tailnet, as
// varlatchd's text does.
func (r *Run) showRepinLines(doc jsjson.Object) error {
	text := func(key string) string { s, _ := doc.Value(key).(string); return s }
	return r.out("pinned:   " + text("pinnedText") + "\nobserved: " + text("observedText") + "\n")
}

// varlatchd runs `varlatchd args... [--config file]` (locateVarlatchd's
// varlatchd, with varlatchdEnviron) and returns what it wrote on stdout and
// stderr and its status (a child ended by a signal is 1); a varlatchd that
// cannot be found, may not be run or cannot be started is the error, its
// message starting with prefix.
func (r *Run) varlatchd(prefix string, args []string, config string) (answer, said []byte, code int, err error) {
	path, err := r.locateVarlatchd(prefix)
	if err != nil {
		return nil, nil, 0, err
	}
	if config != "" {
		args = append(slices.Clone(args), "--config", config)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = hostCredentials(varlatchdEnviron(r), config)
	answer, said, err = runChild(cmd)
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, nil, 0, Fail(prefix+": could not run "+path+": "+err.Error(), ExitUnavailable)
		}
		if code = exit.ExitCode(); code < 0 {
			code = ExitFailure
		}
	}
	// varlatchd's 78 for a person who is not root: the configuration, the
	// data directory and the control socket are its service's. Last, after
	// what varlatchd said.
	if code == ExitConfig && runtime.GOOS != "windows" && os.Geteuid() != 0 {
		said = append(bytes.TrimRight(said, "\n"), []byte("\n"+prefix+": the installation's configuration, data directory and control socket are its service's; run this as root (sudo "+prefix+" ...)\n")...)
	}
	return answer, said, code, nil
}

// warnLines writes each line of a child's stderr through the fail-safe.
func (r *Run) warnLines(said []byte) error {
	for _, line := range strings.Split(strings.TrimRight(string(said), "\n"), "\n") {
		if line == "" {
			continue
		}
		if err := r.warn(line); err != nil {
			return err
		}
	}
	return nil
}
