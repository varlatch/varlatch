// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os/exec"
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

// tailnetRepin is `tailnet`'s partial: `tailnet repin`. The rest of
// `tailnet` is slice 5.7a's.
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
	doc, code, err := r.repinOnce(yes, adopt, config)
	if err != nil {
		return true, err
	}
	if !yes && !asJSON && repinTerminal(r) {
		outcome, _ := doc.Value("outcome").(string)
		question := ""
		switch {
		case outcome == "suffix-changed" || outcome == "reopen-offered":
			question = "Re-pin the tailnet now and reopen tailnet access?"
		case outcome == "adoption-needed" && adopt:
			question = "Adopt the observed tailnet as the pin and open tailnet access?"
		}
		if question != "" {
			// The pinned and the observed tailnet, and what varlatchd offers;
			// an adoption's refusal is the question instead.
			if err := r.showRepinLines(doc); err != nil {
				return true, err
			}
			if msg, _ := doc.Value("message").(string); code == 0 && msg != "" {
				if err := r.out(msg + "\n"); err != nil {
					return true, err
				}
			}
			ok, err := newTerminalPrompter(r).confirm(question, false)
			if err != nil {
				return true, err
			}
			if !ok {
				return true, r.out("Nothing was re-pinned.\n")
			}
			if doc, code, err = r.repinOnce(true, adopt, config); err != nil {
				return true, err
			}
			return true, r.showRepin(doc, code, true)
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

// repinOnce runs `varlatchd admin tailnet repin --json [--yes [--adopt]]`
// and returns its answer and status. --adopt reaches varlatchd only with
// --yes: without it, varlatchd shows whether an adoption is offered.
func (r *Run) repinOnce(yes, adopt bool, config string) (jsjson.Object, int, error) {
	args := []string{"admin", "tailnet", "repin", "--json"}
	if yes {
		args = append(args, "--yes")
		if adopt {
			args = append(args, "--adopt")
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
	cmd.Env = varlatchdEnviron(r)
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
