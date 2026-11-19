// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The host commands of a Go installation that are fronts for `varlatchd
// admin` (internal docs/design/go-step6.md, slice 6.2a, decision 2): the
// person-facing `varlatch admin ...` runs `varlatchd admin ...` as a
// separate process for every database or key operation, and shows what it
// printed through the fail-safe. No socket client of its own, and the
// licensing boundary stays a process boundary (G12: varlatch imports
// nothing under go/server).
//
// A Compose installation's host commands are the TypeScript CLI's
// (decision 11): `--dir` names one, and is refused with the command to use.

// adminUsage is the usage of the `admin` forms the Go CLI runs.
const adminUsage = `Usage: varlatch admin backup run [--json] | varlatch admin backup status | varlatch admin backup test-bucket [--json] | varlatch admin backup restore --in <archive> [--backup-key-file <file>] | varlatch admin security reset --org <organization> (--control <name>... | --all) [--json] | varlatch admin unfreeze --org <slug> --confirm <slug> [--json] | varlatch admin outbound check [--allow <value>] [--org <organization>] [--json] | varlatch admin maintenance begin --ttl <duration> | varlatch admin maintenance end <lease id> | varlatch admin maintenance status
Each also takes --config <file>, the installation's varlatchd.conf (default /etc/varlatch/varlatchd.conf).`

// adminForm is one `varlatch admin` form: its words, the options it takes
// (with a value or not), and whether varlatchd always answers it in JSON.
type adminForm struct {
	words    []string
	options  map[string]bool // option -> takes a value
	operands int             // positional arguments after the words
	json     bool            // varlatchd's answer is always a JSON document
}

var adminForms = []adminForm{
	{words: []string{"backup", "run"}, options: map[string]bool{"--json": false}},
	{words: []string{"backup", "status"}, json: true},
	{words: []string{"backup", "test-bucket"}, options: map[string]bool{"--json": false}},
	{words: []string{"backup", "restore"}, options: map[string]bool{"--in": true, "--backup-key-file": true}},
	{words: []string{"security", "reset"}, options: map[string]bool{"--org": true, "--control": true, "--all": false, "--json": false}},
	{words: []string{"unfreeze"}, options: map[string]bool{"--org": true, "--confirm": true, "--json": false}},
	{words: []string{"outbound", "check"}, options: map[string]bool{"--allow": true, "--org": true, "--json": false}},
	{words: []string{"maintenance", "begin"}, options: map[string]bool{"--ttl": true}, json: true},
	{words: []string{"maintenance", "end"}, operands: 1},
	{words: []string{"maintenance", "status"}, json: true},
}

// adminCommand is `admin`'s partial: the forms above. `admin reenroll`
// (slice 6.9) is not built yet; the TypeScript CLI's `backup create` and
// `backup verify` say what a Go installation runs instead.
func adminCommand(r *Run) (bool, error) {
	if len(r.Args) > 0 && r.Args[0] == "reenroll" {
		return false, nil
	}
	if i := slices.Index(r.Args, "--dir"); i >= 0 {
		return true, composeRefusal(r)
	}
	if len(r.Args) >= 2 && r.Args[0] == "backup" && (r.Args[1] == "create" || r.Args[1] == "verify") {
		return true, UsageError("varlatch admin backup " + r.Args[1] + ": a Go installation's backups are `varlatch admin backup run` (it makes the archive and verifies it) and `varlatch admin backup status`; `backup create` and `backup verify` are a Compose installation's, through the TypeScript CLI")
	}
	form, rest, ok := matchAdminForm(r.Args)
	if !ok {
		return true, UsageOnly(adminUsage)
	}
	config, args, err := form.check(rest)
	if err != nil {
		return true, UsageErrorWithUsage("varlatch admin "+strings.Join(form.words, " ")+": "+err.Error(), "\n"+adminUsage)
	}
	return true, r.runVarlatchd(form, append(append([]string{"admin"}, form.words...), args...), config)
}

// matchAdminForm is the form whose words begin args, and what follows.
func matchAdminForm(args []string) (adminForm, []string, bool) {
	for _, f := range adminForms {
		if len(args) >= len(f.words) && slices.Equal(args[:len(f.words)], f.words) {
			return f, args[len(f.words):], true
		}
	}
	return adminForm{}, nil, false
}

// check takes --config out of args and checks the rest is the form's
// options and operands; varlatchd checks the combinations itself (and
// answers 64 with its own usage).
func (f adminForm) check(args []string) (config string, out []string, err error) {
	operands := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--config" {
			if i+1 >= len(args) || args[i+1] == "" {
				return "", nil, errors.New("--config needs a file")
			}
			config = args[i+1]
			i++
			continue
		}
		takesValue, known := f.options[a]
		switch {
		case known && takesValue:
			if i+1 >= len(args) {
				return "", nil, errors.New(a + " needs a value")
			}
			out = append(out, a, args[i+1])
			i++
		case known:
			out = append(out, a)
		case strings.HasPrefix(a, "-"):
			return "", nil, errors.New("unknown option " + shownArgument(a))
		default:
			operands++
			if operands > f.operands {
				return "", nil, errors.New("unexpected argument " + shownArgument(a))
			}
			out = append(out, a)
		}
	}
	if operands < f.operands {
		return "", nil, errors.New("needs the lease id `maintenance begin` printed")
	}
	return config, out, nil
}

// composeRefusal is decision 11's: a Compose installation keeps its
// TypeScript CLI, installed beside the Go one as varlatch-ts.
func composeRefusal(r *Run) error {
	ts := "varlatch-ts"
	for _, dir := range filepath.SplitList(r.Getenv("PATH")) {
		candidate := filepath.Join(dir, "varlatch-ts")
		if dir != "" && filepath.IsAbs(dir) {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				ts = candidate
				break
			}
		}
	}
	return UsageError("varlatch admin: --dir names a Compose installation, which the Go CLI does not manage; run this with the TypeScript CLI, " + ts + ", until `varlatch migrate` moves the installation (ADR-0059 step 7)")
}

// findVarlatchd is the varlatchd the host commands run: the one installed
// beside this varlatch (install.sh --server puts both in one directory),
// else the first on the run's PATH.
func findVarlatchd(pathList string) (string, error) {
	name := "varlatchd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(self); err == nil {
			beside := filepath.Join(filepath.Dir(real), name)
			if info, err := os.Stat(beside); err == nil && info.Mode().IsRegular() {
				return beside, nil
			}
		}
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // as exec.LookPath, never the working directory
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0) {
			return candidate, nil
		}
	}
	return "", errors.New("varlatchd not found")
}

// runVarlatchd runs `varlatchd args... [--config file]` and shows what it
// printed: a JSON document again as JSON.stringify(doc, null, 2) after the
// fail-safe (RedactValue), any other output and every line on stderr
// through the fail-safe. Its exit status is the command's.
func (r *Run) runVarlatchd(form adminForm, args []string, config string) error {
	path, err := findVarlatchd(r.Getenv("PATH"))
	if err != nil {
		return Fail("varlatch admin: no varlatchd beside this varlatch or on PATH; the host commands run a Go installation's varlatchd, so run this on the installation's host (install.sh --server installs both)", ExitUnavailable)
	}
	if config != "" {
		args = append(args, "--config", config)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = environ(r)
	// What varlatchd prints is read whole, then shown through the
	// fail-safe below: nothing of it reaches this process's streams as it
	// is.
	answer, said, err := runChild(cmd)
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return Fail("varlatch admin: could not run "+path+": "+err.Error(), ExitUnavailable)
		}
		code = exit.ExitCode()
		if code < 0 {
			code = ExitFailure // ended by a signal
		}
	}
	if err := r.showVarlatchd(form, args, answer); err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimRight(string(said), "\n"), "\n") {
		if line == "" {
			continue
		}
		if err := r.warn(line); err != nil {
			return err
		}
	}
	if code == ExitConfig && runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := r.warn("varlatch admin: the installation's configuration, data directory and control socket are its service's; run this as root (sudo varlatch admin ...)"); err != nil {
			return err
		}
	}
	if code != 0 {
		return ExitWith(code)
	}
	return nil
}

// showVarlatchd writes varlatchd's standard output: a JSON answer (the
// form always answers in JSON, or --json was given) parsed and printed
// again through RedactValue; anything else as text through the fail-safe.
func (r *Run) showVarlatchd(form adminForm, args []string, out []byte) error {
	if len(out) == 0 {
		return nil
	}
	if form.json || slices.Contains(args, "--json") {
		if doc, err := jsjson.Parse(bytes.TrimSpace(out)); err == nil {
			return r.printJSON(doc)
		}
	}
	return r.out(string(out))
}

// runChild runs cmd and returns what it wrote on its standard output and
// on its standard error, each read whole, and how it ended.
func runChild(cmd *exec.Cmd) (answer, said []byte, err error) {
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(errPipe)
		done <- b
	}()
	answer, _ = io.ReadAll(outPipe)
	said = <-done
	return answer, said, cmd.Wait()
}
