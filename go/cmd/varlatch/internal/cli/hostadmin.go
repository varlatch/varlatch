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

// adminUsage is the usage of the `admin` forms the Go CLI runs: what
// `varlatch help admin` and `varlatch admin --help` print (an accepted
// difference, go/README.md: the TypeScript usage is a Compose
// installation's), and what a usage error adds.
const adminUsage = `Usage:
  varlatch admin backup run [--json]
  varlatch admin backup status
  varlatch admin backup test-bucket [--json]
  varlatch admin backup restore --in <archive> [--backup-key-file <file>]
  varlatch admin security reset --org <organization> (--control <name>... | --all) [--json]
  varlatch admin unfreeze --org <slug> --confirm <slug> [--json]
  varlatch admin outbound check [--allow <value>] [--org <organization>] [--json]
  varlatch admin maintenance begin --ttl <duration>
  varlatch admin maintenance end <lease id>
  varlatch admin maintenance status
  varlatch admin reenroll (--all | --identity <id>...) [--hours <1-168>]
               (a Go installation's host commands: each runs varlatchd admin with the same words on this host,
                as root; each also takes --config <file>, the installation's varlatchd.conf, default
                /etc/varlatch/varlatchd.conf. A Compose installation's are the TypeScript CLI's, varlatch-ts)`

// AdminHelp is adminUsage, for the transcripts' accepted difference.
const AdminHelp = adminUsage

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

// adminCommand is `admin`'s partial: the forms above, and `admin
// reenroll` (slice 6.9, move.go); the TypeScript CLI's `backup create` and
// `backup verify` say what a Go installation runs instead.
func adminCommand(r *Run) (bool, error) {
	if len(r.Args) > 0 && r.Args[0] == "reenroll" {
		return true, reenrollCommand(r)
	}
	if i := slices.Index(r.Args, "--dir"); i >= 0 {
		return true, composeRefusal(r, "admin")
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
func composeRefusal(r *Run, command string) error {
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
	return UsageError("varlatch " + command + ": --dir names a Compose installation, which the Go CLI does not manage; run this with the TypeScript CLI, " + ts + ", until `varlatch migrate` moves the installation (ADR-0059 step 7)")
}

// findVarlatchd is the varlatchd the host commands run: the one installed
// beside this varlatch (install.sh --server puts both in one directory;
// self is this executable, a symbolic link to it followed), else the first
// on pathList. As root (root), one found on pathList must be one only
// root can change, else it is refused (*unsafeVarlatchd): a PATH entry an
// unprivileged account can write must not get its program run as root.
func findVarlatchd(self, pathList string, root bool) (string, error) {
	name := "varlatchd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self != "" {
		if real, err := filepath.EvalSymlinks(self); err == nil {
			if beside := filepath.Join(filepath.Dir(real), name); isExecutableFile(beside) {
				return beside, nil
			}
		}
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // as exec.LookPath, never the working directory
		}
		candidate := filepath.Join(dir, name)
		if !isExecutableFile(candidate) {
			continue
		}
		if !root {
			return candidate, nil
		}
		// The file, the directory it is in, and the PATH entry that led
		// to it (which may hold a symbolic link to it): whoever can write
		// any of them chooses what runs. The file run is the one checked.
		// A window remains between the check and the exec: whoever can
		// write the parent of a directory checked here (someone other than
		// root) could rename it in between. It is accepted: os/exec has no
		// fexecve to run the very file that was checked.
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", &unsafeVarlatchd{path: candidate, why: "it cannot be resolved"}
		}
		for _, p := range []string{real, filepath.Dir(real), dir} {
			if why := onlyRootCanChange(p); why != "" {
				return "", &unsafeVarlatchd{path: p, why: why}
			}
		}
		return real, nil
	}
	return "", errors.New("varlatchd not found")
}

// unsafeVarlatchd is findVarlatchd's refusal of a varlatchd on PATH, as
// root: path (the program or a directory on the way to it) and why.
type unsafeVarlatchd struct{ path, why string }

func (e *unsafeVarlatchd) Error() string { return e.path + " " + e.why }

// isExecutableFile is a regular file this system would run: on Unix, with
// an execute bit.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0)
}

// onlyRootCanChange is why root must not trust path ("" when it may): it
// is writable by its group or by others, or it is not owned by root.
func onlyRootCanChange(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "cannot be checked"
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "is writable by its group or by others"
	}
	if uid, ok := fileOwner(info); ok && uid != 0 {
		return "is not owned by root"
	}
	return ""
}

// asRoot is whether this process runs as root (never on Windows, where
// os.Geteuid is -1); a variable so the tests can be root.
var asRoot = func() bool { return os.Geteuid() == 0 }

// locateVarlatchd is findVarlatchd for this run, with its refusals as the
// command's: 69 when there is none, 78 when root may not run the one on
// PATH. prefix names the command ("varlatch admin").
func (r *Run) locateVarlatchd(prefix string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	path, err := findVarlatchd(self, r.Getenv("PATH"), asRoot())
	var unsafe *unsafeVarlatchd
	switch {
	case err == nil:
		return path, nil
	case errors.As(err, &unsafe):
		return "", Fail(prefix+": not running the varlatchd on PATH as root: "+Printable(unsafe.path)+" "+unsafe.why+"; as root, the host commands run the varlatchd installed beside this varlatch, or one on PATH that only root can change", ExitConfig)
	default:
		return "", Fail(prefix+": no varlatchd beside this varlatch or on PATH; the host commands run a Go installation's varlatchd, so run this on the installation's host (install.sh --server installs both)", ExitUnavailable)
	}
}

// varlatchdEnviron is the run's environment for varlatchd, without the
// credentials a varlatch run may hold in VARLATCH_* variables: no fronted
// form reads them, so varlatchd never gets them.
func varlatchdEnviron(r *Run) []string {
	var out []string
	for _, kv := range environ(r) {
		name, _, _ := strings.Cut(kv, "=")
		if isCredentialVariable(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// hostCredentials: the unit hands varlatchd its keys as credentials
// (CREDENTIALS_DIRECTORY); a host command run as root, outside the unit,
// finds them where setup wrote them, beside the configuration. So
// CREDENTIALS_DIRECTORY is the configuration's directory when the run set
// none and the Root KEK is there (a person who may not look there gets
// none, and varlatchd says what it lacks). Only a directory's name: no
// key goes into the environment.
func hostCredentials(env []string, config string) []string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "CREDENTIALS_DIRECTORY=") {
			return env
		}
	}
	if config == "" {
		config = "/etc/varlatch/varlatchd.conf"
	}
	dir := filepath.Dir(config)
	if _, err := os.Stat(filepath.Join(dir, "root-kek")); err != nil {
		return env
	}
	return append(env, "CREDENTIALS_DIRECTORY="+dir)
}

// isCredentialVariable is whether name is a VARLATCH_* variable that holds
// a credential: VARLATCH_TOKEN, VARLATCH_OIDC_TOKEN,
// VARLATCH_KEK_PASSPHRASE and any other named for a token, passphrase,
// password, secret, credential or key (Windows names in any case).
func isCredentialVariable(name string) bool {
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, "VARLATCH_") {
		return false
	}
	for _, word := range []string{"TOKEN", "PASSPHRASE", "PASSWORD", "SECRET", "CREDENTIAL"} {
		if strings.Contains(upper, word) {
			return true
		}
	}
	return strings.HasSuffix(upper, "_KEY")
}

// runVarlatchd runs `varlatchd args... [--config file]` and shows what it
// printed: a JSON document again as JSON.stringify(doc, null, 2) after the
// fail-safe (RedactValue), any other output and every line on stderr
// through the fail-safe. Its exit status is the command's.
func (r *Run) runVarlatchd(form adminForm, args []string, config string) error {
	answer, said, code, err := r.varlatchd("varlatch admin", args, config)
	if err != nil {
		return err
	}
	if err := r.showVarlatchd(form, args, answer); err != nil {
		return err
	}
	if err := r.warnLines(said); err != nil {
		return err
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
