// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch doctor` (internal docs/design/go-step6.md, slice 6.5): a Go
// installation's health, a front for `varlatchd admin doctor --json` as
// the admin forms are (hostadmin.go, decision 2). varlatchd reads the
// host and asks the running varlatchd; this adds what the CLI knows
// (whether varlatchd answered, whether both binaries are one release, and
// varlatchd's), and shows the
// report through the fail-safe. It reads, never writes. Exit 1 when a
// mandatory check fails.
//
// A Compose installation's doctor is the TypeScript CLI's (decision 11):
// --dir names one, and is refused with the command to use.

// doctorUsage is the usage of the Go installation's doctor: what `varlatch
// help doctor` prints (an accepted difference, go/README.md: the
// TypeScript usage is a Compose installation's).
const doctorUsage = `Usage:
  varlatch doctor [--json] [--config <file>]
               (a Go installation's health on this host, read only: readiness, the configuration, the data
                directory's and the key files' modes, free space, the disk's fsync latency, the clock, the WAL and
                its checkpoints, the public certificate, the tailnet pin, backups and custody attestations, each
                pass, fail or unknown with what to do; exit 1 when a mandatory check fails. Some checks need root:
                sudo varlatch doctor. --config names the installation's varlatchd.conf, default
                /etc/varlatch/varlatchd.conf. A Compose installation's doctor is the TypeScript CLI's, varlatch-ts)`

// DoctorHelp is doctorUsage, for the transcripts' accepted difference.
const DoctorHelp = doctorUsage

// doctorCheck is one check of the report.
type doctorCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
	Remedy string `json:"remedy,omitempty"`
}

// doctorReport is varlatchd's report, and this command's.
type doctorReport struct {
	Via    string          `json:"via"`
	Facts  json.RawMessage `json:"facts"`
	Checks []doctorCheck   `json:"checks"`
}

// doctorCommand is `doctor`'s partial: every form of it.
func doctorCommand(r *Run) (bool, error) {
	asJSON, config := false, ""
	for i := 0; i < len(r.Args); i++ {
		switch a := r.Args[i]; a {
		case "--json":
			asJSON = true
		case "--config":
			if i+1 >= len(r.Args) || r.Args[i+1] == "" {
				return true, UsageErrorWithUsage("varlatch doctor: --config needs a file", "\n"+doctorUsage)
			}
			config = r.Args[i+1]
			i++
		case "--dir":
			return true, doctorComposeRefusal(r)
		default:
			if strings.HasPrefix(a, "-") {
				return true, UsageErrorWithUsage("varlatch doctor: unknown option "+shownArgument(a), "\n"+doctorUsage)
			}
			return true, UsageErrorWithUsage("varlatch doctor: unexpected argument "+shownArgument(a), "\n"+doctorUsage)
		}
	}
	report, err := r.varlatchdDoctor(config)
	if err != nil {
		return true, err
	}
	report.Checks = append(report.Checks, doctorCLIChecks(report)...)
	if asJSON {
		raw, err := json.Marshal(report)
		if err != nil {
			return true, err
		}
		doc, err := jsjson.Parse(raw)
		if err != nil {
			return true, err
		}
		if err := r.printJSON(doc); err != nil {
			return true, err
		}
	} else if err := r.showDoctor(report); err != nil {
		return true, err
	}
	for _, c := range report.Checks {
		if c.Class == "mandatory" && c.Status == "fail" {
			return true, ExitWith(ExitFailure)
		}
	}
	return true, nil
}

// doctorComposeRefusal is decision 11's refusal of --dir.
func doctorComposeRefusal(r *Run) error {
	ts := "varlatch-ts"
	for _, dir := range filepath.SplitList(r.Getenv("PATH")) {
		if dir != "" && filepath.IsAbs(dir) && isExecutableFile(filepath.Join(dir, "varlatch-ts")) {
			ts = filepath.Join(dir, "varlatch-ts")
			break
		}
	}
	return UsageError("varlatch doctor: --dir names a Compose installation, which the Go CLI does not manage; run " + ts + " doctor --dir <directory> until `varlatch migrate` moves the installation (ADR-0059 step 7)")
}

// varlatchdDoctor runs `varlatchd admin doctor --json [--config file]` and
// returns its report. varlatchd's refusals (its usage, its configuration)
// are shown as it gave them, with its status.
func (r *Run) varlatchdDoctor(config string) (doctorReport, error) {
	path, err := r.locateVarlatchd("varlatch doctor")
	if err != nil {
		return doctorReport{}, err
	}
	args := []string{"admin", "doctor", "--json"}
	if config != "" {
		args = append(args, "--config", config)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = hostCredentials(varlatchdEnviron(r), config)
	answer, said, err := runChild(cmd)
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return doctorReport{}, Fail("varlatch doctor: could not run "+path+": "+err.Error(), ExitUnavailable)
		}
		if code = exit.ExitCode(); code < 0 {
			code = ExitFailure
		}
	}
	var report doctorReport
	// 0 and 1 (a mandatory failure) both carry the report.
	if (code == 0 || code == ExitFailure) && json.Unmarshal(bytes.TrimSpace(answer), &report) == nil && report.Via != "" {
		if err := r.doctorLines(said); err != nil {
			return doctorReport{}, err
		}
		return report, nil
	}
	if len(answer) > 0 {
		if err := r.out(string(answer)); err != nil {
			return doctorReport{}, err
		}
	}
	if err := r.doctorLines(said); err != nil {
		return doctorReport{}, err
	}
	if code == ExitConfig && notRoot() {
		if err := r.warn("varlatch doctor: the installation's configuration and data directory are its service's; run this as root (sudo varlatch doctor)"); err != nil {
			return doctorReport{}, err
		}
	}
	if code == 0 {
		code = ExitFailure
	}
	return doctorReport{}, ExitWith(code)
}

// notRoot is whether this run is not root's, on a system that has one.
func notRoot() bool { return runtime.GOOS != "windows" && os.Geteuid() != 0 }

// doctorLines writes each line varlatchd wrote on stderr through the
// fail-safe.
func (r *Run) doctorLines(said []byte) error {
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

// doctorCLIChecks are the CLI's own checks (a browser's reach, unknown,
// is varlatchd's report's): the TypeScript doctor's ids
// where they mean the same (the conformance suite reads them).
func doctorCLIChecks(report doctorReport) []doctorCheck {
	running := doctorCheck{ID: "services.running", Title: "varlatchd is running", Class: "mandatory"}
	switch report.Via {
	case "daemon":
		running.Status, running.Detail = "pass", "varlatchd answered on its control socket"
	case "unasked":
		// It may well run: this user could not ask it (varlatchd said why
		// on stderr).
		running.Status, running.Detail = "unknown", "this user could not ask varlatchd on its control socket"
		running.Remedy = "Run doctor as root (sudo varlatch doctor) or as the user varlatchd runs as"
	default:
		running.Status, running.Detail = "fail", "varlatchd did not answer on its control socket"
		running.Remedy = "Start varlatchd: sudo systemctl start varlatchd (journalctl -u varlatchd says why it stopped)"
	}
	var facts struct {
		ServerVersion string `json:"serverVersion"`
	}
	_ = json.Unmarshal(report.Facts, &facts)
	release := doctorCheck{ID: "release.pending-upgrade", Title: "varlatch and varlatchd are one release", Class: "mandatory"}
	if facts.ServerVersion == buildinfo.Version {
		release.Status, release.Detail = "pass", "both are "+buildinfo.Version
	} else {
		release.Status = "fail"
		release.Detail = "varlatch is " + buildinfo.Version + ", varlatchd is " + facts.ServerVersion + ": an upgrade did not finish"
		release.Remedy = "Install both binaries from one release (install.sh --server), then run doctor again"
	}
	return []doctorCheck{running, release}
}

// showDoctor writes the report as text, through the fail-safe.
func (r *Run) showDoctor(report doctorReport) error {
	var facts struct {
		ServerVersion string `json:"serverVersion"`
		DataDir       string `json:"dataDir"`
	}
	_ = json.Unmarshal(report.Facts, &facts)
	via := map[string]string{"daemon": "the running varlatchd answered", "offline": "no running varlatchd answered", "unasked": "the running varlatchd could not be asked"}[report.Via]
	if err := r.out(clientctx.MaskUserinfoInText("varlatchd " + facts.ServerVersion + ", data directory " + facts.DataDir + " (" + via + ")\n")); err != nil {
		return err
	}
	for _, c := range report.Checks {
		// varlatchd's words pass through the fail-safe's URL check too: a
		// user name and password in a URL are masked, as on stderr.
		c.Title, c.Detail, c.Remedy = clientctx.MaskUserinfoInText(c.Title), clientctx.MaskUserinfoInText(c.Detail), clientctx.MaskUserinfoInText(c.Remedy)
		mark := map[string]string{"pass": "PASS   ", "fail": "FAIL   ", "unknown": "UNKNOWN"}[c.Status]
		line := mark + " " + c.ID + ": " + c.Title
		if c.Class == "advisory" {
			line += " (advisory)"
		}
		line += "\n"
		if c.Detail != "" {
			line += "        " + c.Detail + "\n"
		}
		if c.Remedy != "" && c.Status != "pass" {
			line += "        to do: " + c.Remedy + "\n"
		}
		if err := r.out(line); err != nil {
			return err
		}
	}
	return nil
}
