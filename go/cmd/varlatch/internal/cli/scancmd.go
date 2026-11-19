// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/findfiles"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/scan"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/termtext"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch scan` (slices 5.4d and 5.4e; ADR-0038 Decision 14; main.ts's
// "scan" case and scanCommand.ts): check staged Git content or build
// output for the Secrets this identity may retrieve, or, with
// --find-files, list the files that look like copies of secrets by name.
//
// The values come from one explicit disclosure, `secret.reveal`, declared
// with `purpose: "scan"` so the audit event says why. They are the selected
// Environment's Secrets, current and retiring versions, and they stay in
// this process's memory for the scan only: nothing derived from them is
// written anywhere, and each one long enough to mask is a value in flight,
// so no output or diagnostic shows it. Nothing is disclosed when there is
// nothing to read. Every failure is 1 (main.ts's everyFailureIsOne).

// scanUsage is scanCommand.ts's SCAN_USAGE.
const scanUsage = "Usage: varlatch scan (--staged | <path>...) [-e <env>] [--json] [--baseline <file>] [--write-baseline]\n" +
	"                     [--max-file-size <size>] [--max-total-size <size>]\n" +
	"       varlatch scan --install-hook [-e <env>]\n" +
	"       varlatch scan --find-files [<dir>] [--json]"

// scanUsageError is a ScanUsageError: printed after "varlatch scan: ",
// with the usage unless it starts with "nothing".
type scanUsageError struct{ message string }

func (e *scanUsageError) Error() string { return e.message }

// scanOptions are ScanOptions. baseline and environment are nil when not
// given.
type scanOptions struct {
	staged, json, installHook, writeBaseline, findFiles bool
	paths                                               []string
	baseline, environment                               *string
	limits                                              scan.Limits
}

var (
	scanValueFlags   = map[string]bool{"-e": true, "--environment": true, "--server": true, "--baseline": true, "--max-file-size": true, "--max-total-size": true}
	scanBooleanFlags = map[string]bool{"--staged": true, "--json": true, "--install-hook": true, "--write-baseline": true, "--find-files": true}
)

// parseScanArgs is parseScanArgs.
func parseScanArgs(args []string) (*scanOptions, error) {
	opts := &scanOptions{paths: []string{}, limits: scan.DefaultLimits}
	var given []string
	onlyPaths := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if onlyPaths || !strings.HasPrefix(a, "-") || a == "-" {
			opts.paths = append(opts.paths, a)
			continue
		}
		if a == "--" {
			onlyPaths = true
			continue
		}
		if scanBooleanFlags[a] || scanValueFlags[a] {
			given = append(given, a)
		}
		if scanBooleanFlags[a] {
			switch a {
			case "--find-files":
				opts.findFiles = true
			case "--staged":
				opts.staged = true
			case "--json":
				opts.json = true
			case "--install-hook":
				opts.installHook = true
			case "--write-baseline":
				opts.writeBaseline = true
			}
			continue
		}
		if !scanValueFlags[a] {
			return nil, &scanUsageError{"unknown option " + a}
		}
		i++
		if i >= len(args) || strings.HasPrefix(args[i], "-") {
			return nil, &scanUsageError{a + " needs a value"}
		}
		value := args[i]
		switch a {
		case "-e", "--environment":
			opts.environment = &value
		case "--baseline":
			opts.baseline = &value
		case "--max-file-size", "--max-total-size":
			size, ok := scan.ParseSize(value)
			if !ok {
				return nil, &scanUsageError{a + ` expects a size such as 64M, 1G, or a number of bytes; got "` + value + `"`}
			}
			if a == "--max-file-size" {
				opts.limits.MaxFileSize = size
			} else {
				opts.limits.MaxTotalSize = size
			}
		}
	}
	if opts.findFiles {
		var others []string
		for _, f := range given {
			if f != "--find-files" && f != "--json" && !containsString(others, f) {
				others = append(others, f)
			}
		}
		if len(others) > 0 {
			return nil, &scanUsageError{"--find-files lists files by name and takes no " + strings.Join(others, ", ") + "; it accepts one directory and --json"}
		}
		if len(opts.paths) > 1 {
			return nil, &scanUsageError{"--find-files takes one directory"}
		}
		return opts, nil
	}
	if opts.installHook {
		if opts.staged || len(opts.paths) > 0 || opts.writeBaseline || opts.json || opts.baseline != nil && *opts.baseline != "" {
			return nil, &scanUsageError{"--install-hook takes no paths and no other options than -e"}
		}
		return opts, nil
	}
	if opts.staged && len(opts.paths) > 0 {
		return nil, &scanUsageError{"give either --staged or paths, not both"}
	}
	if !opts.staged && len(opts.paths) == 0 {
		return nil, &scanUsageError{"give --staged or at least one path"}
	}
	return opts, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// scanFailure is main.ts's catch around runScan: a ScanUsageError or a
// ScanSourceError printed after "varlatch scan: " (a usage error with the
// usage, unless it starts with "nothing"), anything else as it is. Every
// failure is 1 (Run.finish).
func scanFailure(err error) error {
	var refused *scanUsageError
	if errors.As(err, &refused) {
		if strings.HasPrefix(refused.message, "nothing") {
			return Fail("varlatch scan: "+refused.message, ExitUsage)
		}
		return UsageErrorWithUsage("varlatch scan: "+refused.message, "\n"+scanUsage)
	}
	var source *scan.SourceError
	if errors.As(err, &source) {
		return Fail("varlatch scan: "+source.Message, ExitFailure)
	}
	var find *findfiles.Error
	if errors.As(err, &find) {
		return Fail("varlatch scan: "+find.Message, ExitFailure)
	}
	return err
}

func scanCommand(r *Run) error {
	opts, err := parseScanArgs(r.Args)
	if err != nil {
		return scanFailure(err)
	}
	return scanFailure(r.runScan(opts))
}

// runScan is runScan.
func (r *Run) runScan(opts *scanOptions) error {
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	// Names only, before any context: no project, server, or credential is
	// needed.
	if opts.findFiles {
		return r.runFindFiles(opts, cwd)
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	git := scan.Git{Env: environ(r)}
	if opts.installHook {
		hook, err := installHook(git, cwd, ctx.RepoRoot, opts.environment)
		if err != nil {
			return err
		}
		if err := r.println(`Installed the pre-commit hook at ` + hook + `: each commit runs "varlatch scan --staged" first.`); err != nil {
			return err
		}
		return r.println("Skip it once with git commit --no-verify; delete that file to remove it.")
	}

	// What would be read, before anything is disclosed.
	mode := "paths"
	var staged *scan.StagedListing
	var paths *scan.PathListing
	var sizes []int64
	var listed []scan.NotScanned
	if opts.staged {
		mode = "staged"
		if staged, err = scan.ListStaged(git, cwd, ctx.RepoRoot); err != nil {
			return err
		}
		for _, f := range staged.Files {
			sizes = append(sizes, f.Size)
		}
		listed = staged.NotScanned
	} else {
		if paths, err = scan.ListPaths(opts.paths, cwd, ctx.RepoRoot); err != nil {
			return err
		}
		for _, f := range paths.Files {
			sizes = append(sizes, f.Size)
		}
		listed = paths.NotScanned
	}

	baselinePath := filepath.Join(ctx.RepoRoot, scan.BaselineFile)
	if opts.baseline != nil && *opts.baseline != "" {
		baselinePath = resolvePath(cwd, *opts.baseline)
	}
	baseline, err := loadBaseline(baselinePath, opts.baseline != nil)
	if err != nil {
		return err
	}

	// Values are disclosed only when at least one file fits the bounds and
	// will be read.
	readable := false
	for _, size := range sizes {
		if size <= min(opts.limits.MaxFileSize, opts.limits.MaxTotalSize) {
			readable = true
			break
		}
	}
	environment := environmentOf(ctx)
	var secrets []scan.Secret
	if readable {
		api, err := r.client(ctx).get()
		if err != nil {
			return err
		}
		if secrets, err = r.retrieveForScan(api, ctx); err != nil {
			return err
		}
	}
	engine := scan.NewEngine(secrets, opts.limits, baseline)
	// Drop this reference to the values: from here on only the matcher (and
	// the fail-safe's values in flight) hold them.
	secrets = nil
	for _, n := range listed {
		engine.NotScanned(n.Path, n.Reason)
	}
	switch {
	case readable && !engine.ChecksAnything():
		if err := r.warn("varlatch scan: this identity may retrieve no Secret value of " + strconv.Itoa(matcher.MinLength) +
			" bytes or more in " + environment + "; there is nothing to look for."); err != nil {
			return err
		}
	case staged != nil:
		if err := scan.ScanStaged(engine, git, staged); err != nil {
			return err
		}
	default:
		scan.ScanPaths(engine, paths)
	}
	report := engine.Result()

	if opts.writeBaseline {
		if report, err = r.writeBaseline(report, baseline, baselinePath); err != nil {
			return err
		}
	}

	// Item names come from the server: escaped (issue #119).
	for _, notice := range report.Notices() {
		if err := r.warn(Printable(notice)); err != nil {
			return err
		}
	}
	switch {
	case opts.json:
		doc := append(jsjson.Object{{Key: "version", Value: float64(scan.ReportVersion)}, {Key: "environment", Value: ctx.Environment},
			{Key: "mode", Value: mode}, {Key: "exitCode", Value: float64(report.ExitCode())}}, report.JSON()...)
		redacted, rerr := RedactValue(doc, r.inFlight...)
		if rerr != nil {
			return rerr
		}
		err = r.out(termtext.TerminalJSON(redacted) + "\n")
	case len(sizes) == 0 && len(listed) == 0:
		if mode == "staged" {
			err = r.println("varlatch scan: nothing is staged.")
		} else {
			err = r.println("varlatch scan: no files to scan.")
		}
	default:
		for _, line := range report.Human(environment, mode) {
			if err = r.println(Printable(line)); err != nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	if code := report.ExitCode(); code != 0 {
		return ExitWith(code)
	}
	return nil
}

// resolvePath is path.resolve(cwd, p).
func resolvePath(cwd, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

// exists is existsSync: whether path names something, links followed.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadBaseline is loadBaseline: the baseline's entries; none when the
// default file is missing.
func loadBaseline(path string, explicit bool) ([]scan.BaselineEntry, error) {
	if !exists(path) {
		if explicit {
			return nil, &scanUsageError{"no baseline file at " + path}
		}
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	entries, err := scan.ParseBaseline(raw)
	if err != nil {
		return nil, &scanUsageError{"invalid baseline " + path + ": " + err.Error()}
	}
	return entries, nil
}

// writeBaseline is --write-baseline: the baseline with every entry the
// report found added (path, item and version only), and the report with
// every finding allowed by it.
func (r *Run) writeBaseline(report *scan.Report, baseline []scan.BaselineEntry, path string) (*scan.Report, error) {
	known := map[scan.BaselineEntry]bool{}
	for _, e := range baseline {
		known[e] = true
	}
	found := report.BaselineEntries()
	added := map[scan.BaselineEntry]bool{}
	for _, e := range found {
		if !known[e] {
			added[e] = true
		}
	}
	if err := os.WriteFile(path, []byte(jsval.NodeText(scan.FormatBaseline(append(append([]scan.BaselineEntry(nil), baseline...), found...)))), 0o666); err != nil {
		return nil, err
	}
	what := "nothing new to add"
	switch n := len(added); {
	case n == 1:
		what = "added 1 entry"
	case n > 1:
		what = "added " + strconv.Itoa(n) + " entries"
	}
	if err := r.warn("varlatch scan: " + what + " to " + path + " (path, item, and version only). Review it before you commit it."); err != nil {
		return nil, err
	}
	return report.AcceptAll(), nil
}

// retrieveForScan is retrieveForScan: one audited disclosure of every
// Secret this identity may retrieve in the selected Environment, current
// and retiring versions, with purpose "scan". Each value long enough to
// mask is held in flight, so no output or diagnostic shows it.
func (r *Run) retrieveForScan(api *apiclient.Client, ctx *clientctx.Context) ([]scan.Secret, error) {
	meta, err := api.Meta(context.Background())
	if err != nil {
		return nil, err
	}
	capabilities, capOK, err := read(meta, meta != apiclient.Undefined, "capabilities")
	if err != nil {
		return nil, err
	}
	has, err := includes(capabilities, capOK, "secrets.disclosure-purpose", "meta.capabilities.includes")
	if err != nil {
		return nil, err
	}
	if !has {
		shown := "an older release"
		serverVersion, _ := jsval.Get(meta, "serverVersion")
		if v, ok := r.Secrets.SafeVersion(serverVersion); ok {
			shown = v
		}
		if err := r.warn("varlatch scan: this server (" + shown + ") does not record a disclosure purpose; the disclosure is audited as an ordinary one."); err != nil {
			return nil, err
		}
	}
	environment := environmentOf(ctx)
	disclosed, err := api.DiscloseSecrets(context.Background(), ctx.Organization, ctx.Project, environment,
		jsjson.Object{{Key: "scope", Value: "all-authorized-secrets"}, {Key: "purpose", Value: "scan"}})
	if err != nil {
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && (apiErr.CodeIs("PERMISSION_DENIED") || apiErr.CodeIs("RESOURCE_NOT_FOUND")) {
			return nil, &scanUsageError{"nothing was scanned: this identity may not retrieve Secrets in " + environment +
				" (" + safeCode(apiErr.Code) + "; scanning needs secret.reveal there)" + r.requestNote(apiErr)}
		}
		return nil, err
	}
	items, itemsOK, err := read(disclosed, disclosed != apiclient.Undefined, "items")
	if err != nil {
		return nil, err
	}
	if !itemsOK {
		items = nil
	}
	list, err := iterate(items, "disclosed.items")
	if err != nil {
		return nil, err
	}
	var secrets []scan.Secret
	for _, item := range list {
		current, retiring, err := disclosedVersions(item)
		if err != nil {
			return nil, err
		}
		r.holdScanValue(current.Value)
		secrets = append(secrets, current)
		if retiring != nil {
			r.holdScanValue(retiring.Value)
			secrets = append(secrets, *retiring)
		}
	}
	return secrets, nil
}

// holdScanValue holds a disclosed value in flight when it is long enough to
// mask: a shorter one would match ordinary words.
func (r *Run) holdScanValue(value string) {
	if utf16Len(value) >= MinMaskedLength {
		r.holdValue(value)
	}
}

// disclosedVersions is an item of the disclosure's answer: its current
// version and, when it has one, its retiring version. An item of another
// shape (a name, version id or value that is not a string) is refused:
// TypeScript would scan with whatever it got (go/README.md,
// `scan-disclosure-shape`).
func disclosedVersions(item any) (scan.Secret, *scan.Secret, error) {
	o, ok := item.(jsjson.Object)
	if !ok {
		return scan.Secret{}, nil, &clientctx.TypeError{Message: "a disclosed item is not an object"}
	}
	name, n := o.Value("name").(string)
	versionID, v := o.Value("versionId").(string)
	value, ok := o.Value("value").(string)
	if !n || !v || !ok {
		return scan.Secret{}, nil, &clientctx.TypeError{Message: "a disclosed item's name, versionId and value must be strings"}
	}
	current := scan.Secret{Item: name, VersionID: versionID, Value: value}
	retiring := o.Value("retiring")
	if !jsjson.Truthy(retiring) {
		return current, nil, nil
	}
	ro, ok := retiring.(jsjson.Object)
	rVersion, rv := ro.Value("versionId").(string)
	rValue, rok := ro.Value("value").(string)
	if !ok || !rv || !rok {
		return scan.Secret{}, nil, &clientctx.TypeError{Message: "a disclosed item's retiring versionId and value must be strings"}
	}
	return current, &scan.Secret{Item: name, VersionID: rVersion, Retiring: true, Value: rValue}, nil
}

// ---- --find-files ----------------------------------------------------------------

// runFindFiles is runFindFiles: the files under a directory that look like
// copies of secrets by their name, each with whether Git ignores it
// (ADR-0054 Decision 8). Offline: no project, server or credential.
func (r *Run) runFindFiles(opts *scanOptions, cwd string) error {
	dir := "."
	if len(opts.paths) > 0 {
		dir = opts.paths[0]
	}
	report, err := findfiles.Find(r.Env, dir, cwd, findfiles.DefaultLimits)
	if err != nil {
		return err
	}
	if opts.json {
		err = r.out(termtext.TerminalJSON(report.JSON()) + "\n")
	} else {
		for _, line := range report.Human(findfiles.DefaultLimits) {
			if err = r.out(line + "\n"); err != nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	if code := report.ExitCode(); code != 0 {
		return ExitWith(code)
	}
	return nil
}

// ---- The pre-commit hook -----------------------------------------------------------

// hookMarker is HOOK_MARKER: the line that marks a hook varlatch wrote.
const hookMarker = "# varlatch-scan-hook v1"

// shellQuote is shellQuote: s in single quotes for sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// hookScript is hookScript: the hook's text, which runs `varlatch scan
// --staged` from the project directory.
func hookScript(projectDir string, environment *string) string {
	lines := []string{
		"#!/bin/sh",
		hookMarker,
		"# Installed by `varlatch scan --install-hook`. Before each commit it checks",
		"# the staged content for Secrets and stops the commit when it finds one.",
		"# Skip it once with `git commit --no-verify`; delete this file to remove it.",
		"# Git runs hooks from the top of the working tree. Keep Git's paths valid",
		"# after changing directory.",
		`case "${GIT_INDEX_FILE:-/}" in /*) ;; *) GIT_INDEX_FILE="$PWD/$GIT_INDEX_FILE"; export GIT_INDEX_FILE ;; esac`,
		`case "${GIT_DIR:-/}" in /*) ;; *) GIT_DIR="$PWD/$GIT_DIR"; export GIT_DIR ;; esac`,
		`if [ -n "${GIT_DIR:-}" ] && [ -z "${GIT_WORK_TREE:-}" ]; then GIT_WORK_TREE="$PWD"; export GIT_WORK_TREE; fi`,
	}
	if projectDir != "" && projectDir != "." {
		lines = append(lines, "cd "+shellQuote(projectDir)+" || exit 1")
	}
	run := "exec varlatch scan --staged"
	if environment != nil && *environment != "" {
		run += " --environment " + shellQuote(*environment)
	}
	return strings.Join(append(lines, run), "\n") + "\n"
}

// installHook is installHook: write the pre-commit hook (only when asked:
// it is never installed by itself). A hook that varlatch did not write is
// never replaced.
func installHook(git scan.Git, cwd, projectRoot string, environment *string) (string, error) {
	top, err := scan.GitTopLevel(git, cwd)
	if err != nil {
		return "", err
	}
	out, said, exit, err := git.Run(cwd, nil, "rev-parse", "--git-path", "hooks/pre-commit")
	if err != nil {
		// execFileSync's spawn error.
		message := strings.Replace(err.(*scan.SourceError).Message, "could not run git: spawn ", "spawnSync ", 1)
		return "", &scan.SourceError{Message: "could not find the hooks directory: " + message}
	}
	if exit != nil {
		// execFileSync's error: the command, and what git said.
		message := "Command failed: git rev-parse --git-path hooks/pre-commit"
		if len(said) > 0 {
			message += "\n" + jsval.DecodeUTF8(said)
		}
		return "", &scan.SourceError{Message: "could not find the hooks directory: " + message}
	}
	hookPath := strings.TrimFunc(jsval.DecodeUTF8(out), jsval.IsWhitespace)
	if !filepath.IsAbs(hookPath) {
		hookPath = resolvePath(cwd, hookPath)
	}
	real, err := scan.Realpath(projectRoot)
	if err != nil {
		return "", err
	}
	projectDir := scan.RelativePath(top, real)
	if strings.HasPrefix(projectDir, "..") {
		return "", &scanUsageError{projectRoot + " is outside the Git working tree " + top}
	}
	script := hookScript(projectDir, environment)
	if exists(hookPath) {
		existing, err := os.ReadFile(hookPath)
		if err != nil {
			return "", err
		}
		if !strings.Contains(jsval.DecodeUTF8(existing), hookMarker) {
			line := "varlatch scan --staged || exit 1"
			if projectDir != "" && projectDir != "." {
				line = "(cd " + shellQuote(projectDir) + " && varlatch scan --staged) || exit 1"
			}
			return "", &scanUsageError{hookPath + " already exists and was not written by varlatch; it was left unchanged. " +
				"To run the scan from it, add this line:\n  " + line}
		}
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o777); err != nil {
		return "", err
	}
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(hookPath, 0o755); err != nil {
		return "", err
	}
	return hookPath, nil
}
