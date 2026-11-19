// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/findfiles"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/termtext"
)

// `varlatch scan --find-files [<dir>] [--json]` (slice 5.4e; ADR-0054
// Decision 8; scanCommand.ts's parseScanArgs and runFindFiles): the files
// under a directory that look like copies of secrets by their name, each
// with whether Git ignores it. Offline: no project, server or credential.
// The rest of `scan` is slice 5.4d.

// scanUsage is scanCommand.ts's SCAN_USAGE.
const scanUsage = "Usage: varlatch scan (--staged | <path>...) [-e <env>] [--json] [--baseline <file>] [--write-baseline]\n" +
	"                     [--max-file-size <size>] [--max-total-size <size>]\n" +
	"       varlatch scan --install-hook [-e <env>]\n" +
	"       varlatch scan --find-files [<dir>] [--json]"

var (
	scanValueFlags   = setOf("-e", "--environment", "--server", "--baseline", "--max-file-size", "--max-total-size")
	scanBooleanFlags = setOf("--staged", "--json", "--install-hook", "--write-baseline", "--find-files")
)

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// asksFindFiles is whether the command line is scan's find-files form:
// `--find-files` before `--`. (parseScanArgs never takes it as another
// option's value, since a value may not begin with "-": `scan -e
// --find-files` is the find-files form's usage error.)
func asksFindFiles(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--find-files" {
			return true
		}
	}
	return false
}

// scanFindFiles runs `scan` when its command line asks for --find-files.
func scanFindFiles(r *Run) (bool, error) {
	if !asksFindFiles(r.Args) {
		return false, nil
	}
	dir, json, err := parseFindFilesArgs(r.Args)
	if err != nil {
		return true, UsageErrorWithUsage("varlatch scan: "+err.Error(), "\n"+scanUsage)
	}
	cwd, err := Cwd()
	if err != nil {
		return true, err
	}
	report, err := findfiles.Find(r.Env, dir, cwd, findfiles.DefaultLimits)
	if err != nil {
		if e, ok := err.(*findfiles.Error); ok {
			return true, Fail("varlatch scan: "+e.Message, ExitFailure)
		}
		return true, err
	}
	if json {
		err = r.out(termtext.TerminalJSON(report.JSON()) + "\n")
	} else {
		for _, line := range report.Human(findfiles.DefaultLimits) {
			if err = r.out(line + "\n"); err != nil {
				break
			}
		}
	}
	if err != nil {
		return true, err
	}
	if code := report.ExitCode(); code != 0 {
		return true, ExitWith(code)
	}
	return true, nil
}

// scanArgError is a ScanUsageError: its message, without the command's
// name.
type scanArgError string

func (e scanArgError) Error() string { return string(e) }

// parseFindFilesArgs is parseScanArgs for a command line that asks for
// --find-files: every option read as scan reads it, then the find-files
// form's own rules.
func parseFindFilesArgs(args []string) (dir string, json bool, err error) {
	var paths, given []string
	onlyPaths := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if onlyPaths || !strings.HasPrefix(a, "-") || a == "-" {
			paths = append(paths, a)
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
			if a == "--json" {
				json = true
			}
			continue
		}
		if !scanValueFlags[a] {
			return "", false, scanArgError("unknown option " + a)
		}
		i++
		if i >= len(args) || strings.HasPrefix(args[i], "-") {
			return "", false, scanArgError(a + " needs a value")
		}
		if (a == "--max-file-size" || a == "--max-total-size") && !validSize(args[i]) {
			return "", false, scanArgError(a + ` expects a size such as 64M, 1G, or a number of bytes; got "` + args[i] + `"`)
		}
	}
	var others []string
	for _, f := range given {
		if f != "--find-files" && f != "--json" && !contains(others, f) {
			others = append(others, f)
		}
	}
	if len(others) > 0 {
		return "", false, scanArgError("--find-files lists files by name and takes no " + strings.Join(others, ", ") + "; it accepts one directory and --json")
	}
	if len(paths) > 1 {
		return "", false, scanArgError("--find-files takes one directory")
	}
	dir = "."
	if len(paths) == 1 {
		dir = paths[0]
	}
	return dir, json, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var sizeText = regexp.MustCompile(`(?i)^(\d+)([KMG]?)(i?B)?$`)

// validSize is whether scan.ts's parseSize reads text as a size: digits
// with an optional K, M or G (and i?B), trimmed as String#trim trims, a
// positive safe integer of bytes.
func validSize(text string) bool {
	m := sizeText.FindStringSubmatch(strings.TrimFunc(text, isJSWhitespace))
	if m == nil {
		return false
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	switch strings.ToUpper(m[2]) {
	case "K":
		n *= 1 << 10
	case "M":
		n *= 1 << 20
	case "G":
		n *= 1 << 30
	}
	return n > 0 && n == math.Trunc(n) && n <= 1<<53-1
}
