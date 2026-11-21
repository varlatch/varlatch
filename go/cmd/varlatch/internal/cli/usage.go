// SPDX-License-Identifier: Apache-2.0

package cli

import (
	_ "embed"
	"regexp"
	"strings"
)

// Usage is the CLI's usage text, byte for byte apps/cli/src/usage.ts's
// USAGE: `varlatch --help` prints all of it, `varlatch <command> --help` the
// entries for that command, both on stdout with status 0 (ADR-0043
// Decision 10). usage.txt is a copy; the framework vectors hold the
// TypeScript text, and TestUsageIsTypeScripts fails when they differ.
//
//go:embed usage.txt
var Usage string

var (
	entryStart = regexp.MustCompile(`^ {2}varlatch (\S+)`)
	entryMore  = regexp.MustCompile(`^ {3,}\S`)
)

// CommandHelp is usage.ts's commandHelp: the usage entries for command,
// each starting at a line `  varlatch <command> ...` and running through
// the more deeply indented lines under it; false when it has none.
func CommandHelp(command string) (string, bool) {
	var entries [][]string
	var current []string
	open := false
	for _, line := range strings.Split(Usage, "\n") {
		if m := entryStart.FindStringSubmatch(line); m != nil {
			open = m[1] == command
			if open {
				current = []string{line}
				entries = append(entries, current)
			}
		} else if open && entryMore.MatchString(line) {
			current = append(current, line)
			entries[len(entries)-1] = current
		} else {
			open = false
		}
	}
	if len(entries) == 0 {
		return "", false
	}
	lines := []string{"Usage:"}
	for _, e := range entries {
		lines = append(lines, e...)
	}
	return strings.Join(lines, "\n"), true
}

// commandHelp is what `varlatch help <command>` and `<command> --help`
// print: CommandHelp, except for `admin`, `doctor` and `move`, whose forms
// are a Go installation's (adminUsage, doctorUsage, moveUsage; go/README.md,
// the accepted differences admin-usage, doctor-usage and move-usage), and
// `self-update`, whose forms are the Go CLI's (selfUpdateUsage; the accepted
// difference self-update-usage).
func commandHelp(command string) (string, bool) {
	switch command {
	case "admin":
		return adminUsage, true
	case "doctor":
		return doctorUsage, true
	case "move":
		return moveUsage, true
	case "self-update":
		return selfUpdateUsage, true
	}
	return CommandHelp(command)
}
