// SPDX-License-Identifier: Apache-2.0

package cli

import (
	_ "embed"
	"regexp"
	"strings"
)

// TypeScriptUsage is the TypeScript CLI's usage text, byte for byte
// apps/cli/src/usage.ts's USAGE. usage.txt is a copy; the framework vectors
// hold the TypeScript text, and TestUsageIsTypeScripts fails when they
// differ.
//
//go:embed usage.txt
var TypeScriptUsage string

// Usage is the CLI's usage text: `varlatch --help` prints all of it, `varlatch
// <command> --help` the entries for that command, both on stdout with status
// 0 (ADR-0043 Decision 10). It is TypeScriptUsage with the host commands'
// entries a Go installation's (go/README.md, the accepted difference
// host-usage).
var Usage = hostUsage(TypeScriptUsage)

var (
	entryStart = regexp.MustCompile(`^ {2}varlatch (\S+)`)
	entryMore  = regexp.MustCompile(`^ {3,}\S`)
)

// hostUsage is TypeScriptUsage with every entry of a Compose installation's
// host commands taken out, and a Go installation's own in their place:
// `adopt`, which a Go installation has no use for, goes; `migrate` and
// `tailnet repin`, which only the Go CLI has, come.
func hostUsage(text string) string {
	instead := map[string][]string{
		// In the order they are used on a host.
		"admin":       {setupUsage, moveUsage, doctorUsage, adminUsage},
		"setup":       nil,
		"adopt":       nil,
		"move":        nil,
		"doctor":      nil,
		"self-update": {selfUpdateUsage},
		"upgrade":     {upgradeUsage, migrateUsage},
	}
	var out []string
	dropping, command := false, ""
	done := map[string]bool{}
	after := func() {
		if command == "tailnet" {
			out = append(out, tailnetRepinEntry)
		}
		command = ""
	}
	for _, line := range strings.Split(text, "\n") {
		m := entryStart.FindStringSubmatch(line)
		switch {
		case m != nil:
			after()
			command = m[1]
			var texts []string
			if texts, dropping = instead[command]; dropping && !done[command] {
				done[command] = true
				for _, t := range texts {
					out = append(out, strings.TrimPrefix(t, "Usage:\n"))
				}
			}
		case !entryMore.MatchString(line):
			after()
			dropping = false
		}
		if !dropping {
			out = append(out, line)
		}
	}
	// The TypeScript title has a dash the Go CLI's text does without.
	out[0] = strings.Replace(out[0], "varlatch \u2014 ", "varlatch: ", 1)
	return strings.Join(out, "\n")
}

// tailnetRepinEntry is `tailnet repin`'s entry.
var tailnetRepinEntry = "  " + strings.TrimPrefix(repinUsage, "Usage: ") + `
               (on the installation's host: pins the server to the tailnet its node is on now, after a change it
                refused: a renamed tailnet, or --adopt when the pin is missing. Without --yes it shows what it would
                pin and, on a terminal and without --json, asks)`

// TailnetHelp is `tailnet`'s help: the TypeScript text and repin's entry.
func TailnetHelp() string {
	help, _ := CommandHelp("tailnet")
	return help + "\n" + tailnetRepinEntry
}

// CommandHelp is usage.ts's commandHelp: the usage entries for command,
// each starting at a line `  varlatch <command> ...` and running through
// the more deeply indented lines under it; false when it has none.
func CommandHelp(command string) (string, bool) {
	var entries [][]string
	var current []string
	open := false
	for _, line := range strings.Split(TypeScriptUsage, "\n") {
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
// print: CommandHelp, except for `admin`, `doctor`, `move`, `setup` and
// `upgrade`, whose forms are a Go installation's (adminUsage, doctorUsage,
// moveUsage, setupUsage, upgradeUsage; go/README.md, the accepted
// differences admin-usage, doctor-usage, move-usage, setup-usage and
// upgrade-usage), `self-update`, whose forms are the Go CLI's
// (selfUpdateUsage; the accepted difference self-update-usage), and
// `tailnet`, which has `repin` too (the accepted difference tailnet-usage).
func commandHelp(command string) (string, bool) {
	switch command {
	case "admin":
		return adminUsage, true
	case "doctor":
		return doctorUsage, true
	case "setup":
		return setupUsage, true
	case "tailnet":
		return TailnetHelp(), true
	case "move":
		return moveUsage, true
	case "self-update":
		return selfUpdateUsage, true
	case "upgrade":
		return upgradeUsage, true
	}
	return CommandHelp(command)
}
