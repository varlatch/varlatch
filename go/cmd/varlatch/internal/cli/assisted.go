// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"regexp"
	"slices"
)

// Assisted mode (ADR-0043 Decision 3), a port of apps/cli/src/assisted.ts:
// a coding agent is driving the CLI with the human's own credential. It
// changes client behaviour only, never authorization: `varlatch run` masks
// what it can and refuses what it cannot, and a Secret's value is never
// taken from the command line. The server sees it only as the `assisted`
// token in the User-Agent, which the audit records as what the client said,
// never as an authorization input. The markers coding agents set are a
// backstop for an agent that drops the option: accident prevention, not a
// boundary (internal docs/design/go-cli.md, decision 2).

const (
	assistedOption = "--assisted"
	assistedEnv    = "VARLATCH_ASSISTED"
	approvalOption = "--approval"
)

// AgentMarkers are the variables coding agents set in the shells they
// start, in assisted.ts's order (the first one set wins).
var AgentMarkers = []string{
	"CLAUDECODE",      // Claude Code
	"CODEX_THREAD_ID", // Codex
	"CURSOR_AGENT",    // Cursor
	"COPILOT_CLI",     // GitHub Copilot CLI
	"COPILOT_AGENT",   // GitHub Copilot in VS Code
	"GEMINI_CLI",      // Gemini CLI
	"OPENCODE",        // OpenCode
	"AGENT",           // proposed convention: OpenCode, Goose
	"AI_AGENT",        // @vercel/detect-agent's proposal
}

// AssistedMode is assisted.ts's AssistedMode.
type AssistedMode struct {
	On bool
	// Source is what turned it on: "option", "environment", "marker" or "".
	Source string
	// Marker is the marker that turned it on, when one did.
	Marker string
}

// ResolveAssisted is assisted.ts's resolveAssisted: the explicit option;
// VARLATCH_ASSISTED=1 (or true); a coding agent's marker, unless
// VARLATCH_ASSISTED=0 (or false) turned marker detection off.
// VARLATCH_ASSISTED=0 never overrides the explicit option.
func ResolveAssisted(optionGiven bool, env Env) AssistedMode {
	if optionGiven {
		return AssistedMode{On: true, Source: "option"}
	}
	if raw, ok := env.LookupEnv(assistedEnv); ok {
		switch jsLower(jsTrim(raw)) {
		case "1", "true":
			return AssistedMode{On: true, Source: "environment"}
		case "0", "false":
			return AssistedMode{}
		}
	}
	for _, marker := range AgentMarkers {
		raw, _ := env.LookupEnv(marker)
		value := jsLower(jsTrim(raw))
		if value != "" && value != "0" && value != "false" {
			return AssistedMode{On: true, Source: "marker", Marker: marker}
		}
	}
	return AssistedMode{}
}

// DescribeAssisted is assisted.ts's describeAssisted: names only.
func DescribeAssisted(mode AssistedMode) string {
	switch mode.Source {
	case "option":
		return assistedOption
	case "environment":
		return assistedEnv + "=1"
	case "marker":
		return mode.Marker + " is set"
	}
	return "off"
}

// splitOwn splits argv at the first `--`: before it are the CLI's own
// arguments, the rest (the separator included) belongs to the command
// `varlatch run` starts and is never touched.
func splitOwn(argv []string) (own, rest []string) {
	if i := slices.Index(argv, "--"); i >= 0 {
		return argv[:i], argv[i:]
	}
	return argv, nil
}

// TakeAssistedOption is assisted.ts's takeAssistedOption: argv without
// the global option, and whether it was given.
func TakeAssistedOption(argv []string) ([]string, bool) {
	own, rest := splitOwn(argv)
	kept := make([]string, 0, len(argv))
	for _, a := range own {
		if a != assistedOption {
			kept = append(kept, a)
		}
	}
	given := len(kept) != len(own)
	return append(kept, rest...), given
}

var approvalID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

// TakeApprovalOption is approvals.ts's takeApprovalOption: argv without
// the global --approval <id>, the id, and the problem with it, if any (the
// last one found, as TypeScript keeps it).
func TakeApprovalOption(argv []string) (rest []string, approval string, problem string) {
	own, after := splitOwn(argv)
	kept := make([]string, 0, len(argv))
	given := false
	for i := 0; i < len(own); i++ {
		if own[i] != approvalOption {
			kept = append(kept, own[i])
			continue
		}
		switch {
		case i+1 >= len(own) || len(own[i+1]) > 0 && own[i+1][0] == '-':
			problem = approvalOption + " needs the approval id the CLI printed"
		case given:
			problem = approvalOption + " given twice"
		case !approvalID.MatchString(own[i+1]):
			problem = approvalOption + ": not an approval id: " + own[i+1]
		default:
			approval, given = own[i+1], true
		}
		i++
	}
	return append(kept, after...), approval, problem
}
