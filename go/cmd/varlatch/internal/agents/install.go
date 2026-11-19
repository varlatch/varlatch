// SPDX-License-Identifier: Apache-2.0

// Package agents is `varlatch agents guide` and `varlatch agents install`
// (ADR-0043 Decisions 7 to 9; internal docs/design/go-cli.md, slice 5.1d):
// the skill in the paths coding agents read, a short block in AGENTS.md,
// small adapters for the coding agents that need more, and the opt-in
// guardrail and MCP settings. It is a port of apps/cli/src/agents
// (install.ts, files.ts, toml.ts, mcpConfig.ts, guardrails.ts' files and
// skill.ts) and writes the same files, byte for byte.
//
// Every write keeps what the CLI did not write: the skill directories are
// the CLI's own, AGENTS.md changes only inside the marked block, CLAUDE.md
// and .aider.conf.yml gain one marked line each, and a settings file is
// edited only when the edit cannot reformat it; otherwise the human gets
// the exact edit to make. `--check` compares without writing; `--remove`
// takes back what the CLI wrote. Nothing is written through a symbolic
// link.
package agents

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Scope is where install writes: "project" or "user".
type Scope = string

// Mode is "install", "check" or "remove".
type Mode = string

// Change is one file install created, updated, removed or left unchanged.
type Change struct {
	// Path is relative to the root, with forward slashes.
	Path   string
	Action string
}

// Result is install.ts's InstallResult.
type Result struct {
	Scope       Scope
	Root        string
	Changes     []Change
	Manual      []string
	LeftInPlace []string
	Agents      []AgentReads
	Notices     []string
	Drift       bool
}

// AgentReads is how a coding agent named with --agent finds the skill and
// AGENTS.md.
type AgentReads struct{ Agent, Reads string }

// Options is install.ts's InstallOptions.
type Options struct {
	Scope Scope
	// Root is the project root (project scope) or the home directory (user scope).
	Root    string
	Version string
	// Agents are the coding agents named with --agent.
	Agents []string
	Mode   Mode
	// Guardrails writes the opt-in guardrails; --remove takes them out regardless.
	Guardrails bool
	// MCP adds the `varlatch mcp` server; --remove takes it out regardless.
	MCP bool
}

// Error is install.ts's AgentsInstallError: Usage when the command line is
// wrong (64), otherwise a file the CLI will not edit (78).
type Error struct {
	Message string
	Usage   bool
}

func (e *Error) Error() string { return e.Message }

type agentInfo struct {
	name    string
	adapter string // "claude", "gemini", "aider" or ""
	reads   string
}

// agentTable is install.ts's AGENTS, the CLI's compatibility table, in
// its order.
var agentTable = []agentInfo{
	{"claude-code", "claude", ".claude/skills; AGENTS.md only without a CLAUDE.md, so an existing one imports it"},
	{"codex", "", ".agents/skills and AGENTS.md"},
	{"cursor", "", ".agents/skills and AGENTS.md"},
	{"copilot", "", ".agents/skills and AGENTS.md"},
	{"gemini", "gemini", ".agents/skills; AGENTS.md once .gemini/settings.json lists it in context.fileName"},
	{"opencode", "", ".agents/skills and AGENTS.md"},
	{"devin", "", ".agents/skills and AGENTS.md"},
	{"amp", "", ".agents/skills and AGENTS.md"},
	{"goose", "", ".agents/skills and AGENTS.md"},
	{"zed", "", ".agents/skills and AGENTS.md"},
	{"cline", "", ".claude/skills and AGENTS.md"},
	{"roo", "", ".agents/skills and AGENTS.md"},
	{"aider", "aider", "no skills; AGENTS.md once .aider.conf.yml lists it under read:"},
	{"jules", "", "AGENTS.md"},
}

func agentOf(name string) (agentInfo, bool) {
	for _, a := range agentTable {
		if a.name == name {
			return a, true
		}
	}
	return agentInfo{}, false
}

var skillBases = []string{filepath.Join(".agents", "skills", SkillName), filepath.Join(".claude", "skills", SkillName)}

const (
	blockBegin   = "<!-- varlatch:begin -->"
	blockEnd     = "<!-- varlatch:end -->"
	claudeMarker = "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->"
	aiderLine    = "read: AGENTS.md # added by varlatch agents install"
)

// AgentsBlock is the AGENTS.md block: the rules that matter most, and
// where the rest is.
func AgentsBlock() string { return strings.Join(agentsBlockLines, "\n") }

var agentsBlockLines = []string{
	blockBegin,
	"## Configuration and secrets: Varlatch",
	"",
	"This project keeps its configuration and secrets in Varlatch.",
	"",
	"- Start every Varlatch command with `varlatch --assisted`.",
	"- Never read, print, or create `.env` files, and never put a secret value in a command.",
	"- This repository is already set up (`varlatch.toml`): never run `varlatch init`.",
	"- To move a `.env` file into Varlatch, without reading it:",
	"  1. Compare names with the target environment: `varlatch --assisted import .env -e <environment> --dry-run --json`",
	"     marks those it already has (the file may be an older copy). Ask the human about each; the import replaces one",
	"     only with `--replace <NAME>` for it.",
	"  2. Import: `varlatch --assisted import .env -e <environment> --contract --plain <NAME> --delete-source --json`.",
	"     `--plain` only for items the human confirmed are not secret; the file is deleted only after every value was stored.",
	"  3. If the import created a Contract revision, activate it: `varlatch --assisted contract activate <revision>`.",
	"- Work in the environment the human named; otherwise the project's default (`varlatch --assisted context --json`",
	"  shows `environment` and `server`). Never switch to another environment or server to get around missing configuration.",
	"- Create values only when the task asks for it (setting up, importing, a requested new value), in the environment it",
	"  is for, or after the human approves that item there; such a task needs no second approval. Starting or checking an",
	"  app never authorizes creating values: report a missing one and hand it over. Never invent configuration to make a",
	"  run succeed.",
	"- To find out whether an environment is ready (what is missing or invalid), run",
	"  `varlatch --assisted validate -e <environment> --json`; listing values does not check the Contract.",
	"- When a value is missing, give the human this command for their own terminal, where it prompts without showing the",
	"  value (no `--assisted`; add `--server <url>` when the server was overridden), or point them to the dashboard:",
	"",
	"  ```text",
	"  varlatch values set <NAME> -e <environment>",
	"  ```",
	"",
	"- Never replace an existing value or change an item's sensitivity without the human's approval for that item:",
	"  in assisted mode `values set`, `values rotate`, and `import` refuse to replace one without `--replace <NAME>`.",
	"- Never delete a value without the human's approval for that item in that environment: in assisted mode",
	"  `values delete` refuses without `--confirm <NAME>`, which you add only after that approval.",
	"- When a Secret is too short to mask (exit 78), leave it out only if the command's code or documentation shows that",
	"  the command does not use it; that needs no approval:",
	"  `varlatch --assisted run -e <environment> --omit <NAME> -- <command>`. Then name every item left out in your answer,",
	"  and say whether the task itself was done: getting past exit 78 does not show that it was. If you are not sure, or",
	"  the command uses it, stop and ask the human. Only after they approve a remedy for that item and environment may you",
	"  carry it out, with `--assisted`; for a new random value:",
	"  `varlatch --assisted values set <NAME> -e <environment> --replace <NAME> --generate hex:32` (keep `--server <url>`",
	"  when it was overridden). A credential a provider issued is the human's to enter. Marking an item as not secret",
	"  changes the Contract for the whole project: `varlatch --assisted agents guide contract`. Showing a Secret unmasked",
	"  is the human's alone: never add `--allow-unmasked` or `--no-redact` (assisted mode refuses both).",
	"- When the human asks for a new random value, generate it (`--generate hex:32`); a credential issued elsewhere is",
	"  theirs to enter. Never run a command printed for the human's own terminal yourself.",
	"- Inside an agent-safe run, the run's Secrets are Placeholders, not secrets, listed (names only) by",
	"  `varlatch --assisted context --json` under `agentRun.placeholders`. Showing a listed one discloses nothing",
	"  (`varlatch --assisted run -- printenv <NAME>` when the human asks you to check it); never show any other",
	"  variable there: the run also carries credentials and inherited values. Placeholders go in",
	"  `varlatch --assisted request` targets, for example",
	"  `varlatch --assisted request -H \"Authorization: Bearer $STRIPE_KEY\" https://api.example.com/v1/balance`",
	"  (double quotes: in single quotes the literal `$STRIPE_KEY` is sent, and nothing is substituted).",
	"- Run anything that needs configuration with `varlatch --assisted run -- <command>`. If it says no values are",
	"  stored in Varlatch, the command gets only what it inherits: check what it needs (`validate`) and report that.",
	"- When a step needs the human (signing in, entering a secret), give them the exact command and wait.",
	"- To sign in: run `varlatch --assisted login --server <url> --start`, give the human the address and code it prints, wait until they say they approved, then run `varlatch --assisted login --server <url> --wait`.",
	"- Everything else is in the `varlatch` skill (`.agents/skills/varlatch/SKILL.md`), also printed by",
	"  `varlatch --assisted agents guide`.",
	blockEnd,
}

// withBlock is AGENTS.md with the block added or replaced, or taken out
// when removing (nil: the file held only the block, so it goes).
func withBlock(current desired, remove bool) (desired, error) {
	text := ""
	if current != nil {
		text = *current
	}
	start := strings.Index(text, blockBegin)
	end := -1
	if start >= 0 {
		if i := strings.Index(text[start:], blockEnd); i >= 0 {
			end = start + i
		}
	}
	if start >= 0 && end < 0 {
		return nil, &Error{"AGENTS.md has " + blockBegin + " without " + blockEnd + "; restore or delete the marker, then run this again", false}
	}
	if start < 0 && strings.Contains(text, blockEnd) {
		return nil, &Error{"AGENTS.md has " + blockEnd + " without " + blockBegin + "; restore or delete the marker, then run this again", false}
	}
	// An existing block keeps its line ending, so installing again changes nothing.
	eol := eolOf(text)
	if start >= 0 {
		eol = ownedEol(text, start, end+len(blockEnd))
	}
	block := strings.ReplaceAll(AgentsBlock(), "\n", eol)
	if start >= 0 {
		if remove {
			return withoutOwned(text, start, end+len(blockEnd)), nil
		}
		return ptr(text[:start] + block + text[end+len(blockEnd):]), nil
	}
	if remove {
		return current, nil
	}
	return ptr(appendOwned(current, block+eol)), nil
}

// importsAgents is whether a CLAUDE.md's text already imports AGENTS.md
// (importPath is relative to the file): a line `@AGENTS.md`, perhaps
// `@./AGENTS.md`, between spaces or tabs.
func importsAgents(text, importPath string) bool {
	for _, line := range jsLines(text) {
		line = strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(line, "@") {
			continue
		}
		line = strings.TrimPrefix(strings.TrimPrefix(line, "@"), "./")
		// "@./AGENTS.md": (\.\/)? is optional, so "@AGENTS.md" and "@./AGENTS.md" both match.
		if strings.TrimRight(strings.TrimPrefix(line, importPath), " \t") == "" && strings.HasPrefix(line, importPath) {
			return true
		}
	}
	return false
}

// withClaudeImport is a CLAUDE.md with the marked import of AGENTS.md
// added, or taken out when removing (nil: the file held only the import).
// Unchanged when the file already imports AGENTS.md.
func withClaudeImport(current desired, remove bool, importPath string) desired {
	text := ""
	if current != nil {
		text = *current
	}
	if remove {
		// ${marker}\r?\n@${importPath}(?=\r?\n|$), the first one.
		for from := 0; ; {
			i := strings.Index(text[from:], claudeMarker)
			if i < 0 {
				return current
			}
			i += from
			rest := text[i+len(claudeMarker):]
			for _, eol := range []string{"\r\n", "\n"} {
				line := eol + "@" + importPath
				if strings.HasPrefix(rest, line) {
					after := rest[len(line):]
					if after == "" || strings.HasPrefix(after, "\n") || strings.HasPrefix(after, "\r\n") {
						return withoutOwned(text, i, i+len(claudeMarker)+len(line))
					}
				}
			}
			from = i + 1
		}
	}
	if importsAgents(text, importPath) {
		return current
	}
	eol := eolOf(text)
	return ptr(appendOwned(current, claudeMarker+eol+"@"+importPath+eol))
}

// withGeminiContext is the Gemini CLI settings with AGENTS.md among its
// context files, or nil when they need no change.
func withGeminiContext(settings jsjson.Object) jsjson.Object {
	contextValue, _ := settings.Get("context")
	var context jsjson.Object
	switch contextValue.(type) {
	case jsjson.Object, []any:
		// typeof "object" and not null: an array is spread by its indexes.
		context = spread(contextValue)
	default:
		context = jsjson.Object{}
	}
	current, present := context.Get("fileName")
	var names []any
	switch c := current.(type) {
	case []any:
		names = append(names, c...)
	default:
		if present {
			names = []any{current}
		} else {
			names = []any{"GEMINI.md"}
		}
	}
	if includes(names, "AGENTS.md") {
		return nil
	}
	return with(settings, "context", with(context, "fileName", append(names, "AGENTS.md")))
}

var (
	commentTail  = jsRegexp(`\s+#.*$`)
	doubleQuoted = regexp.MustCompile(`^"([^"\\]|\\.)*"$`)
	singleQuoted = regexp.MustCompile(`^'([^']|'')*'$`)
	flowList     = regexp.MustCompile(`^\[[^\[\]{}"'#]*\]$`)
	indicator    = regexp.MustCompile("^[-?:,\\[\\]{}#&*!|>'\"%@`]")
	mappingColon = jsRegexp(`:(\s|$)`)
	trailingWS   = jsRegexp(`\s+$`)
	commentLine  = jsRegexp(`^\s*#`)
	plainKey     = jsRegexp(`^([A-Za-z0-9][A-Za-z0-9_.-]*):(?:\s+(.*))?$`)
	listItem     = jsRegexp(`^\s*-\s+(.*)$`)
	yamlBreak    = regexp.MustCompile(`\r\n|[\n\r\x{85}\x{2028}\x{2029}]`)
)

// replaceFirst is String.prototype.replace with a regular expression that
// has no g flag.
func replaceFirst(re interface{ FindStringIndex(string) []int }, s, with string) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return s
	}
	return s[:loc[0]] + with + s[loc[1]:]
}

// aiderLayout is what .aider.conf.yml needs, judged without a YAML parser
// and on the safe side: "append", "has-read" or "unsafe" (install.ts).
func aiderLayout(text string) string {
	oneLineValue := func(value string) bool {
		v := trim(replaceFirst(commentTail, value, ""))
		if v == "" {
			return true
		}
		if doubleQuoted.MatchString(v) || singleQuoted.MatchString(v) {
			return true
		}
		if flowList.MatchString(v) {
			return true
		}
		// A plain scalar: no leading indicator, and no ": " that would open a mapping.
		return !indicator.MatchString(v) && !mappingColon.MatchString(v)
	}
	hasRead, listOpen := false, false
	for _, raw := range yamlBreak.Split(text, -1) {
		line := replaceFirst(trailingWS, raw, "")
		if line == "" || commentLine.MatchString(line) {
			continue
		}
		if strings.Contains(line, "\t") {
			return "unsafe"
		}
		if key := plainKey.FindStringSubmatch(line); key != nil {
			if !oneLineValue(key[2]) {
				return "unsafe"
			}
			if key[1] == "read" {
				hasRead = true
			}
			listOpen = trim(replaceFirst(commentTail, key[2], "")) == ""
			continue
		}
		if item := listItem.FindStringSubmatch(line); item != nil && listOpen && oneLineValue(item[1]) {
			continue
		}
		return "unsafe"
	}
	if hasRead {
		return "has-read"
	}
	return "append"
}

// withAiderRead is .aider.conf.yml with the marked read: line added, or
// taken out when removing (nil: nothing else is left).
func withAiderRead(current desired, remove bool) desired {
	text := ""
	if current != nil {
		text = *current
	}
	if remove {
		i := lineStartsWith(text, aiderLine)
		if i < 0 {
			return current
		}
		return withoutOwned(text, i, i+len(aiderLine))
	}
	return ptr(appendOwned(current, aiderLine+eolOf(text)))
}

type plan struct {
	files       []planned
	manual      []string
	leftInPlace []string
	notices     []string
}

func notTextNote(name, edit string) string {
	return name + " is not a UTF-8 text file, so the CLI leaves it as it is: " + edit
}

func (p *plan) build(opts Options) error {
	remove := opts.Mode == "remove"
	at := func(path string) string { return filepath.Join(opts.Root, path) }
	st := newStaging()

	// The skill directories are the CLI's own: every file in them is
	// managed, and one this version does not ship is removed.
	skill := SkillFiles(opts.Version)
	for _, base := range skillBases {
		wanted := map[string]bool{}
		if !remove {
			for _, f := range skill {
				path := at(filepath.Join(base, f.path))
				p.files = append(p.files, planned{path: path, desired: ptr(f.content)})
				wanted[path] = true
			}
		}
		existing, err := filesUnder(at(base))
		if err != nil {
			return err
		}
		for _, path := range existing {
			if !wanted[path] {
				p.files = append(p.files, planned{path: path})
			}
		}
	}
	if opts.Scope == "user" {
		return nil
	}

	// AGENTS.md as a link: the file it leads to is edited, never the link,
	// and only when that file is in the project.
	agentsPath := at("AGENTS.md")
	if isSymlink(agentsPath) {
		real, err := realpath(agentsPath)
		realRoot := resolvedPath(opts.Root)
		if err != nil || !isInside(realRoot, real) {
			where := "to a file that does not exist"
			if err == nil {
				where = "to " + real + ", outside this project"
			}
			return &Error{"AGENTS.md is a symbolic link " + where + ", so the CLI does not edit it; " +
				"replace it with a file, or link it to a file in this project, then run this again", false}
		}
		// The same file, named under the root, so changes are reported relative to it.
		agentsPath = filepath.Join(resolve(opts.Root), relative(realRoot, real))
	}

	// Claude Code reads AGENTS.md only when no CLAUDE.md is in the way: an
	// existing one (at the root, else in .claude/) imports it.
	type claudeFile struct {
		path, importPath   string
		link, exists, same bool
		current            content
	}
	var claude []claudeFile
	for _, c := range []claudeFile{{path: "CLAUDE.md", importPath: "AGENTS.md"}, {path: filepath.Join(".claude", "CLAUDE.md"), importPath: "../AGENTS.md"}} {
		c.link = isSymlink(at(c.path))
		c.exists = c.link || exists(at(c.path))
		c.same = c.exists && sameFile(at(c.path), agentsPath)
		if !c.link {
			current, err := st.read(at(c.path))
			if err != nil {
				return err
			}
			c.current = current
		}
		claude = append(claude, c)
	}

	agentsMd, err := st.read(agentsPath)
	if err != nil {
		return err
	}
	if agentsMd.state == notText {
		return &Error{"AGENTS.md is not a UTF-8 text file, so the CLI does not edit it; fix or move it, then run this again", false}
	}
	// An earlier release wrote its import through such a link, into AGENTS.md
	// itself, and lost the block. That marked line is the CLI's to take back.
	for _, c := range claude {
		if c.same && agentsMd.state == isText {
			if next := withClaudeImport(ptr(agentsMd.text), true, c.importPath); next != nil {
				agentsMd.text = *next
			} else {
				agentsMd.text = ""
			}
		}
	}
	if !(remove && agentsMd.state == missing) {
		var current desired
		if agentsMd.state == isText {
			current = ptr(agentsMd.text)
		}
		next, err := withBlock(current, remove)
		if err != nil {
			return err
		}
		st.write(agentsPath, next)
	}

	selected := map[string]bool{}
	for _, name := range opts.Agents {
		if a, ok := agentOf(name); ok {
			selected[a.adapter] = true
		}
	}
	if remove {
		for _, c := range claude {
			if c.same {
				continue
			}
			if c.link {
				linked, err := readText(at(c.path))
				if err != nil {
					return err
				}
				if linked.state == isText && strings.Contains(linked.text, claudeMarker) {
					p.leftInPlace = append(p.leftInPlace, "the marked @"+c.importPath+" line in "+c.path+", a symbolic link the CLI does not write through")
				}
				continue
			}
			if c.current.state == isText {
				st.write(at(c.path), withClaudeImport(ptr(c.current.text), true, c.importPath))
			}
		}
	} else {
		var target *claudeFile
		for i := range claude {
			if claude[i].exists {
				target = &claude[i]
				break
			}
		}
		switch {
		case target != nil && target.same:
			agentsLink := agentsPath != at("AGENTS.md")
			switch {
			case target.link:
				p.notices = append(p.notices, target.path+" is a link to AGENTS.md; Claude Code reads it directly")
			case agentsLink:
				p.notices = append(p.notices, "AGENTS.md is a link to "+target.path+"; Claude Code reads it directly")
			default:
				p.notices = append(p.notices, target.path+" and AGENTS.md are the same file; Claude Code reads it directly")
			}
		case target != nil && target.link:
			linked, err := readText(at(target.path))
			if err != nil {
				return err
			}
			if !(linked.state == isText && importsAgents(linked.text, target.importPath)) {
				p.manual = append(p.manual, target.path+" is a symbolic link (to "+shownPath(opts.Root, at(target.path))+"), so the CLI does not write through it: "+
					"for Claude Code to read AGENTS.md, make "+target.path+" a file with the line @"+target.importPath+", or add that line where it leads")
			}
		case target != nil && target.current.state == isText:
			st.write(at(target.path), withClaudeImport(ptr(target.current.text), false, target.importPath))
		case target != nil:
			p.manual = append(p.manual, notTextNote(target.path, "add the line @"+target.importPath))
		case selected["claude"]:
			st.write(at("CLAUDE.md"), withClaudeImport(nil, false, "AGENTS.md"))
		default:
			local, err := st.read(at("CLAUDE.local.md"))
			if err != nil {
				return err
			}
			if local.state != missing {
				p.manual = append(p.manual, "Claude Code skips AGENTS.md while CLAUDE.local.md exists: add the line @AGENTS.md to CLAUDE.local.md")
			}
		}
	}

	if err := p.gemini(opts, st, at, remove, selected); err != nil {
		return err
	}
	if err := p.aider(st, at, remove, selected); err != nil {
		return err
	}
	if remove || opts.Guardrails {
		g, err := planGuardrails(opts.Root, opts.Agents, opts.Mode, st)
		if err != nil {
			return err
		}
		p.manual = append(p.manual, g.manual...)
		p.leftInPlace = append(p.leftInPlace, g.leftInPlace...)
		p.notices = append(p.notices, g.notices...)
	}
	// After guardrails, which may have staged .codex/config.toml.
	if remove || opts.MCP {
		m, err := planMCP(opts.Root, opts.Agents, opts.Mode, st)
		if err != nil {
			return err
		}
		p.manual = append(p.manual, m.manual...)
		p.leftInPlace = append(p.leftInPlace, m.leftInPlace...)
		p.notices = append(p.notices, m.notices...)
	}
	p.files = append(p.files, st.entries()...)
	var unique []string
	for _, n := range p.notices {
		if !slices.Contains(unique, n) {
			unique = append(unique, n)
		}
	}
	p.notices = unique
	return nil
}

func (p *plan) gemini(opts Options, st *staging, at func(string) string, remove bool, selected map[string]bool) error {
	geminiPath := at(filepath.Join(".gemini", "settings.json"))
	raw, err := st.read(geminiPath)
	if err != nil {
		return err
	}
	const edit = `add "AGENTS.md" to context.fileName in .gemini/settings.json`
	switch {
	case remove:
		if raw.state == isText && strings.Contains(raw.text, `"AGENTS.md"`) {
			p.leftInPlace = append(p.leftInPlace, `"AGENTS.md" in context.fileName in .gemini/settings.json`)
		}
	case raw.state == notText:
		p.manual = append(p.manual, notTextNote(".gemini/settings.json", edit))
	case raw.state == isText || selected["gemini"]:
		var parsed any = jsjson.Object{}
		if raw.state == isText {
			v, ok := parseJSON(raw.text)
			if !ok {
				v = nil
			}
			parsed = v
		}
		settings, isSettings := parsed.(jsjson.Object)
		var next jsjson.Object
		if isSettings {
			next = withGeminiContext(settings)
		}
		editable := isSettings && (raw.state == missing || isCanonicalJSON(raw.text, settings))
		switch {
		case !isSettings || (next != nil && !editable):
			p.manual = append(p.manual, edit+" (the CLI edits the file only when that keeps its formatting)")
		case next != nil:
			// Written exactly as it was read, with a final line break only if it had one.
			eol := ""
			if raw.state == missing || strings.HasSuffix(raw.text, "\n") {
				eol = "\n"
			}
			st.write(geminiPath, ptr(stringify2(next)+eol))
		}
	}
	return nil
}

func (p *plan) aider(st *staging, at func(string) string, remove bool, selected map[string]bool) error {
	aiderPath := at(".aider.conf.yml")
	raw, err := st.read(aiderPath)
	if err != nil {
		return err
	}
	switch {
	case remove:
		if raw.state == isText {
			next := withAiderRead(ptr(raw.text), true)
			if next == nil || *next != raw.text {
				st.write(aiderPath, next)
			}
			if next != nil && strings.Contains(*next, "AGENTS.md") {
				p.leftInPlace = append(p.leftInPlace, "AGENTS.md under read: in .aider.conf.yml")
			}
		}
	case raw.state == notText:
		p.manual = append(p.manual, notTextNote(".aider.conf.yml", "add AGENTS.md under read:"))
	case raw.state == isText || selected["aider"]:
		layout := "append"
		var current desired
		if raw.state == isText {
			layout = aiderLayout(raw.text)
			current = ptr(raw.text)
		}
		switch {
		case raw.state == isText && strings.Contains(raw.text, aiderLine):
			// Installed before; the file may have changed around the CLI's line since.
		case layout == "append":
			st.write(aiderPath, withAiderRead(current, false))
		case layout == "has-read":
			if !(raw.state == isText && strings.Contains(raw.text, "AGENTS.md")) {
				p.manual = append(p.manual, "add AGENTS.md to the read: entry in .aider.conf.yml")
			}
		default:
			p.manual = append(p.manual, "add AGENTS.md under read: in .aider.conf.yml (the CLI appends to the file only when its layout makes that safe)")
		}
	}
	return nil
}

// shownPath is where a link leads, for a message: relative to the project
// when inside it, else the full path.
func shownPath(root, path string) string {
	realRoot := resolvedPath(root)
	target := resolvedPath(path)
	if isInside(realRoot, target) {
		return filepath.ToSlash(relative(realRoot, target))
	}
	return target
}

// pruneEmpty removes, after --remove, the emptied skill directories, and
// their parents if nothing else is in them. root is the scope's root;
// nothing below it that is a link is followed or removed.
func pruneEmpty(w *writer, root, base string) error {
	var prune func(rel string) error
	prune = func(rel string) error {
		dir := filepath.Join(root, rel)
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			return nil
		}
		entries, err := readDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				if err := prune(filepath.Join(rel, e.Name())); err != nil {
					return err
				}
			}
		}
		if entries, err = readDir(dir); err != nil {
			return err
		}
		if len(entries) == 0 {
			return w.rmdir(rel)
		}
		return nil
	}
	if err := prune(base); err != nil {
		return err
	}
	for dir := filepath.Dir(filepath.Join(root, base)); dir != root && strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		if !exists(dir) {
			break
		}
		entries, err := readDir(dir)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			break
		}
		if err := w.rmdir(relative(root, dir)); err != nil {
			return err
		}
	}
	return nil
}

// RunInstall is install.ts's runInstall.
func RunInstall(opts Options) (*Result, error) {
	known := make([]string, len(agentTable))
	for i, a := range agentTable {
		known[i] = a.name
	}
	for _, name := range opts.Agents {
		if _, ok := agentOf(name); !ok {
			// The name, as echoed, is masked as one value (a URL's user name
			// and password); one holding an at-sign comes before its
			// explanation, which the fail-safe then keeps.
			shown := clientctx.MaskURLInValue(name)
			if clientctx.HasAtSign(shown) {
				return nil, &Error{shown + ": unknown coding agent; known: " + strings.Join(known, ", "), true}
			}
			return nil, &Error{"unknown coding agent " + shown + "; known: " + strings.Join(known, ", "), true}
		}
	}
	if opts.Scope == "user" && len(opts.Agents) > 0 {
		return nil, &Error{"--agent applies to a project: its adapters edit the project's files", true}
	}
	if opts.Scope == "user" && opts.Guardrails {
		return nil, &Error{"--guardrails applies to a project: it edits the project's coding-agent settings", true}
	}
	if opts.Scope == "user" && opts.MCP {
		return nil, &Error{"--mcp applies to a project: it edits the project's MCP files", true}
	}
	// Nothing is read, written, removed or pruned through a link below the
	// root: refused before the plan reads anything, and again for every file
	// it would change, before anything is changed.
	for _, dir := range scopeDirs(opts) {
		if link := linkBelow(opts.Root, dir); link != "" {
			return nil, refuseBefore(opts, link)
		}
	}
	var p plan
	if err := p.build(opts); err != nil {
		return nil, err
	}
	for _, file := range p.files {
		rel := relative(opts.Root, file.path)
		if link := linkBelow(opts.Root, filepath.Dir(rel)); link != "" {
			return nil, refuseBefore(opts, link)
		}
		// A file it would change or remove that has a name it cannot see (a
		// hard link, perhaps outside the root), or, outside a managed pair,
		// any second name.
		if opts.Mode != "check" && !isSymlink(file.path) {
			current, st, err := readBytes(file.path)
			changes := err == nil && st == isText && (file.desired == nil || !sameBytes(current, *file.desired))
			if changes {
				if err := checkHardLinks(opts.Root, rel, opts.Scope != "user"); err != nil {
					return nil, err
				}
			}
		}
	}
	w := &writer{path: opts.Root, pairs: opts.Scope != "user"}
	defer w.close()
	// Names a removal took away with their file (a hard-linked pair): never
	// reported twice, nor written again by a later row for the same file.
	gone := map[string]bool{}
	result := &Result{Scope: opts.Scope, Root: opts.Root, Changes: []Change{}, Manual: p.manual, LeftInPlace: p.leftInPlace, Notices: p.notices}
	for _, file := range p.files {
		rel := filepath.ToSlash(relative(opts.Root, file.path))
		if gone[rel] {
			continue
		}
		current, st, err := readBytes(file.path)
		if err != nil {
			return nil, err
		}
		if st == notText {
			return nil, &Error{relative(opts.Root, file.path) + " is not a file; move it, then run this again", false}
		}
		var action string
		switch {
		case file.desired == nil && st == missing:
			action = "unchanged"
		case file.desired == nil:
			action = "remove"
		case st == missing:
			action = "create"
		case sameBytes(current, *file.desired):
			action = "unchanged"
		default:
			action = "update"
		}
		// Never through a link: it stays as it is, and the human gets the edit.
		if action != "unchanged" && isSymlink(file.path) {
			result.Manual = append(result.Manual, rel+" is a symbolic link, so the CLI does not write through it: replace it with a file, then run this again")
			continue
		}
		result.Changes = append(result.Changes, Change{Path: rel, Action: action})
		if opts.Mode == "check" || action == "unchanged" {
			continue
		}
		if file.desired == nil {
			others, err := w.remove(relative(opts.Root, file.path))
			if err != nil {
				return nil, err
			}
			for _, other := range others {
				name := filepath.ToSlash(other)
				gone[name] = true
				result.Changes = append(result.Changes, Change{Path: name, Action: "remove"})
			}
			continue
		}
		if err := w.write(relative(opts.Root, file.path), []byte(*file.desired)); err != nil {
			return nil, err
		}
	}
	if opts.Mode == "remove" {
		for _, base := range append(slices.Clone(skillBases), ".codex", ".cursor", ".vscode", ".gemini") {
			if err := pruneEmpty(w, opts.Root, base); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range opts.Agents {
		a, _ := agentOf(name)
		result.Agents = append(result.Agents, AgentReads{name, a.reads})
	}
	for _, c := range result.Changes {
		if c.Action != "unchanged" {
			result.Drift = true
		}
	}
	return result, nil
}

// Describe is describeInstall: the human-readable lines for a result.
func Describe(result *Result, mode Mode) []string {
	verb := map[string]string{"create": "created", "update": "updated", "remove": "removed"}
	if mode == "check" {
		verb = map[string]string{"create": "missing:", "update": "differs:", "remove": "extra:"}
	}
	var lines []string
	for _, c := range result.Changes {
		if c.Action != "unchanged" {
			lines = append(lines, verb[c.Action]+" "+c.Path)
		}
	}
	if len(lines) == 0 {
		if mode == "remove" {
			lines = append(lines, "Nothing to remove.")
		} else {
			lines = append(lines, "The agent files are up to date.")
		}
	}
	for _, m := range result.Manual {
		lines = append(lines, "To do by hand: "+m)
	}
	for _, l := range result.LeftInPlace {
		lines = append(lines, "Left in place: "+l)
	}
	for _, n := range result.Notices {
		lines = append(lines, "Note: "+n)
	}
	for _, a := range result.Agents {
		lines = append(lines, a.Agent+" reads "+a.Reads)
	}
	return lines
}

// ChangedTargets is changedTargets: what a result changed, one entry per
// skill directory or file, for `init`'s one-line summary.
func ChangedTargets(result *Result) []string {
	var targets []string
	for _, c := range result.Changes {
		if c.Action == "unchanged" {
			continue
		}
		target := c.Path
		for _, b := range skillBases {
			base := filepath.ToSlash(b)
			if strings.HasPrefix(c.Path, base+"/") {
				target = base + "/"
				break
			}
		}
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return targets
}

// JSON is the result as `--json` prints it, after the schema version.
func (r *Result) JSON() jsjson.Object {
	changes := make([]any, len(r.Changes))
	for i, c := range r.Changes {
		changes[i] = jsjson.Object{{Key: "path", Value: c.Path}, {Key: "action", Value: c.Action}}
	}
	agents := make([]any, len(r.Agents))
	for i, a := range r.Agents {
		agents[i] = jsjson.Object{{Key: "agent", Value: a.Agent}, {Key: "reads", Value: a.Reads}}
	}
	return jsjson.Object{
		{Key: "scope", Value: r.Scope},
		{Key: "root", Value: r.Root},
		{Key: "changes", Value: changes},
		{Key: "manual", Value: strs(r.Manual)},
		{Key: "leftInPlace", Value: strs(r.LeftInPlace)},
		{Key: "agents", Value: agents},
		{Key: "notices", Value: strs(r.Notices)},
		{Key: "drift", Value: r.Drift},
	}
}

func strs(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}
