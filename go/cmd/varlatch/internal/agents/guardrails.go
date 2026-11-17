// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/toml"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch agents install --guardrails` (ADR-0043 Decision 8), the files
// it writes: a port of apps/cli/src/agents/guardrails.ts. Opt-in settings
// in coding agents' own files: VARLATCH_ASSISTED=1 where the settings can
// set the shells' environment, and a pre-tool-use hook that calls
// `varlatch agents hook --format <agent>` (the hook itself is slice 5.6a).
// Accident prevention, not a boundary.

type sidePlan struct {
	manual      []string
	leftInPlace []string
	notices     []string
}

// guardrailAgents are the coding agents with guardrails, and the hook
// format each one's hooks use, in GUARDRAIL_AGENTS' order.
var guardrailAgents = []struct{ agent, format string }{{"claude-code", "claude"}, {"codex", "codex"}}

func hasGuardrails(agent string) bool {
	return slices.ContainsFunc(guardrailAgents, func(g struct{ agent, format string }) bool { return g.agent == agent })
}

// HookCommand is the command a guardrail hook runs.
func HookCommand(format string) string { return "varlatch agents hook --format " + format }

// claudeMatcher is the tools the Claude Code hook runs for: the shell, the
// file tools, and MCP tools.
const claudeMatcher = "Bash|Read|Grep|Edit|MultiEdit|Write|NotebookEdit|mcp__.*"

// ClaudeDeny are static rules for when the hook cannot run: the documented
// .env patterns, and the credential store.
var ClaudeDeny = []string{"Read(./.env)", "Read(./.env.local)", "Read(./.env.*.local)", "Read(~/.config/varlatch/**)"}

const hookTimeoutSeconds = 30

func hasHook(entries any, command string) bool {
	list, ok := entries.([]any)
	if !ok {
		return false
	}
	for _, e := range list {
		hooks, ok := get(e, "hooks")
		inner, isList := hooks.([]any)
		if !ok || !isList {
			continue
		}
		for _, h := range inner {
			if c, ok := get(h, "command"); ok && c == any(command) {
				return true
			}
		}
	}
	return false
}

// withHook is a settings object with the CLI's PreToolUse entry added, or
// the reason it cannot be ("" and the object otherwise).
func withHook(settings jsjson.Object, command string, matcher string) (jsjson.Object, string) {
	hooks, present := settings.Get("hooks")
	if !present || hooks == nil {
		hooks = jsjson.Object{}
	}
	hooksObject, ok := hooks.(jsjson.Object)
	if !ok {
		return nil, "its hooks setting is not an object"
	}
	pre, present := hooksObject.Get("PreToolUse")
	if !present || pre == nil {
		pre = []any{}
	}
	list, ok := pre.([]any)
	if !ok {
		return nil, "its hooks.PreToolUse setting is not a list"
	}
	if hasHook(list, command) {
		return settings, ""
	}
	entry := jsjson.Object{}
	if matcher != "" {
		entry = append(entry, jsjson.Member{Key: "matcher", Value: matcher})
	}
	entry = append(entry, jsjson.Member{Key: "hooks", Value: []any{jsjson.Object{
		{Key: "type", Value: "command"},
		{Key: "command", Value: command},
		{Key: "timeout", Value: float64(hookTimeoutSeconds)},
	}}})
	return with(settings, "hooks", with(hooksObject, "PreToolUse", append(slices.Clone(list), entry))), ""
}

// withoutHook is a settings object without the hooks that call command,
// and without hook containers left empty.
func withoutHook(settings jsjson.Object, command string) jsjson.Object {
	hooksValue, _ := settings.Get("hooks")
	hooks, ok := hooksValue.(jsjson.Object)
	if !ok {
		return settings
	}
	preValue, _ := hooks.Get("PreToolUse")
	preList, ok := preValue.([]any)
	if !ok {
		return settings
	}
	var pre []any
	for _, e := range preList {
		inner, _ := get(e, "hooks")
		innerList, ok := inner.([]any)
		if !isObject(e) || !ok {
			pre = append(pre, e)
			continue
		}
		var kept []any
		for _, h := range innerList {
			if c, ok := get(h, "command"); ok && isObject(h) && c == any(command) {
				continue
			}
			kept = append(kept, h)
		}
		switch {
		case len(kept) == len(innerList):
			pre = append(pre, e)
		case len(kept) > 0:
			pre = append(pre, with(e.(jsjson.Object), "hooks", kept))
		}
	}
	// The destructured keys come back last: {...otherHooks, PreToolUse}, {...rest, hooks}.
	otherHooks := without(hooks, "PreToolUse")
	next := otherHooks
	if len(pre) > 0 {
		next = append(otherHooks, jsjson.Member{Key: "PreToolUse", Value: pre})
	}
	rest := without(settings, "hooks")
	if len(next) > 0 {
		return append(rest, jsjson.Member{Key: "hooks", Value: next})
	}
	return rest
}

// withClaudeGuardrails is Claude Code's settings with the guardrails: the
// environment variable, the deny rules, the hook.
func withClaudeGuardrails(settings jsjson.Object) (jsjson.Object, []string) {
	var manual []string
	next := append(jsjson.Object(nil), settings...)
	env, present := next.Get("env")
	if !present || env == nil {
		env = jsjson.Object{}
	}
	if envObject, ok := env.(jsjson.Object); !ok {
		manual = append(manual, `set "VARLATCH_ASSISTED": "1" under env in .claude/settings.json (its env setting is not an object)`)
	} else if value, set := envObject.Get("VARLATCH_ASSISTED"); !set {
		next = with(next, "env", with(envObject, "VARLATCH_ASSISTED", "1"))
	} else if value != any("1") {
		manual = append(manual, ".claude/settings.json sets VARLATCH_ASSISTED to "+string(jsjson.Stringify(value))+
			`; the guardrails leave it (set it to "1" for assisted mode in every command)`)
	}
	permissions, present := next.Get("permissions")
	if !present || permissions == nil {
		permissions = jsjson.Object{}
	}
	permissionsObject, ok := permissions.(jsjson.Object)
	deny, denyPresent := get(permissions, "deny")
	denyList, denyIsList := deny.([]any)
	if !ok || (denyPresent && !denyIsList) {
		manual = append(manual, "add "+strings.Join(ClaudeDeny, ", ")+" to permissions.deny in .claude/settings.json")
	} else {
		var missingRules []any
		for _, rule := range ClaudeDeny {
			if !includes(denyList, rule) {
				missingRules = append(missingRules, rule)
			}
		}
		if len(missingRules) > 0 {
			next = with(next, "permissions", with(permissionsObject, "deny", append(slices.Clone(denyList), missingRules...)))
		}
	}
	hooked, refused := withHook(next, HookCommand("claude"), claudeMatcher)
	if refused != "" {
		manual = append(manual, `add the hook "`+HookCommand("claude")+`" under hooks.PreToolUse in .claude/settings.json (`+refused+")")
	} else {
		next = hooked
	}
	return next, manual
}

var codexEnvBody = []string{`VARLATCH_ASSISTED = "1"`}

// withCodexEnv is Codex's config.toml with VARLATCH_ASSISTED = "1" in
// shell_environment_policy.set, in the CLI's marked region, or the reason
// the CLI leaves it.
func withCodexEnv(current desired) tomlEdit {
	text := ""
	if current != nil {
		text = *current
	}
	before := parseTOML(text)
	if before == nil {
		return tomlEdit{refused: "it does not parse as TOML"}
	}
	policy, _ := before.Get("shell_environment_policy")
	set, setPresent := tget(policy, "set")
	if isTable(set) {
		if v, _ := tget(set, "VARLATCH_ASSISTED"); v == any("1") {
			return tomlEdit{next: current}
		}
	}
	if setPresent {
		return tomlEdit{refused: "it already has a shell_environment_policy.set"}
	}
	return withTOMLPart(current, partEnv, codexEnvBody, func(b *toml.Table) *toml.Table {
		policy := toml.NewTable()
		if p, _ := b.Get("shell_environment_policy"); isTable(p) {
			policy = p.(*toml.Table).Clone()
		}
		set := toml.NewTable()
		set.Set("VARLATCH_ASSISTED", "1")
		policy.Set("set", set)
		out := b.Clone()
		out.Set("shell_environment_policy", policy)
		return out
	})
}

// jsonFile is a JSON settings file as guardrails.ts's readJson reads it.
type jsonFile struct {
	raw      content
	parsed   jsjson.Object // nil when it is not a JSON object
	editable bool
}

func readJSONFile(st *staging, path string) (jsonFile, error) {
	raw, err := st.read(path)
	if err != nil {
		return jsonFile{}, err
	}
	if raw.state != isText {
		f := jsonFile{raw: raw}
		if raw.state == missing {
			f.parsed, f.editable = jsjson.Object{}, true
		}
		return f, nil
	}
	v, ok := parseJSON(raw.text)
	o, isObj := v.(jsjson.Object)
	if !ok || !isObj {
		return jsonFile{raw: raw}, nil
	}
	return jsonFile{raw: raw, parsed: o, editable: isCanonicalJSON(raw.text, o)}, nil
}

// serializeJSON is how the CLI writes a settings file: two-space JSON, with
// a final line break only if the file had one.
func serializeJSON(value jsjson.Object, raw content) string {
	if raw.state == isText && !strings.HasSuffix(raw.text, "\n") {
		return stringify2(value)
	}
	return stringify2(value) + "\n"
}

// planGuardrails is the guardrail changes for a project. install guards the
// coding agents named with --agent, or else Claude Code and Codex when
// .codex exists. --remove takes the CLI's entries out of every coding
// agent's files.
func planGuardrails(root string, agents []string, mode Mode, st *staging) (sidePlan, error) {
	var plan sidePlan
	at := func(p string) string { return filepath.Join(root, p) }
	remove := mode == "remove"
	var named []string
	for _, a := range agents {
		if hasGuardrails(a) {
			named = append(named, a)
		} else {
			plan.notices = append(plan.notices, a+" has no guardrails yet; the skill and AGENTS.md still apply")
		}
	}
	guard := func(agent, dir string) bool {
		return remove || slices.Contains(named, agent) || (len(agents) == 0 && (dir == "" || exists(at(dir))))
	}

	if guard("claude-code", "") {
		path := at(filepath.Join(".claude", "settings.json"))
		file, err := readJSONFile(st, path)
		if err != nil {
			return plan, err
		}
		cmd := HookCommand("claude")
		switch {
		case remove:
			if file.parsed != nil && file.raw.state != missing {
				next := withoutHook(file.parsed, cmd)
				if !deepEqual(next, file.parsed) {
					if file.editable {
						if len(next) > 0 {
							st.write(path, ptr(serializeJSON(next, file.raw)))
						} else {
							st.write(path, nil)
						}
					} else {
						plan.manual = append(plan.manual, `remove the hook "`+cmd+`" from .claude/settings.json`)
					}
				}
				env, _ := file.parsed.Get("env")
				if v, ok := get(env, "VARLATCH_ASSISTED"); ok && v == any("1") {
					plan.leftInPlace = append(plan.leftInPlace, `"VARLATCH_ASSISTED": "1" under env in .claude/settings.json`)
				}
				permissions, _ := file.parsed.Get("permissions")
				denyValue, _ := get(permissions, "deny")
				deny, _ := denyValue.([]any)
				var ours []string
				for _, rule := range ClaudeDeny {
					if includes(deny, rule) {
						ours = append(ours, rule)
					}
				}
				if len(ours) > 0 {
					plan.leftInPlace = append(plan.leftInPlace, strings.Join(ours, ", ")+" in permissions.deny in .claude/settings.json")
				}
			}
		case file.parsed == nil || !file.editable:
			plan.manual = append(plan.manual,
				"add the Claude Code guardrails to .claude/settings.json by hand (the CLI edits it only when it is two-space JSON): "+
					`"env": {"VARLATCH_ASSISTED": "1"}, permissions.deny `+strings.Join(ClaudeDeny, ", ")+`, and a PreToolUse hook running "`+cmd+`"`)
		default:
			next, manual := withClaudeGuardrails(file.parsed)
			plan.manual = append(plan.manual, manual...)
			if !deepEqual(next, file.parsed) || file.raw.state == missing {
				st.write(path, ptr(serializeJSON(next, file.raw)))
			}
		}
	}

	if guard("codex", ".codex") {
		hooksPath := at(filepath.Join(".codex", "hooks.json"))
		hooks, err := readJSONFile(st, hooksPath)
		if err != nil {
			return plan, err
		}
		cmd := HookCommand("codex")
		switch {
		case remove:
			if hooks.parsed != nil && hooks.raw.state != missing {
				next := withoutHook(hooks.parsed, cmd)
				if !deepEqual(next, hooks.parsed) {
					if hooks.editable {
						if len(next) > 0 {
							st.write(hooksPath, ptr(serializeJSON(next, hooks.raw)))
						} else {
							st.write(hooksPath, nil)
						}
					} else {
						plan.manual = append(plan.manual, `remove the hook "`+cmd+`" from .codex/hooks.json`)
					}
				}
			}
		case hooks.parsed == nil || !hooks.editable:
			plan.manual = append(plan.manual, `add a PreToolUse hook running "`+cmd+`" to .codex/hooks.json (the CLI edits it only when it is two-space JSON)`)
		default:
			next, refused := withHook(hooks.parsed, cmd, "")
			if refused != "" {
				plan.manual = append(plan.manual, `add a PreToolUse hook running "`+cmd+`" to .codex/hooks.json (`+refused+")")
			} else if !deepEqual(next, hooks.parsed) || hooks.raw.state == missing {
				st.write(hooksPath, ptr(serializeJSON(next, hooks.raw)))
			}
		}

		configPath := at(filepath.Join(".codex", "config.toml"))
		config, err := st.read(configPath)
		if err != nil {
			return plan, err
		}
		switch {
		case remove:
			if config.state == isText {
				edit := withoutTOMLPart(config.text, partEnv, codexEnvBody)
				if edit.refused != "" {
					plan.leftInPlace = append(plan.leftInPlace, "VARLATCH_ASSISTED in .codex/config.toml ("+edit.refused+"; take it out by hand)")
				} else if edit.next == nil || *edit.next != config.text {
					st.write(configPath, edit.next)
				}
			}
		case config.state == notText:
			plan.manual = append(plan.manual, `.codex/config.toml is not a UTF-8 text file, so the CLI leaves it as it is: set VARLATCH_ASSISTED = "1" in [shell_environment_policy.set]`)
		default:
			var current desired
			if config.state == isText {
				current = ptr(config.text)
			}
			edit := withCodexEnv(current)
			if edit.refused != "" {
				plan.manual = append(plan.manual, `set VARLATCH_ASSISTED = "1" in shell_environment_policy.set in .codex/config.toml (`+edit.refused+")")
			} else if !sameDesired(edit.next, current) {
				st.write(configPath, edit.next)
			}
		}
		if !remove {
			plan.notices = append(plan.notices, "Codex reads a project's .codex/ settings and hooks only once you trust the project, and runs each hook after you review it (/hooks)")
		}
	}
	return plan, nil
}

// sameDesired is a === b for two string | null values.
func sameDesired(a, b desired) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
