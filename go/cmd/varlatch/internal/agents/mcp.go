// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/toml"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch agents install --mcp` (ADR-0043 Decisions 7 and 9), a port of
// apps/cli/src/agents/mcpConfig.ts: a `varlatch` server entry that runs
// `varlatch mcp`, in the project MCP configuration of the coding agents that
// use one. JSON files are edited only when they are two-space JSON; the
// Codex entry is a marked TOML block that --remove takes back byte for byte.

type mcpTarget struct {
	path string
	toml bool
	// key holds the servers in a JSON file; entry is the CLI's server there.
	key   string
	entry func() jsjson.Object
}

func stdioEntry(withType string) func() jsjson.Object {
	return func() jsjson.Object {
		o := jsjson.Object{}
		if withType != "" {
			o = append(o, jsjson.Member{Key: "type", Value: withType})
		}
		return append(o, jsjson.Member{Key: "command", Value: "varlatch"}, jsjson.Member{Key: "args", Value: []any{"mcp"}})
	}
}

// mcpTargets are MCP_TARGETS, in order: the project MCP files, and what the
// Varlatch entry looks like in each.
var mcpTargets = []mcpTarget{
	{path: ".mcp.json", key: "mcpServers", entry: stdioEntry("")},
	{path: filepath.Join(".cursor", "mcp.json"), key: "mcpServers", entry: stdioEntry("stdio")},
	{path: filepath.Join(".vscode", "mcp.json"), key: "servers", entry: stdioEntry("stdio")},
	{path: filepath.Join(".gemini", "settings.json"), key: "mcpServers", entry: stdioEntry("")},
	{path: "opencode.json", key: "mcp", entry: func() jsjson.Object {
		return jsjson.Object{{Key: "type", Value: "local"}, {Key: "command", Value: []any{"varlatch", "mcp"}}}
	}},
	{path: filepath.Join(".codex", "config.toml"), toml: true},
}

func mcpTargetOf(path string) mcpTarget {
	for _, t := range mcpTargets {
		if t.path == path {
			return t
		}
	}
	return mcpTarget{}
}

// mcpFilesByAgent are the MCP files each coding agent reads (VS Code's
// Copilot reads .vscode/mcp.json; its CLI, .mcp.json).
var mcpFilesByAgent = map[string][]string{
	"claude-code": {".mcp.json"},
	"copilot":     {".mcp.json", filepath.Join(".vscode", "mcp.json")},
	"cursor":      {filepath.Join(".cursor", "mcp.json")},
	"gemini":      {filepath.Join(".gemini", "settings.json")},
	"opencode":    {"opencode.json"},
	"codex":       {filepath.Join(".codex", "config.toml")},
}

const mcpServer = "varlatch"

var codexMCPBody = []string{`command = "varlatch"`, `args = ["mcp"]`}

func display(path string) string { return strings.ReplaceAll(path, `\`, "/") }

// serializeMCP is mcpConfig.ts's serialize: two-space JSON, with a final
// line break only if the file had one.
func serializeMCP(value jsjson.Object, raw content) string {
	if raw.state != missing && !strings.HasSuffix(raw.text, "\n") {
		return stringify2(value)
	}
	return stringify2(value) + "\n"
}

// planMCP is the MCP entries for a project. install writes to the files of
// the coding agents named with --agent and to every MCP file that already
// exists, or, when that is none, to .mcp.json. --remove takes the entry
// out of every MCP file.
func planMCP(root string, agents []string, mode Mode, st *staging) (sidePlan, error) {
	var plan sidePlan
	remove := mode == "remove"
	at := func(p string) string { return filepath.Join(root, p) }
	var paths []string
	if remove {
		for _, t := range mcpTargets {
			paths = append(paths, t.path)
		}
	} else {
		add := func(p string) {
			if !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
		for _, agent := range agents {
			for _, p := range mcpFilesByAgent[agent] {
				add(p)
			}
		}
		for _, agent := range agents {
			if _, ok := mcpFilesByAgent[agent]; !ok {
				plan.notices = append(plan.notices, agent+` has no project MCP file the CLI writes; add "varlatch mcp" to its MCP settings if it uses MCP`)
			}
		}
		for _, t := range mcpTargets {
			raw, err := st.read(at(t.path))
			if err != nil {
				return plan, err
			}
			if raw.state != missing {
				add(t.path)
			}
		}
		if len(paths) == 0 && len(agents) == 0 {
			add(".mcp.json")
		}
	}

	for _, path := range paths {
		target := mcpTargetOf(path)
		raw, err := st.read(at(path))
		if err != nil {
			return plan, err
		}
		if raw.state == notText {
			if !remove {
				plan.manual = append(plan.manual, display(path)+` is not a UTF-8 text file, so the CLI leaves it as it is: add a "varlatch" MCP server running "varlatch mcp"`)
			}
			continue
		}
		if target.toml {
			planCodexMCP(&plan, st, at(path), path, raw, remove)
			continue
		}
		planJSONMCP(&plan, st, at(path), path, target, raw, remove)
	}
	return plan, nil
}

func planCodexMCP(plan *sidePlan, st *staging, full, path string, raw content, remove bool) {
	if remove {
		if raw.state == isText {
			// A refusal leaves the file as it is: it is never read as "delete the file".
			edit := withoutTOMLPart(raw.text, partMCP, codexMCPBody)
			if edit.refused != "" {
				plan.leftInPlace = append(plan.leftInPlace, partMCP+" in "+display(path)+" ("+edit.refused+"; take it out by hand)")
			} else if edit.next == nil || *edit.next != raw.text {
				st.write(full, edit.next)
			}
		}
		return
	}
	before := parseTOML(raw.text)
	var servers any
	if before != nil {
		servers, _ = before.Get("mcp_servers")
	}
	if existing, ok := tget(servers, mcpServer); ok {
		// A differing entry, whatever its types (args = 12 included), is the human's.
		command, _ := tget(existing, "command")
		args, _ := tget(existing, "args")
		list, isList := args.(*toml.Array)
		if !(isTable(existing) && command == any("varlatch") && isList && len(list.Items) == 1 && list.Items[0] == any("mcp")) {
			plan.manual = append(plan.manual, display(path)+` already has an mcp_servers.varlatch entry that differs from "varlatch mcp"; the CLI leaves it`)
		}
		return
	}
	var current desired
	if raw.state == isText {
		current = ptr(raw.text)
	}
	edit := withTOMLPart(current, partMCP, codexMCPBody, expectMCP)
	if edit.refused != "" {
		plan.manual = append(plan.manual, `add [mcp_servers.varlatch] with command = "varlatch" and args = ["mcp"] to `+display(path)+" ("+edit.refused+")")
	} else {
		st.write(full, edit.next)
	}
	plan.notices = append(plan.notices, "Codex uses a project's MCP servers only once you trust the project")
}

// expectMCP is what config.toml must parse to after the CLI adds its
// server: what it said, with mcp_servers.varlatch set.
func expectMCP(b *toml.Table) *toml.Table {
	servers := toml.NewTable()
	if s, _ := b.Get("mcp_servers"); isTable(s) {
		servers = s.(*toml.Table).Clone()
	}
	entry := toml.NewTable()
	entry.Set("command", "varlatch")
	entry.Set("args", &toml.Array{Items: []any{"mcp"}})
	servers.Set(mcpServer, entry)
	out := b.Clone()
	out.Set("mcp_servers", servers)
	return out
}

func planJSONMCP(plan *sidePlan, st *staging, full, path string, target mcpTarget, raw content, remove bool) {
	var parsed any = jsjson.Object{}
	parsedOK := true
	if raw.state == isText {
		parsed, parsedOK = parseJSON(raw.text)
	}
	object, isObj := parsed.(jsjson.Object)
	isObj = isObj && parsedOK
	editable := isObj && (raw.state == missing || isCanonicalJSON(raw.text, object))
	var container any
	containerPresent := false
	if isObj {
		container, containerPresent = object.Get(target.key)
	}
	containerObject, containerIsObj := container.(jsjson.Object)
	var existing any
	existingPresent := false
	if containerIsObj {
		existing, existingPresent = containerObject.Get(mcpServer)
	}
	entry := target.entry()
	if remove {
		if !existingPresent || !isObj || !containerIsObj {
			return
		}
		switch {
		case !deepEqual(existing, entry):
			plan.leftInPlace = append(plan.leftInPlace, `the "varlatch" server in `+display(path)+", which differs from the one the CLI writes")
		case !editable:
			plan.manual = append(plan.manual, `remove the "varlatch" server from `+target.key+" in "+display(path))
		default:
			others := without(containerObject, mcpServer)
			next := without(object, target.key)
			if len(others) > 0 {
				next = append(next, jsjson.Member{Key: target.key, Value: others})
			}
			if len(next) > 0 {
				st.write(full, ptr(serializeMCP(next, raw)))
			} else {
				st.write(full, nil)
			}
		}
		return
	}
	snippet := `add "varlatch": ` + string(jsjson.Stringify(entry)) + " under " + target.key + " in " + display(path)
	if !editable || (containerPresent && !containerIsObj) {
		plan.manual = append(plan.manual, snippet+" (the CLI edits the file only when that keeps its formatting)")
		return
	}
	if existingPresent {
		if !deepEqual(existing, entry) {
			plan.manual = append(plan.manual, display(path)+` already has a "varlatch" server that differs from the CLI's; the CLI leaves it`)
		}
		return
	}
	servers := jsjson.Object{}
	if containerIsObj {
		servers = containerObject
	}
	st.write(full, ptr(serializeMCP(with(object, target.key, with(servers, mcpServer, entry)), raw)))
	if path == ".mcp.json" {
		plan.notices = append(plan.notices, "Claude Code asks before it uses a project's .mcp.json servers")
	}
}
