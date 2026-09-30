// SPDX-License-Identifier: Apache-2.0
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { isCanonicalJson, type Staging } from "./files.js";
import { isTable, parseTomlOrNull, withTomlPart } from "./toml.js";

/**
 * `varlatch agents install --mcp` (ADR-0043 Decisions 7 and 9): a
 * `varlatch` server entry that runs `varlatch mcp`, in the project MCP
 * configuration of the coding agents that use one. MCP is the secondary
 * interface, for hosts without a shell; a coding agent with a shell uses the
 * CLI directly.
 *
 * JSON files are edited only when they are two-space JSON, and the entry is
 * named `varlatch`, so `--remove` takes out an entry equal to the one the
 * CLI writes and names one that differs. The Codex entry is a marked TOML
 * block that `--remove` takes back byte for byte.
 */

type Json = Record<string, unknown>;

interface JsonTarget {
  format: "json";
  /** The key that holds the servers. */
  key: string;
  entry: Json;
}

interface TomlTarget {
  format: "toml";
}

/** The project MCP files, by path, and what the Varlatch entry looks like in each. */
export const MCP_TARGETS: Readonly<Record<string, JsonTarget | TomlTarget>> = {
  ".mcp.json": { format: "json", key: "mcpServers", entry: { command: "varlatch", args: ["mcp"] } },
  [join(".cursor", "mcp.json")]: { format: "json", key: "mcpServers", entry: { type: "stdio", command: "varlatch", args: ["mcp"] } },
  [join(".vscode", "mcp.json")]: { format: "json", key: "servers", entry: { type: "stdio", command: "varlatch", args: ["mcp"] } },
  [join(".gemini", "settings.json")]: { format: "json", key: "mcpServers", entry: { command: "varlatch", args: ["mcp"] } },
  "opencode.json": { format: "json", key: "mcp", entry: { type: "local", command: ["varlatch", "mcp"] } },
  [join(".codex", "config.toml")]: { format: "toml" },
};

/** The MCP files each coding agent reads (VS Code's Copilot reads .vscode/mcp.json; its CLI, .mcp.json). */
export const MCP_FILES_BY_AGENT: Readonly<Record<string, readonly string[]>> = {
  "claude-code": [".mcp.json"],
  copilot: [".mcp.json", join(".vscode", "mcp.json")],
  cursor: [join(".cursor", "mcp.json")],
  gemini: [join(".gemini", "settings.json")],
  opencode: ["opencode.json"],
  codex: [join(".codex", "config.toml")],
};

const SERVER = "varlatch";
const CODEX_MCP_BODY = ['command = "varlatch"', 'args = ["mcp"]'];

export interface McpPlan {
  manual: string[];
  leftInPlace: string[];
  notices: string[];
}

function display(path: string): string {
  return path.split("\\").join("/");
}

/** Written the way the CLI reads it back: two-space JSON, with a final line break only if the file had one. */
function serialize(value: Json, raw: string | null): string {
  return `${JSON.stringify(value, null, 2)}${raw !== null && !raw.endsWith("\n") ? "" : "\n"}`;
}

/**
 * The MCP entries for a project. `install` writes to the files of the
 * coding agents named with --agent and to every MCP file that already
 * exists, or, when that is none, to .mcp.json. `--remove` takes the entry
 * out of every MCP file.
 */
export function planMcp(root: string, agents: string[], mode: "install" | "check" | "remove", staging: Staging): McpPlan {
  const plan: McpPlan = { manual: [], leftInPlace: [], notices: [] };
  const remove = mode === "remove";
  const at = (p: string) => join(root, p);
  let paths: string[];
  if (remove) paths = Object.keys(MCP_TARGETS);
  else {
    const named = new Set(agents.flatMap((agent) => MCP_FILES_BY_AGENT[agent] ?? []));
    for (const agent of agents) {
      if (!(agent in MCP_FILES_BY_AGENT)) plan.notices.push(`${agent} has no project MCP file the CLI writes; add "varlatch mcp" to its MCP settings if it uses MCP`);
    }
    for (const path of Object.keys(MCP_TARGETS)) if (staging.read(at(path)) !== null) named.add(path);
    if (named.size === 0 && agents.length === 0) named.add(".mcp.json");
    paths = [...named];
  }

  for (const path of paths) {
    const target = MCP_TARGETS[path] as JsonTarget | TomlTarget;
    const raw = staging.read(at(path));
    if (raw === undefined) {
      if (!remove) plan.manual.push(`${display(path)} is not a UTF-8 text file, so the CLI leaves it as it is: add a "varlatch" MCP server running "varlatch mcp"`);
      continue;
    }
    if (target.format === "toml") {
      if (remove) {
        if (raw !== null) {
          const { next } = withTomlPart(raw, "[mcp_servers.varlatch]", null);
          if (next !== raw) staging.write(at(path), next);
        }
        continue;
      }
      const before = parseTomlOrNull(raw ?? "");
      const servers = before === null ? undefined : before.mcp_servers;
      const existing = isTable(servers) ? servers[SERVER] : undefined;
      if (existing !== undefined) {
        if (!(isTable(existing) && existing.command === "varlatch" && isDeepStrictEqual([...((existing.args as unknown[]) ?? [])], ["mcp"]))) {
          plan.manual.push(`${display(path)} already has an mcp_servers.varlatch entry that differs from "varlatch mcp"; the CLI leaves it`);
        }
        continue;
      }
      const { next, reason } = withTomlPart(raw, "[mcp_servers.varlatch]", CODEX_MCP_BODY, (b) => ({
        ...b,
        mcp_servers: { ...(isTable(b.mcp_servers) ? b.mcp_servers : {}), [SERVER]: { command: "varlatch", args: ["mcp"] } },
      }));
      if (next === null) plan.manual.push(`add [mcp_servers.varlatch] with command = "varlatch" and args = ["mcp"] to ${display(path)} (${reason})`);
      else staging.write(at(path), next);
      plan.notices.push("Codex uses a project's MCP servers only once you trust the project");
      continue;
    }

    let parsed: unknown = raw === null ? {} : undefined;
    if (raw !== null) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = undefined;
      }
    }
    const editable = isTable(parsed) && (raw === null || isCanonicalJson(raw, parsed));
    const container = isTable(parsed) ? parsed[target.key] : undefined;
    const existing = isTable(container) ? container[SERVER] : undefined;
    if (remove) {
      if (existing === undefined || !isTable(parsed) || !isTable(container)) continue;
      if (!isDeepStrictEqual(existing, target.entry)) {
        plan.leftInPlace.push(`the "varlatch" server in ${display(path)}, which differs from the one the CLI writes`);
      } else if (!editable) {
        plan.manual.push(`remove the "varlatch" server from ${target.key} in ${display(path)}`);
      } else {
        const { [SERVER]: _ours, ...others } = container;
        const { [target.key]: _container, ...rest } = parsed;
        const next = Object.keys(others).length > 0 ? { ...rest, [target.key]: others } : rest;
        staging.write(at(path), Object.keys(next).length > 0 ? serialize(next, raw) : null);
      }
      continue;
    }
    const snippet = `add "varlatch": ${JSON.stringify(target.entry)} under ${target.key} in ${display(path)}`;
    if (!editable || (container !== undefined && !isTable(container))) {
      plan.manual.push(`${snippet} (the CLI edits the file only when that keeps its formatting)`);
      continue;
    }
    if (existing !== undefined) {
      if (!isDeepStrictEqual(existing, target.entry)) plan.manual.push(`${display(path)} already has a "varlatch" server that differs from the CLI's; the CLI leaves it`);
      continue;
    }
    const next = { ...(parsed as Json), [target.key]: { ...((container as Json | undefined) ?? {}), [SERVER]: target.entry } };
    staging.write(at(path), serialize(next, raw));
    if (path === ".mcp.json") plan.notices.push("Claude Code asks before it uses a project's .mcp.json servers");
  }
  return plan;
}
