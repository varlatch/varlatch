// SPDX-License-Identifier: Apache-2.0
import { existsSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { isCanonicalJson, type Staging } from "./files.js";
import { isTable, parseTomlOrNull, withTomlPart } from "./toml.js";
import type { HookFormat } from "./hook.js";

/**
 * `varlatch agents install --guardrails` (ADR-0043 Decision 8): opt-in
 * settings in coding agents' own files. `VARLATCH_ASSISTED=1` where the
 * settings can set the shells' environment, and a pre-tool-use hook that
 * calls the one handler, `varlatch agents hook --format <agent>`.
 *
 * Accident prevention, not a boundary: a hook fails open when the CLI is
 * missing, and the agent's shell can read what its file tools cannot.
 *
 * JSON settings are edited only when they are formatted the way the CLI
 * writes them (two-space JSON), since JSON keeps no comments to mark an
 * entry as the CLI's. `--remove` takes out the hook entries, which name the
 * handler, and reports the environment and deny entries it leaves. TOML
 * gets a marked, exact addition that `--remove` takes back byte for byte.
 */

export interface GuardrailPlan {
  manual: string[];
  leftInPlace: string[];
  notices: string[];
}

/** The coding agents with guardrails, and the handler format each one's hooks use. */
export const GUARDRAIL_AGENTS: Readonly<Record<string, HookFormat>> = { "claude-code": "claude", codex: "codex" };

export function hookCommand(format: HookFormat): string {
  return `varlatch agents hook --format ${format}`;
}

/** Tools the Claude Code hook runs for: the shell, the file tools, and MCP tools. */
const CLAUDE_MATCHER = "Bash|Read|Grep|Edit|MultiEdit|Write|NotebookEdit|mcp__.*";
/** Static rules for when the hook cannot run: the documented .env patterns, and the credential store. */
export const CLAUDE_DENY = ["Read(./.env)", "Read(./.env.local)", "Read(./.env.*.local)", "Read(~/.config/varlatch/**)"];
const HOOK_TIMEOUT_SECONDS = 30;

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasHook(entries: unknown, command: string): boolean {
  return Array.isArray(entries) && entries.some((e) => isObject(e) && Array.isArray(e.hooks) && e.hooks.some((h) => isObject(h) && h.command === command));
}

/** A settings object with our PreToolUse entry added, or the reason it cannot be. */
function withHook(settings: Json, command: string, matcher: string | null): Json | string {
  const hooks = settings.hooks ?? {};
  if (!isObject(hooks)) return "its hooks setting is not an object";
  const pre = hooks.PreToolUse ?? [];
  if (!Array.isArray(pre)) return "its hooks.PreToolUse setting is not a list";
  if (hasHook(pre, command)) return settings;
  const entry = { ...(matcher === null ? {} : { matcher }), hooks: [{ type: "command", command, timeout: HOOK_TIMEOUT_SECONDS }] };
  return { ...settings, hooks: { ...hooks, PreToolUse: [...pre, entry] } };
}

/** A settings object without the hooks that call `command`, and without hook containers left empty. */
function withoutHook(settings: Json, command: string): Json {
  if (!isObject(settings.hooks) || !Array.isArray(settings.hooks.PreToolUse)) return settings;
  const pre = settings.hooks.PreToolUse.flatMap((e) => {
    if (!isObject(e) || !Array.isArray(e.hooks)) return [e];
    const kept = e.hooks.filter((h) => !(isObject(h) && h.command === command));
    if (kept.length === e.hooks.length) return [e];
    return kept.length === 0 ? [] : [{ ...e, hooks: kept }];
  });
  const { PreToolUse: _pre, ...otherHooks } = settings.hooks;
  const hooks = pre.length > 0 ? { ...otherHooks, PreToolUse: pre } : otherHooks;
  const { hooks: _hooks, ...rest } = settings;
  return Object.keys(hooks).length > 0 ? { ...rest, hooks } : rest;
}

/** Claude Code's settings with the guardrails: the environment variable, the deny rules, the hook. */
export function withClaudeGuardrails(settings: Json): { next: Json; manual: string[] } {
  const manual: string[] = [];
  let next: Json = { ...settings };
  const env = next.env ?? {};
  if (!isObject(env)) manual.push('set "VARLATCH_ASSISTED": "1" under env in .claude/settings.json (its env setting is not an object)');
  else if (env.VARLATCH_ASSISTED === undefined) next = { ...next, env: { ...env, VARLATCH_ASSISTED: "1" } };
  else if (env.VARLATCH_ASSISTED !== "1") {
    manual.push(`.claude/settings.json sets VARLATCH_ASSISTED to ${JSON.stringify(env.VARLATCH_ASSISTED)}; the guardrails leave it (set it to "1" for assisted mode in every command)`);
  }
  const permissions = next.permissions ?? {};
  if (!isObject(permissions) || (permissions.deny !== undefined && !Array.isArray(permissions.deny))) {
    manual.push(`add ${CLAUDE_DENY.join(", ")} to permissions.deny in .claude/settings.json`);
  } else {
    const deny = (permissions.deny as unknown[] | undefined) ?? [];
    const missing = CLAUDE_DENY.filter((rule) => !deny.includes(rule));
    if (missing.length > 0) next = { ...next, permissions: { ...permissions, deny: [...deny, ...missing] } };
  }
  const hooked = withHook(next, hookCommand("claude"), CLAUDE_MATCHER);
  if (typeof hooked === "string") manual.push(`add the hook "${hookCommand("claude")}" under hooks.PreToolUse in .claude/settings.json (${hooked})`);
  else next = hooked;
  return { next, manual };
}

/** Codex's hooks file with the handler added. */
export function withCodexHook(hooksFile: Json): Json | string {
  return withHook(hooksFile, hookCommand("codex"), null);
}

/**
 * Codex's config.toml with `VARLATCH_ASSISTED = "1"` in
 * shell_environment_policy.set, in the CLI's marked region, or null with a
 * reason (see withTomlPart: the parser judges whether the change is safe).
 */
export function withCodexEnv(current: string | null): { next: string | null; reason?: string } {
  const before = parseTomlOrNull(current ?? "");
  if (before === null) return { next: null, reason: "it does not parse as TOML" };
  const policy = before.shell_environment_policy;
  const set = isTable(policy) ? policy.set : undefined;
  if (isTable(set) && set.VARLATCH_ASSISTED === "1") return { next: current };
  if (set !== undefined) return { next: null, reason: "it already has a shell_environment_policy.set" };
  return withTomlPart(current, "[shell_environment_policy.set]", ['VARLATCH_ASSISTED = "1"'], (b) => ({
    ...b,
    shell_environment_policy: { ...(isTable(b.shell_environment_policy) ? b.shell_environment_policy : {}), set: { VARLATCH_ASSISTED: "1" } },
  }));
}

/** config.toml without the CLI's environment table (null: nothing else was in the file). */
export function withoutCodexEnv(current: string): string | null {
  return withTomlPart(current, "[shell_environment_policy.set]", null).next;
}

interface JsonFile {
  raw: string | null | undefined;
  parsed: Json | null;
  editable: boolean;
}

function readJson(staging: Staging, path: string): JsonFile {
  const raw = staging.read(path);
  if (typeof raw !== "string") return { raw, parsed: raw === null ? {} : null, editable: raw === null };
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isObject(parsed)) return { raw, parsed: null, editable: false };
    return { raw, parsed, editable: isCanonicalJson(raw, parsed) };
  } catch {
    return { raw, parsed: null, editable: false };
  }
}

/** Written the way the CLI reads it back: two-space JSON, with a final line break only if the file had one. */
function serialize(value: Json, raw: string | null | undefined): string {
  return `${JSON.stringify(value, null, 2)}${typeof raw === "string" && !raw.endsWith("\n") ? "" : "\n"}`;
}

/**
 * The guardrail changes for a project. `install` guards the coding agents
 * named with --agent, or else Claude Code (whose .claude directory install
 * creates for the skill) and Codex when .codex exists. `--remove` takes the
 * CLI's entries out of every coding agent's files.
 */
export function planGuardrails(root: string, agents: string[], mode: "install" | "check" | "remove", staging: Staging): GuardrailPlan {
  const plan: GuardrailPlan = { manual: [], leftInPlace: [], notices: [] };
  const at = (p: string) => join(root, p);
  const remove = mode === "remove";
  const named = agents.filter((a) => a in GUARDRAIL_AGENTS);
  for (const agent of agents) {
    if (!(agent in GUARDRAIL_AGENTS)) plan.notices.push(`${agent} has no guardrails yet; the skill and AGENTS.md still apply`);
  }
  const guard = (agent: string, dir: string | null) =>
    remove || named.includes(agent) || (agents.length === 0 && (dir === null || existsSync(at(dir))));

  if (guard("claude-code", null)) {
    const path = at(join(".claude", "settings.json"));
    const file = readJson(staging, path);
    if (remove) {
      if (file.parsed !== null && file.raw !== null) {
        const next = withoutHook(file.parsed, hookCommand("claude"));
        if (!isDeepStrictEqual(next, file.parsed)) {
          if (file.editable) staging.write(path, Object.keys(next).length > 0 ? serialize(next, file.raw) : null);
          else plan.manual.push(`remove the hook "${hookCommand("claude")}" from .claude/settings.json`);
        }
        const env = file.parsed.env;
        if (isObject(env) && env.VARLATCH_ASSISTED === "1") plan.leftInPlace.push('"VARLATCH_ASSISTED": "1" under env in .claude/settings.json');
        const deny = isObject(file.parsed.permissions) && Array.isArray(file.parsed.permissions.deny) ? file.parsed.permissions.deny : [];
        const ours = CLAUDE_DENY.filter((rule) => deny.includes(rule));
        if (ours.length > 0) plan.leftInPlace.push(`${ours.join(", ")} in permissions.deny in .claude/settings.json`);
      }
    } else if (file.parsed === null || !file.editable) {
      plan.manual.push(
        `add the Claude Code guardrails to .claude/settings.json by hand (the CLI edits it only when it is two-space JSON): ` +
          `"env": {"VARLATCH_ASSISTED": "1"}, permissions.deny ${CLAUDE_DENY.join(", ")}, and a PreToolUse hook running "${hookCommand("claude")}"`,
     );
    } else {
      const { next, manual } = withClaudeGuardrails(file.parsed);
      plan.manual.push(...manual);
      if (!isDeepStrictEqual(next, file.parsed) || file.raw === null) staging.write(path, serialize(next, file.raw));
    }
  }

  if (guard("codex", ".codex")) {
    const hooksPath = at(join(".codex", "hooks.json"));
    const hooks = readJson(staging, hooksPath);
    if (remove) {
      if (hooks.parsed !== null && hooks.raw !== null) {
        const next = withoutHook(hooks.parsed, hookCommand("codex"));
        if (!isDeepStrictEqual(next, hooks.parsed)) {
          if (hooks.editable) staging.write(hooksPath, Object.keys(next).length > 0 ? serialize(next, hooks.raw) : null);
          else plan.manual.push(`remove the hook "${hookCommand("codex")}" from .codex/hooks.json`);
        }
      }
    } else if (hooks.parsed === null || !hooks.editable) {
      plan.manual.push(`add a PreToolUse hook running "${hookCommand("codex")}" to .codex/hooks.json (the CLI edits it only when it is two-space JSON)`);
    } else {
      const next = withCodexHook(hooks.parsed);
      if (typeof next === "string") plan.manual.push(`add a PreToolUse hook running "${hookCommand("codex")}" to .codex/hooks.json (${next})`);
      else if (!isDeepStrictEqual(next, hooks.parsed) || hooks.raw === null) staging.write(hooksPath, serialize(next, hooks.raw));
    }

    const configPath = at(join(".codex", "config.toml"));
    const config = staging.read(configPath);
    if (remove) {
      if (typeof config === "string") {
        const next = withoutCodexEnv(config);
        if (next !== config) staging.write(configPath, next);
      }
    } else if (config === undefined) {
      plan.manual.push('.codex/config.toml is not a UTF-8 text file, so the CLI leaves it as it is: set VARLATCH_ASSISTED = "1" in [shell_environment_policy.set]');
    } else {
      const { next, reason } = withCodexEnv(config);
      if (next === null) plan.manual.push(`set VARLATCH_ASSISTED = "1" in shell_environment_policy.set in .codex/config.toml (${reason})`);
      else if (next !== config) staging.write(configPath, next);
    }
    if (!remove) plan.notices.push("Codex reads a project's .codex/ settings and hooks only once you trust the project, and runs each hook after you review it (/hooks)");
  }
  return plan;
}
