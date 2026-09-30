// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, rmdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { SKILL_NAME, skillFiles } from "./skill.js";

/**
 * `varlatch agents install` (ADR-0043 Decision 7): the skill in the paths
 * coding agents read, a short block in AGENTS.md, and small adapters for the
 * coding agents that need more. The per-agent facts are data, in AGENTS.
 *
 * Every write keeps what the CLI did not write: the skill directories are
 * the CLI's own, AGENTS.md changes only inside the marked block, CLAUDE.md
 * and .aider.conf.yml gain one marked line each, and a settings file is
 * edited only when the edit cannot reformat it; otherwise the human gets
 * the exact edit to make. `--check` compares without writing; `--remove`
 * takes back what the CLI wrote.
 */

export type Scope = "project" | "user";
export type Mode = "install" | "check" | "remove";
export type Action = "create" | "update" | "remove" | "unchanged";

export interface Change {
  /** Relative to the root, with forward slashes. */
  path: string;
  action: Action;
}

export interface InstallResult {
  scope: Scope;
  root: string;
  changes: Change[];
  /** Edits left to the human, because making them would reformat the file. */
  manual: string[];
  /** Adapter entries that --remove leaves in place, because they are not marked as the CLI's. */
  leftInPlace: string[];
  /** For each coding agent named with --agent, how it finds the skill and AGENTS.md. */
  agents: { agent: string; reads: string }[];
  /** Whether anything differs from what install writes (for --check). */
  drift: boolean;
}

export interface InstallOptions {
  scope: Scope;
  /** The project root (project scope) or the home directory (user scope). */
  root: string;
  version: string;
  /** Coding agents named with --agent: their adapters apply even without an existing file. */
  agents: string[];
  mode: Mode;
}

type Adapter = "claude" | "gemini" | "aider";

/**
 * The CLI's compatibility table: what each coding agent reads, and the
 * adapter it needs beyond the shared paths (.agents/skills, .claude/skills,
 * AGENTS.md). First taken from the survey checked against vendor
 * documentation on 2026-09-30. "Reads" is what the vendor documents, not a
 * tested claim; tested support is only what the agent evaluation covers.
 */
export const AGENTS: Readonly<Record<string, { adapter: Adapter | null; reads: string }>> = {
  "claude-code": { adapter: "claude", reads: ".claude/skills; AGENTS.md only without a CLAUDE.md, so an existing one imports it" },
  codex: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  cursor: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  copilot: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  gemini: { adapter: "gemini", reads: ".agents/skills; AGENTS.md once .gemini/settings.json lists it in context.fileName" },
  opencode: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  devin: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  amp: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  goose: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  zed: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  cline: { adapter: null, reads: ".claude/skills and AGENTS.md" },
  roo: { adapter: null, reads: ".agents/skills and AGENTS.md" },
  aider: { adapter: "aider", reads: "no skills; AGENTS.md once .aider.conf.yml lists it under read:" },
  jules: { adapter: null, reads: "AGENTS.md" },
};

export class AgentsInstallError extends Error {
  override name = "AgentsInstallError";
  constructor(
    message: string,
    /** True when the command line is wrong (64); otherwise a file the CLI will not edit (78). */
    readonly usage: boolean,
  ) {
    super(message);
  }
}

const SKILL_BASES = [join(".agents", "skills", SKILL_NAME), join(".claude", "skills", SKILL_NAME)];
const BLOCK_BEGIN = "<!-- varlatch:begin -->";
const BLOCK_END = "<!-- varlatch:end -->";
const CLAUDE_MARKER = "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->";
const AIDER_LINE = "read: AGENTS.md # added by varlatch agents install";

/** The AGENTS.md block: the rules that matter most, and where the rest is. */
export function agentsBlock(): string {
  return [
    BLOCK_BEGIN,
    "## Configuration and secrets: Varlatch",
    "",
    "This project keeps its configuration and secrets in Varlatch.",
    "",
    "- Start every Varlatch command with `varlatch --assisted`.",
    "- Never read, print, or create `.env` files, and never put a secret value in a command.",
    "- Run anything that needs configuration with `varlatch --assisted run -- <command>`.",
    "- When a step needs the human (signing in, entering a secret), give them the exact command and wait.",
    "- Everything else is in the `varlatch` skill (`.agents/skills/varlatch/SKILL.md`), also printed by",
    "  `varlatch --assisted agents guide`.",
    BLOCK_END,
  ].join("\n");
}

function eolOf(text: string): string {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

function trimEndLines(text: string): string {
  return text.replace(/(\r?\n)+$/, "");
}

/**
 * AGENTS.md with the block added or replaced, or taken out when removing
 * (null: nothing else is left, so the file goes). Keeps the file's line
 * endings and everything outside the markers.
 */
export function withBlock(current: string | null, remove: boolean): string | null {
  const text = current ?? "";
  const eol = eolOf(text);
  const start = text.indexOf(BLOCK_BEGIN);
  const end = start < 0 ? -1 : text.indexOf(BLOCK_END, start);
  if (start >= 0 && end < 0) {
    throw new AgentsInstallError(`AGENTS.md has ${BLOCK_BEGIN} without ${BLOCK_END}; restore or delete the marker, then run this again`, false);
  }
  if (start < 0 && text.includes(BLOCK_END)) {
    throw new AgentsInstallError(`AGENTS.md has ${BLOCK_END} without ${BLOCK_BEGIN}; restore or delete the marker, then run this again`, false);
  }
  const block = agentsBlock().replaceAll("\n", eol);
  if (start >= 0) {
    const before = text.slice(0, start);
    const after = text.slice(end + BLOCK_END.length);
    if (!remove) return before + block + after;
    const kept = trimEndLines(before);
    const rest = after.replace(/^(\r?\n)+/, "");
    const joined = kept && rest ? `${kept}${eol}${eol}${rest}` : kept ? `${kept}${eol}` : rest;
    return joined.trim() ? joined : null;
  }
  if (remove) return current;
  if (!text.trim()) return block + eol;
  return `${trimEndLines(text)}${eol}${eol}${block}${eol}`;
}

/**
 * A CLAUDE.md with the marked import of AGENTS.md added, or taken out when
 * removing (null: the file held only the import, so it goes). `importPath`
 * is relative to the file. Unchanged when the file already imports AGENTS.md.
 */
export function withClaudeImport(current: string, remove: boolean, importPath = "AGENTS.md"): string | null {
  const eol = eolOf(current);
  const ours = `${CLAUDE_MARKER}${eol}@${importPath}${eol}`;
  if (remove) {
    const next = current.includes(`${eol}${eol}${ours}`) ? current.replace(`${eol}${eol}${ours}`, eol) : current.replace(ours, "");
    return next.trim() ? next : null;
  }
  if (new RegExp(`^[ \\t]*@(\\./)?${importPath.replaceAll(".", "\\.")}[ \\t]*$`, "m").test(current)) return current;
  if (!current.trim()) return ours;
  return `${trimEndLines(current)}${eol}${eol}${ours}`;
}

/** The Gemini CLI settings with AGENTS.md among its context files, or null when they need no change. */
export function withGeminiContext(settings: Record<string, unknown>): Record<string, unknown> | null {
  const context = typeof settings.context === "object" && settings.context !== null ? (settings.context as Record<string, unknown>) : {};
  const current = context.fileName;
  const names = current === undefined ? ["GEMINI.md"] : Array.isArray(current) ? [...(current as unknown[])] : [current];
  if (names.includes("AGENTS.md")) return null;
  return { ...settings, context: { ...context, fileName: [...names, "AGENTS.md"] } };
}

/** .aider.conf.yml with the marked read: line added, or taken out when removing (null: nothing else is left). */
export function withAiderRead(current: string | null, remove: boolean): string | null {
  const text = current ?? "";
  const eol = eolOf(text);
  if (remove) {
    const next = text
      .split(/\r?\n/)
      .filter((line) => line !== AIDER_LINE)
      .join(eol);
    return next.trim() ? next : null;
  }
  if (!text.trim()) return `${AIDER_LINE}${eol}`;
  return `${trimEndLines(text)}${eol}${AIDER_LINE}${eol}`;
}

function read(path: string): string | null {
  try {
    return statSync(path).isFile() ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
}

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(path));
    else out.push(path);
  }
  return out;
}

function isCanonicalJson(raw: string, parsed: unknown): boolean {
  const canonical = JSON.stringify(parsed, null, 2);
  return raw === canonical || raw === `${canonical}\n`;
}

interface Plan {
  /** Each file the command manages, with the content it should have (null: absent). */
  files: { path: string; desired: string | null }[];
  manual: string[];
  leftInPlace: string[];
}

function plan(opts: InstallOptions): Plan {
  const files: Plan["files"] = [];
  const manual: string[] = [];
  const leftInPlace: string[] = [];
  const remove = opts.mode === "remove";
  const at = (p: string) => join(opts.root, p);

  // The skill directories are the CLI's own: every file in them is managed,
  // and one this version does not ship is removed.
  const skill = skillFiles(opts.version);
  for (const base of SKILL_BASES) {
    const wanted = new Set<string>();
    if (!remove) {
      for (const [path, content] of skill) {
        files.push({ path: at(join(base, path)), desired: content });
        wanted.add(at(join(base, path)));
      }
    }
    for (const existing of filesUnder(at(base))) if (!wanted.has(existing)) files.push({ path: existing, desired: null });
  }
  if (opts.scope === "user") return { files, manual, leftInPlace };

  const agentsMd = read(at("AGENTS.md"));
  if (!(remove && agentsMd === null)) files.push({ path: at("AGENTS.md"), desired: withBlock(agentsMd, remove) });

  const selected = new Set(opts.agents.map((agent) => AGENTS[agent]?.adapter));

  // Claude Code reads AGENTS.md only when no CLAUDE.md is in the way: an
  // existing one (at the root, else in .claude/) imports it.
  const claude = [
    { path: "CLAUDE.md", importPath: "AGENTS.md" },
    { path: join(".claude", "CLAUDE.md"), importPath: "../AGENTS.md" },
  ].map((c) => ({ ...c, current: read(at(c.path)) }));
  if (remove) {
    for (const c of claude) if (c.current !== null) files.push({ path: at(c.path), desired: withClaudeImport(c.current, true, c.importPath) });
  } else {
    const target = claude.find((c) => c.current !== null);
    if (target) files.push({ path: at(target.path), desired: withClaudeImport(target.current as string, false, target.importPath) });
    else if (selected.has("claude")) files.push({ path: at("CLAUDE.md"), desired: withClaudeImport("", false) });
    else if (read(at("CLAUDE.local.md")) !== null) {
      manual.push("Claude Code skips AGENTS.md while CLAUDE.local.md exists: add the line @AGENTS.md to CLAUDE.local.md");
    }
  }

  const geminiPath = at(join(".gemini", "settings.json"));
  const geminiRaw = read(geminiPath);
  if (remove) {
    if (geminiRaw?.includes('"AGENTS.md"')) leftInPlace.push('"AGENTS.md" in context.fileName in .gemini/settings.json');
  } else if (geminiRaw !== null || selected.has("gemini")) {
    let parsed: unknown = null;
    try {
      parsed = geminiRaw === null ? {} : JSON.parse(geminiRaw);
    } catch {
      parsed = null;
    }
    const settings = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
    const next = settings ? withGeminiContext(settings) : null;
    const editable = settings !== null && (geminiRaw === null || isCanonicalJson(geminiRaw, settings));
    if (settings === null || (next !== null && !editable)) {
      manual.push('add "AGENTS.md" to context.fileName in .gemini/settings.json (the CLI edits the file only when that keeps its formatting)');
    } else if (next !== null) {
      files.push({ path: geminiPath, desired: `${JSON.stringify(next, null, 2)}\n` });
    }
  }

  const aiderPath = at(".aider.conf.yml");
  const aiderRaw = read(aiderPath);
  if (remove) {
    if (aiderRaw !== null) {
      const next = withAiderRead(aiderRaw, true);
      if (next !== aiderRaw) files.push({ path: aiderPath, desired: next });
      if (next?.includes("AGENTS.md")) leftInPlace.push("AGENTS.md under read: in .aider.conf.yml");
    }
  } else if (aiderRaw !== null || selected.has("aider")) {
    if (aiderRaw !== null && /^read:/m.test(aiderRaw)) {
      if (!aiderRaw.includes("AGENTS.md")) manual.push("add AGENTS.md to the read: entry in .aider.conf.yml");
    } else {
      files.push({ path: aiderPath, desired: withAiderRead(aiderRaw, false) });
    }
  }
  return { files, manual, leftInPlace };
}

/** After --remove: the emptied skill directories go, and their parents if nothing else is in them. */
function pruneEmpty(root: string, base: string): void {
  const prune = (dir: string): void => {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) if (entry.isDirectory()) prune(join(dir, entry.name));
    if (readdirSync(dir).length === 0) rmdirSync(dir);
  };
  prune(join(root, base));
  for (let dir = dirname(join(root, base)); dir !== root && dir.startsWith(root); dir = dirname(dir)) {
    if (!existsSync(dir) || readdirSync(dir).length > 0) break;
    rmdirSync(dir);
  }
}

export function runInstall(opts: InstallOptions): InstallResult {
  for (const agent of opts.agents) {
    if (!(agent in AGENTS)) throw new AgentsInstallError(`unknown coding agent ${agent}; known: ${Object.keys(AGENTS).join(", ")}`, true);
  }
  if (opts.scope === "user" && opts.agents.length > 0) {
    throw new AgentsInstallError("--agent applies to a project: its adapters edit the project's files", true);
  }
  const { files, manual, leftInPlace } = plan(opts);
  const changes: Change[] = [];
  for (const file of files) {
    const current = read(file.path);
    const action: Action =
      file.desired === null
        ? current === null
          ? "unchanged"
          : "remove"
        : current === null
          ? "create"
          : current === file.desired
            ? "unchanged"
            : "update";
    changes.push({ path: relative(opts.root, file.path).split("\\").join("/"), action });
    if (opts.mode === "check" || action === "unchanged") continue;
    if (file.desired === null) rmSync(file.path, { force: true });
    else {
      mkdirSync(dirname(file.path), { recursive: true });
      writeFileSync(file.path, file.desired);
    }
  }
  if (opts.mode === "remove") for (const base of SKILL_BASES) pruneEmpty(opts.root, base);
  return {
    scope: opts.scope,
    root: opts.root,
    changes,
    manual,
    leftInPlace,
    agents: opts.agents.map((agent) => ({ agent, reads: (AGENTS[agent] as { reads: string }).reads })),
    drift: changes.some((c) => c.action !== "unchanged"),
  };
}

/** The human-readable lines for a result. */
export function describeInstall(result: InstallResult, mode: Mode): string[] {
  const verb: Record<Action, string> =
    mode === "check"
      ? { create: "missing:", update: "differs:", remove: "extra:", unchanged: "" }
      : { create: "created", update: "updated", remove: "removed", unchanged: "" };
  const lines = result.changes.filter((c) => c.action !== "unchanged").map((c) => `${verb[c.action]} ${c.path}`);
  if (lines.length === 0) lines.push(mode === "remove" ? "Nothing to remove." : "The agent files are up to date.");
  for (const m of result.manual) lines.push(`To do by hand: ${m}`);
  for (const l of result.leftInPlace) lines.push(`Left in place: ${l}`);
  for (const a of result.agents) lines.push(`${a.agent} reads ${a.reads}`);
  return lines;
}

/** What a result changed, one entry per skill directory or file: for `init`'s one-line summary. */
export function changedTargets(result: InstallResult): string[] {
  const targets = new Set<string>();
  for (const change of result.changes) {
    if (change.action === "unchanged") continue;
    const base = SKILL_BASES.map((b) => b.split("\\").join("/")).find((b) => change.path.startsWith(`${b}/`));
    targets.add(base ? `${base}/` : change.path);
  }
  return [...targets];
}
