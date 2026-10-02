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
    "- This repository is already set up (`varlatch.toml`): never run `varlatch init`.",
    "- To move a `.env` file into Varlatch, without reading it:",
    "  1. Compare names with the target environment: `varlatch --assisted import .env -e <environment> --dry-run --json`",
    "     marks those it already has (the file may be an older copy). Ask the human about each; the import replaces one",
    "     only with `--replace <NAME>` for it.",
    "  2. Import: `varlatch --assisted import .env -e <environment> --contract --plain <NAME> --delete-source --json`.",
    "     `--plain` only for items the human confirmed are not secret; the file is deleted only after every value was stored.",
    "  3. If the import created a Contract revision, activate it: `varlatch --assisted contract activate <revision>`.",
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
    "- Never add `--allow-unmasked` or `--no-redact` yourself (assisted mode refuses both). When a Secret is too short to",
    "  mask (exit 78), report the item and wait: every remedy is the human's, run in their own terminal.",
    "- Inside an agent-safe run, the run's Secrets are Placeholders, not secrets, listed (names only) by",
    "  `varlatch --assisted context --json` under `agentRun.placeholders`. Showing a listed one discloses nothing",
    "  (`varlatch --assisted run -- printenv <NAME>` when the human asks you to check it); never show any other",
    "  variable there: the run also carries credentials and inherited values. Placeholders go in",
    "  `varlatch --assisted request` targets, for example",
    '  `varlatch --assisted request -H "Authorization: Bearer $STRIPE_KEY" https://api.example.com/v1/balance`.',
    "- Run anything that needs configuration with `varlatch --assisted run -- <command>`. If it says no values are",
    "  stored in Varlatch, the command gets only what it inherits: check what it needs (`validate`) and report that.",
    "- When a step needs the human (signing in, entering a secret), give them the exact command and wait.",
    "- Everything else is in the `varlatch` skill (`.agents/skills/varlatch/SKILL.md`), also printed by",
    "  `varlatch --assisted agents guide`.",
    BLOCK_END,
  ].join("\n");
}

function eolOf(text: string): string {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

/**
 * The CLI's additions are exact, so that removing one gives the file back
 * byte for byte. A new file is the addition alone. An existing file, even
 * an empty one, keeps every byte and gains one line break (which ends its
 * last line, or leaves a blank line when it already ended one) and then the
 * addition, whose lines end with the file's line ending.
 */
function appendOwned(current: string | null, owned: string): string {
  return current === null ? owned : current + eolOf(current) + owned;
}

/**
 * The line ending of an addition at [start, end): the one inside it, else
 * the one that ends it. install used the same one for the line break it put
 * before the addition, so this is what removing takes back, and what
 * installing again reuses. Judging from the whole file instead would be
 * fooled by the file's own bytes next to the addition: a file ending in a
 * bare CR, followed by the LF install added, reads as CRLF.
 */
function ownedEol(text: string, start: number, end: number): string {
  const span = text.slice(start, end);
  if (span.includes("\r\n")) return "\r\n";
  if (span.includes("\n")) return "\n";
  return text.startsWith("\r\n", end) ? "\r\n" : "\n";
}

/**
 * The file without the addition at [start, end), and without the line break
 * that ends it. At the end of the file, the line break install put before
 * it goes too. Only those exact bytes go, so the file's own bytes around
 * them stay. Null: nothing precedes or follows the addition, so install
 * created the file and removing takes the file away.
 */
function withoutOwned(text: string, start: number, end: number): string | null {
  const eol = ownedEol(text, start, end);
  const before = text.slice(0, start);
  const rest = text.slice(end);
  const after = rest.startsWith(eol) ? rest.slice(eol.length) : rest;
  if (after !== "") return before + after;
  if (before === "") return null;
  return before.endsWith(eol) ? before.slice(0, -eol.length) : before;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * AGENTS.md with the block added or replaced, or taken out when removing
 * (null: the file held only the block, so it goes). Every byte outside the
 * block and the line breaks install added around it stays as it was.
 */
export function withBlock(current: string | null, remove: boolean): string | null {
  const text = current ?? "";
  const start = text.indexOf(BLOCK_BEGIN);
  const end = start < 0 ? -1 : text.indexOf(BLOCK_END, start);
  if (start >= 0 && end < 0) {
    throw new AgentsInstallError(`AGENTS.md has ${BLOCK_BEGIN} without ${BLOCK_END}; restore or delete the marker, then run this again`, false);
  }
  if (start < 0 && text.includes(BLOCK_END)) {
    throw new AgentsInstallError(`AGENTS.md has ${BLOCK_END} without ${BLOCK_BEGIN}; restore or delete the marker, then run this again`, false);
  }
  // An existing block keeps its line ending, so installing again changes nothing.
  const eol = start >= 0 ? ownedEol(text, start, end + BLOCK_END.length) : eolOf(text);
  const block = agentsBlock().replaceAll("\n", eol);
  if (start >= 0) {
    if (remove) return withoutOwned(text, start, end + BLOCK_END.length);
    return text.slice(0, start) + block + text.slice(end + BLOCK_END.length);
  }
  if (remove) return current;
  return appendOwned(current, block + eol);
}

/**
 * A CLAUDE.md with the marked import of AGENTS.md added, or taken out when
 * removing (null: the file held only the import, so it goes). `importPath`
 * is relative to the file. Unchanged when the file already imports AGENTS.md.
 */
export function withClaudeImport(current: string | null, remove: boolean, importPath = "AGENTS.md"): string | null {
  const text = current ?? "";
  if (remove) {
    const ours = new RegExp(`${escapeRegExp(CLAUDE_MARKER)}\\r?\\n@${escapeRegExp(importPath)}(?=\\r?\\n|$)`).exec(text);
    return ours ? withoutOwned(text, ours.index, ours.index + ours[0].length) : current;
  }
  if (new RegExp(`^[ \\t]*@(\\./)?${escapeRegExp(importPath)}[ \\t]*$`, "m").test(text)) return current;
  const eol = eolOf(text);
  return appendOwned(current, `${CLAUDE_MARKER}${eol}@${importPath}${eol}`);
}

/** The Gemini CLI settings with AGENTS.md among its context files, or null when they need no change. */
export function withGeminiContext(settings: Record<string, unknown>): Record<string, unknown> | null {
  const context = typeof settings.context === "object" && settings.context !== null ? (settings.context as Record<string, unknown>) : {};
  const current = context.fileName;
  const names = current === undefined ? ["GEMINI.md"] : Array.isArray(current) ? [...(current as unknown[])] : [current];
  if (names.includes("AGENTS.md")) return null;
  return { ...settings, context: { ...context, fileName: [...names, "AGENTS.md"] } };
}

/**
 * What .aider.conf.yml needs, judged without a YAML parser and on the safe
 * side: "append" only when every line is blank, a comment, a top-level
 * `key: value` with a plain key and a one-line value, or a list item under
 * a top-level key, and no key is `read`. Appending `read:` at column 0 then
 * adds one key and changes no other value. "has-read": a top-level plain
 * `read` key, which is the human's to extend. "unsafe": anything else
 * (quoted or indented keys, block scalars, anchors, multi-line values,
 * several documents), which the CLI leaves untouched.
 */
export function aiderLayout(text: string): "append" | "has-read" | "unsafe" {
  const oneLineValue = (value: string): boolean => {
    const v = value.replace(/\s+#.*$/, "").trim();
    if (v === "") return true;
    if (/^"([^"\\]|\\.)*"$/.test(v) || /^'([^']|'')*'$/.test(v)) return true;
    if (/^\[[^[\]{}"'#]*\]$/.test(v)) return true;
    // A plain scalar: no leading indicator, and no ": " that would open a mapping.
    return !/^[-?:,[\]{}#&*!|>'"%@`]/.test(v) && !/:(\s|$)/.test(v);
  };
  let hasRead = false;
  let listOpen = false;
  // Every character a YAML parser may take as a line break, including those
  // YAML 1.1 (Aider's parser) adds: a bare CR, NEL, and the Unicode line and
  // paragraph separators. Otherwise a "comment" could hide a read: key.
  for (const raw of text.split(/\r\n|[\n\r\u0085\u2028\u2029]/)) {
    const line = raw.replace(/\s+$/, "");
    if (line === "" || /^\s*#/.test(line)) continue;
    if (line.includes("\t")) return "unsafe";
    const key = /^([A-Za-z0-9][A-Za-z0-9_.-]*):(?:\s+(.*))?$/.exec(line);
    if (key) {
      if (!oneLineValue(key[2] ?? "")) return "unsafe";
      if (key[1] === "read") hasRead = true;
      listOpen = (key[2] ?? "").replace(/\s+#.*$/, "").trim() === "";
      continue;
    }
    const item = /^\s*-\s+(.*)$/.exec(line);
    if (item && listOpen && oneLineValue(item[1] as string)) continue;
    return "unsafe";
  }
  return hasRead ? "has-read" : "append";
}

/** .aider.conf.yml with the marked read: line added, or taken out when removing (null: nothing else is left). */
export function withAiderRead(current: string | null, remove: boolean): string | null {
  const text = current ?? "";
  if (remove) {
    const ours = new RegExp(`^${escapeRegExp(AIDER_LINE)}(?=\\r?\\n|$)`, "m").exec(text);
    return ours ? withoutOwned(text, ours.index, ours.index + ours[0].length) : current;
  }
  return appendOwned(current, AIDER_LINE + eolOf(text));
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * A file's text; null when there is no file; undefined when the path is not
 * a UTF-8 text file, which the CLI never edits (decoding and encoding again
 * would change its bytes). A byte order mark is kept.
 */
function readText(path: string): string | null | undefined {
  const bytes = readBytes(path);
  if (bytes === undefined || bytes === null) return bytes;
  try {
    return UTF8.decode(bytes);
  } catch {
    return undefined;
  }
}

/** A file's bytes; null when nothing is there; undefined when something other than a file is. */
function readBytes(path: string): Buffer | null | undefined {
  try {
    if (!statSync(path).isFile()) return undefined;
  } catch {
    return null;
  }
  return readFileSync(path);
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
  const notText = (name: string, edit: string) => manual.push(`${name} is not a UTF-8 text file, so the CLI leaves it as it is: ${edit}`);

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

  const agentsMd = readText(at("AGENTS.md"));
  if (agentsMd === undefined) {
    throw new AgentsInstallError("AGENTS.md is not a UTF-8 text file, so the CLI does not edit it; fix or move it, then run this again", false);
  }
  if (!(remove && agentsMd === null)) files.push({ path: at("AGENTS.md"), desired: withBlock(agentsMd, remove) });

  const selected = new Set(opts.agents.map((agent) => AGENTS[agent]?.adapter));

  // Claude Code reads AGENTS.md only when no CLAUDE.md is in the way: an
  // existing one (at the root, else in .claude/) imports it.
  const claude = [
    { path: "CLAUDE.md", importPath: "AGENTS.md" },
    { path: join(".claude", "CLAUDE.md"), importPath: "../AGENTS.md" },
  ].map((c) => ({ ...c, current: readText(at(c.path)) }));
  if (remove) {
    for (const c of claude) {
      if (typeof c.current === "string") files.push({ path: at(c.path), desired: withClaudeImport(c.current, true, c.importPath) });
    }
  } else {
    const target = claude.find((c) => c.current !== null);
    if (target && typeof target.current === "string") {
      files.push({ path: at(target.path), desired: withClaudeImport(target.current, false, target.importPath) });
    } else if (target) notText(target.path, `add the line @${target.importPath}`);
    else if (selected.has("claude")) files.push({ path: at("CLAUDE.md"), desired: withClaudeImport(null, false) });
    else if (readText(at("CLAUDE.local.md")) !== null) {
      manual.push("Claude Code skips AGENTS.md while CLAUDE.local.md exists: add the line @AGENTS.md to CLAUDE.local.md");
    }
  }

  const geminiPath = at(join(".gemini", "settings.json"));
  const geminiRaw = readText(geminiPath);
  const geminiEdit = 'add "AGENTS.md" to context.fileName in .gemini/settings.json';
  if (remove) {
    if (geminiRaw?.includes('"AGENTS.md"')) leftInPlace.push('"AGENTS.md" in context.fileName in .gemini/settings.json');
  } else if (geminiRaw === undefined) {
    notText(".gemini/settings.json", geminiEdit);
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
      manual.push(`${geminiEdit} (the CLI edits the file only when that keeps its formatting)`);
    } else if (next !== null) {
      // Written exactly as it was read, with a final line break only if it had one.
      const eol = geminiRaw === null || geminiRaw.endsWith("\n") ? "\n" : "";
      files.push({ path: geminiPath, desired: `${JSON.stringify(next, null, 2)}${eol}` });
    }
  }

  const aiderPath = at(".aider.conf.yml");
  const aiderRaw = readText(aiderPath);
  if (remove) {
    if (typeof aiderRaw === "string") {
      const next = withAiderRead(aiderRaw, true);
      if (next !== aiderRaw) files.push({ path: aiderPath, desired: next });
      if (next?.includes("AGENTS.md")) leftInPlace.push("AGENTS.md under read: in .aider.conf.yml");
    }
  } else if (aiderRaw === undefined) {
    notText(".aider.conf.yml", "add AGENTS.md under read:");
  } else if (aiderRaw !== null || selected.has("aider")) {
    const layout = aiderRaw === null ? "append" : aiderLayout(aiderRaw);
    if (aiderRaw?.includes(AIDER_LINE)) {
      // Installed before; the file may have changed around the CLI's line since.
    } else if (layout === "append") {
      files.push({ path: aiderPath, desired: withAiderRead(aiderRaw, false) });
    } else if (layout === "has-read") {
      if (!aiderRaw?.includes("AGENTS.md")) manual.push("add AGENTS.md to the read: entry in .aider.conf.yml");
    } else {
      manual.push("add AGENTS.md under read: in .aider.conf.yml (the CLI appends to the file only when its layout makes that safe)");
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
    const current = readBytes(file.path);
    if (current === undefined) {
      throw new AgentsInstallError(`${relative(opts.root, file.path)} is not a file; move it, then run this again`, false);
    }
    const action: Action =
      file.desired === null
        ? current === null
          ? "unchanged"
          : "remove"
        : current === null
          ? "create"
          : current.equals(Buffer.from(file.desired, "utf8"))
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
