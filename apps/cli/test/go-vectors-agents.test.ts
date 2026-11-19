// SPDX-License-Identifier: Apache-2.0
import { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { withCodexEnv, withoutCodexEnv } from "../src/agents/guardrails.js";
import {
  AGENTS,
  AgentsInstallError,
  agentsBlock,
  aiderLayout,
  changedTargets,
  describeInstall,
  runInstall,
  withAiderRead,
  withBlock,
  withClaudeImport,
  withGeminiContext,
  type InstallOptions,
  type Mode,
} from "../src/agents/install.js";
import { GuideTopicError, guide, skillFiles } from "../src/agents/skill.js";
import { withTomlPart, withoutTomlPart } from "../src/agents/toml.js";
import { unfillDir, writeOrCompare } from "./goKit.js";
import { PATH_BELOW_DIR, RECORD_WINDOWS, WINDOWS_COMMENT, readRecording, windowsFile } from "./goWindows.js";

/**
 * Vectors for the Go CLI's agent files (internal docs/design/go-cli.md,
 * slice 5.1d), from apps/cli/src/agents itself:
 *
 * - the pure edits: the AGENTS.md block, the CLAUDE.md import, the Gemini
 *   CLI's context, .aider.conf.yml's layout and line, the TOML region of
 *   .codex/config.toml, and `agents guide`;
 * - install: projects (files, symbolic and hard links, files that are not
 *   UTF-8, directories in the way) taken through a sequence of runs of
 *   runInstall, for every coding agent, with and without --guardrails and
 *   --mcp, in both scopes: each run's result (or error), its lines, init's
 *   summary, and the whole tree afterwards.
 *
 * In a tree, a skill file equal to what this version installs is
 * "{{skill}}", and the AGENTS.md block "{{block}}" (the Go replay
 * substitutes the same, from its own copies); the scratch directory is
 * "{{dir}}". Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-agents.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/agents.json", import.meta.url));
const VERSION = "9.9.9-vector";

const scratch = realpathSync.native(mkdtempSync(join(tmpdir(), "varlatch-go-vectors-agents-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);
const NEL = String.fromCharCode(0x85);
const NBSP = String.fromCharCode(0xa0);
const BOM = String.fromCharCode(0xfeff);

/** Runs f; its result, or the error it throws (an AgentsInstallError with its kind). */
function attempt(f: () => unknown): unknown {
  try {
    const result = f();
    return { result: result === undefined ? "undefined" : result };
  } catch (err) {
    if (err instanceof AgentsInstallError) return { error: err.message, usage: err.usage };
    if (err instanceof GuideTopicError) return { error: err.message };
    throw err;
  }
}

// ---- the pure edits -------------------------------------------------------

const block = agentsBlock();
const TEXTS: Array<string | null> = [
  null,
  "",
  "\n",
  "# Rules\n",
  "# Rules",
  "# Rules\r\n\r\nUse pnpm.\r\n",
  "User rules\r",
  "a\rb\r",
  `${BOM}# Rules\n`,
  `# Rules\n\n${block}\n`,
  `# Rules\n\n${block}\n\n## After\n`,
  `${block}\n`,
  block,
  `# Rules\r\n\r\n${block.replaceAll("\n", "\r\n")}\r\n`,
  "<!-- varlatch:begin -->\nold text\n<!-- varlatch:end -->\n",
  "x\n<!-- varlatch:begin -->\nold\r\n<!-- varlatch:end -->\r\ny\n",
  "x\n<!-- varlatch:begin -->\nhalf\n",
  "x\nhalf\n<!-- varlatch:end -->\n",
  "<!-- varlatch:end --><!-- varlatch:begin -->",
  "<!-- varlatch:begin --><!-- varlatch:end -->",
  "<!-- varlatch:begin -->x<!-- varlatch:end --><!-- varlatch:begin -->y<!-- varlatch:end -->",
  `${LS}rules${PS}`,
];

const CLAUDE_TEXTS: Array<string | null> = [
  null,
  "",
  "# Claude\n",
  "# Claude",
  "# Claude\r\n",
  "@AGENTS.md\n",
  "@./AGENTS.md\n",
  "  @AGENTS.md\t \n",
  "x\r@AGENTS.md\ry",
  `x${LS}@AGENTS.md${PS}`,
  "@AGENTS.mdx\n",
  "@ AGENTS.md\n",
  "@../AGENTS.md\n",
  "@./../AGENTS.md\n",
  "# Claude\n\n<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.md\n",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.md\n",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\r\n@AGENTS.md\r\n",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.md",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.mdx\n<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.md\nafter\n",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@../AGENTS.md\n",
  "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\r@AGENTS.md\n",
];

const GEMINI: string[] = [
  "{}",
  '{"theme":"dark"}',
  '{"context":{"fileName":"CONTEXT.md"}}',
  '{"context":{"fileName":["A.md","B.md"]}}',
  '{"context":{"fileName":["AGENTS.md"]}}',
  '{"context":{"fileName":"AGENTS.md"}}',
  '{"context":{"fileName":null}}',
  '{"context":{"fileName":7}}',
  '{"context":null}',
  '{"context":"x"}',
  '{"context":["a","b"]}',
  '{"context":{"other":1,"fileName":[]}}',
  '{"2":"two","context":{"1":"one"},"a":1}',
  '{"__proto__":{"x":1},"context":{}}',
];

const AIDER: string[] = [
  "",
  "\n",
  "model: gpt-4\n",
  "model: gpt-4\nauto-commits: false\n",
  "# comment\nmodel: x # trailing\n",
  "read: CONVENTIONS.md\n",
  "read:\n  - CONVENTIONS.md\n  - AGENTS.md\n",
  "read: [AGENTS.md]\n",
  "files:\n  - a.py\n  - b.py\nmodel: x\n",
  "  model: x\n",
  "model:\tx\n",
  '"model": x\n',
  "'model': x\n",
  "model: |\n  multi\n",
  "model: >\n  folded\n",
  "model: &anchor x\n",
  "model: *alias\n",
  "---\nmodel: x\n---\nmodel: y\n",
  "model: x: y\n",
  'model: "quoted: value"\n',
  "model: 'it''s'\n",
  'model: "unterminated\n',
  "model: [a, b]\n",
  "model: [a, [b]]\n",
  "model: {a: 1}\n",
  "model: x\n- stray item\n",
  "model:\n- item\n",
  "model:\n  - item: nested\n",
  "model: x\r\nread: y\r\n",
  "model: x\r",
  `# hidden${LS}read: y\n`,
  `# hidden${NEL}read: y\n`,
  `# hidden${PS}model: x\n`,
  `model: x${NBSP}\n`,
  `${NBSP}model: x\n`,
  "model: x #comment\n",
  "model: x#notcomment\n",
  "1model: x\n",
  "_model: x\n",
  "mo.del-x_y: z\n",
  "model: %x\n",
  "model: @x\n",
  "model: `x`\n",
  "model: ?x\n",
  "read: AGENTS.md # added by varlatch agents install\n",
  "model: x\nread: AGENTS.md # added by varlatch agents install\n",
];

const AIDER_REMOVE: string[] = [
  "read: AGENTS.md # added by varlatch agents install\n",
  "read: AGENTS.md # added by varlatch agents install",
  "model: x\n\nread: AGENTS.md # added by varlatch agents install\n",
  "model: x\r\n\r\nread: AGENTS.md # added by varlatch agents install\r\n",
  "model: x\nread: AGENTS.md # added by varlatch agents install\nother: y\n",
  "model: x\rread: AGENTS.md # added by varlatch agents install\r",
  `model: x${LS}read: AGENTS.md # added by varlatch agents install${PS}`,
  "xread: AGENTS.md # added by varlatch agents install\n",
  "read: AGENTS.md # added by varlatch agents install x\n",
  "model: x\n",
];

const REGION = "# varlatch:begin: added by varlatch agents install; varlatch agents install --remove takes it out";
const CODEX: Array<string | null> = [
  null,
  "",
  "\n",
  'model = "o3"\n',
  'model = "o3"',
  'model = "o3"\r\n',
  'model = "o3"\n\n[profiles.fast]\nmodel = "mini"\n',
  '[shell_environment_policy]\ninherit = "core"\n',
  '[shell_environment_policy.set]\nFOO = "bar"\n',
  '[shell_environment_policy]\nset = { VARLATCH_ASSISTED = "1" }\n',
  '[mcp_servers.other]\ncommand = "x"\n',
  '[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n',
  '[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = 12\n',
  "not toml = = 1\n",
  'when = 1979-05-27T07:32:00-08:00\nday = 1979-05-27\nat = 07:32:00.999999\nlocal = 1979-05-27 07:32:00\nn = 0x1F\nf = 6.02e+23\ninf = -inf\nnan = nan\nb = true\nneg = -0\n',
  '[table]\nkey = "value"\n[[array]]\nx = 1\n',
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `model = "o3"\n\n${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `model = "o3"\r\n\r\n${REGION}\r\n[shell_environment_policy.set]\r\nVARLATCH_ASSISTED = "1"\r\n# varlatch:end\r\n`,
  `model = "o3"\n\n${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n# varlatch:end\n`,
  `model = "o3"\n\n${REGION}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n# varlatch:end\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\nOTHER = "x"\n# varlatch:end\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\nOTHER = "appended"\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n`,
  `x = 1\n# varlatch:end\n`,
  `${REGION}\nstray = 1\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n[profiles.x]\na = 1\n# varlatch:end\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\nx# varlatch:end\n`,
  `[shell_environment_policy]\ninherit = "all"\n\n${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `${REGION}\r[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `a = 1\n${REGION}\n  [shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n# varlatch:end\n`,
  `[shell_environment_policy.set.inner]\nx = 1\n`,
  "[mcp_servers]\nvarlatch = 3\n",
  "mcp_servers = [1]\n",
];

const MCP_BODY = ['command = "varlatch"', 'args = ["mcp"]'];

function pureEdits(): Record<string, unknown> {
  return {
    block,
    withBlock: TEXTS.flatMap((current) => [false, true].map((remove) => ({ current, remove, ...(attempt(() => withBlock(current, remove)) as object) }))),
    withClaudeImport: CLAUDE_TEXTS.flatMap((current) =>
      ["AGENTS.md", "../AGENTS.md"].flatMap((importPath) => [false, true].map((remove) => ({ current, remove, importPath, result: withClaudeImport(current, remove, importPath) }))),
    ),
    withGeminiContext: GEMINI.map((settings) => ({ settings, result: (() => {
      const next = withGeminiContext(JSON.parse(settings) as Record<string, unknown>);
      return next === null ? null : JSON.stringify(next, null, 2);
    })() })),
    aiderLayout: AIDER.map((text) => ({ text, result: aiderLayout(text) })),
    withAiderRead: [...AIDER, ...AIDER_REMOVE].flatMap((current) => [false, true].map((remove) => ({ current, remove, result: withAiderRead(current, remove) }))),
    toml: CODEX.flatMap((current) => [
      { current, edit: "withCodexEnv", result: withCodexEnv(current) },
      ...(current === null ? [] : [{ current, edit: "withoutCodexEnv", result: withoutCodexEnv(current) }]),
      {
        current,
        edit: "withMcpPart",
        result: withTomlPart(current, "[mcp_servers.varlatch]", MCP_BODY, (b) => ({
          ...b,
          mcp_servers: { ...(typeof b.mcp_servers === "object" && b.mcp_servers !== null && !Array.isArray(b.mcp_servers) ? b.mcp_servers : {}), varlatch: { command: "varlatch", args: ["mcp"] } },
        })),
      },
      ...(current === null ? [] : [{ current, edit: "withoutMcpPart", result: withoutTomlPart(current, "[mcp_servers.varlatch]", MCP_BODY) }]),
    ]),
    guide: [undefined, "setup", "run", "agent-run", "self-hosting", "contract", "nosuch", "", "SETUP"].map((topic) => ({
      topic: topic ?? null,
      ...(attempt(() => guide(topic)) as object),
    })),
    skillFiles: Object.fromEntries(skillFiles(VERSION)),
  };
}

// ---- install ----------------------------------------------------------------

/** A fixture entry: a text file, bytes, a symbolic link, a hard link to an earlier entry, or a directory. */
type Entry = { text: string } | { base64: string } | { link: string } | { hardlink: string } | { dir: true };
type Setup = Record<string, Entry>;
type Step = Partial<Omit<InstallOptions, "root" | "version">> & { scope?: "project" | "user"; init?: boolean };

interface Scenario {
  name: string;
  setup: Setup;
  steps: Step[];
}

const text = (t: string): Entry => ({ text: t });
const json = (v: unknown): Entry => ({ text: `${JSON.stringify(v, null, 2)}\n` });

function build(dir: string, setup: Setup): void {
  for (const [path, entry] of Object.entries(setup)) {
    const at = join(dir, path);
    mkdirSync(dirname(at), { recursive: true });
    if ("text" in entry) writeFileSync(at, entry.text);
    else if ("base64" in entry) writeFileSync(at, Buffer.from(entry.base64, "base64"));
    else if ("link" in entry) symlinkSync(entry.link.split("{{dir}}").join(dir), at);
    else if ("hardlink" in entry) linkSync(join(dir, entry.hardlink), at);
    else mkdirSync(at, { recursive: true });
  }
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The tree under dir: each entry by its path (a directory's ends in "/"), with the substitutions above. */
function tree(dir: string): Record<string, unknown> {
  const skill = skillFiles(VERSION);
  const out: Record<string, unknown> = {};
  const walk = (rel: string) => {
    for (const name of readdirSync(join(dir, rel)).sort()) {
      const path = rel ? `${rel}/${name}` : name;
      const at = join(dir, path);
      const stat = lstatSync(at);
      if (stat.isSymbolicLink()) out[path] = { link: unfillDir(readlinkSync(at), dir) };
      else if (stat.isDirectory()) {
        out[`${path}/`] = {};
        walk(path);
      } else {
        const bytes = readFileSync(at);
        let content: string;
        try {
          content = UTF8.decode(bytes);
        } catch {
          out[path] = { base64: bytes.toString("base64") };
          continue;
        }
        const skillPath = /^(project|home)\/\.(agents|claude)\/skills\/varlatch\/(.*)$/.exec(path)?.[3];
        if (skillPath !== undefined && skill.get(skillPath) === content) out[path] = { text: "{{skill}}" };
        else out[path] = { text: content.split(block).join("{{block}}").split(block.replaceAll("\n", "\r\n")).join("{{block-crlf}}") };
      }
    }
  };
  walk("");
  return out;
}

function runStep(dir: string, step: Step, withLines: boolean): unknown {
  const { init, scope = "project", agents = [], mode = "install", ...rest } = step;
  const root = scope === "user" ? join(dir, "home") : join(dir, "project");
  const options: InstallOptions = { scope, root, version: VERSION, agents, mode: mode as Mode, ...rest };
  const sub = (s: string) => unfillDir(s, dir);
  try {
    const result = runInstall(options);
    return JSON.parse(
      sub(
        JSON.stringify({
          result: { ...result },
          ...(withLines ? { lines: describeInstall(result, options.mode) } : {}),
          ...(init ? { changedTargets: changedTargets(result) } : {}),
        }),
      ),
    );
  } catch (err) {
    if (err instanceof AgentsInstallError) return { error: sub(err.message), usage: err.usage };
    // A system error the CLI lets escape (Node.js prints it and exits 1);
    // the Go CLI fails too, in its own words.
    return { uncaught: (err as NodeJS.ErrnoException).code ?? (err as Error).name };
  }
}

function record(s: Scenario): Record<string, unknown> {
  const dir = join(scratch, s.name.replace(/[^a-z0-9.-]+/gi, "_"));
  mkdirSync(join(dir, "project"), { recursive: true });
  mkdirSync(join(dir, "home"), { recursive: true });
  build(dir, s.setup);
  // A tree equal to the one before the step is "unchanged".
  let before = JSON.stringify(tree(dir));
  const steps = s.steps.map((step) => {
    const outcome = runStep(dir, step, !s.name.startsWith("matrix."));
    const after = tree(dir);
    const same = JSON.stringify(after) === before;
    before = JSON.stringify(after);
    return { step, outcome, tree: same ? "unchanged" : after };
  });
  return { name: s.name, setup: s.setup, steps };
}

/** Every project file an adapter, the guardrails or the MCP entries read, formatted as the CLI writes them. */
const EXISTING: Setup = {
  "project/AGENTS.md": text("# Rules\n\nUse pnpm.\n"),
  "project/CLAUDE.md": text("# Claude\n"),
  "project/.gemini/settings.json": json({ theme: "dark" }),
  "project/.aider.conf.yml": text("model: gpt-4\nauto-commits: false\n"),
  "project/.codex/config.toml": text('model = "o3"\n\n[profiles.fast]\nmodel = "mini"\n'),
  "project/.codex/hooks.json": json({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "other-hook" }] }] } }),
  "project/.mcp.json": json({ mcpServers: { other: { command: "other" } } }),
  "project/.cursor/mcp.json": json({ mcpServers: {} }),
  "project/.vscode/mcp.json": json({ servers: { other: { type: "stdio", command: "o" } } }),
  "project/opencode.json": json({ $schema: "https://opencode.ai/config.json" }),
  "project/.claude/settings.json": json({ permissions: { allow: ["Bash(ls)"], deny: ["Read(./.env)"] } }),
};

const AGENT_SETS: string[][] = [[], ...Object.keys(AGENTS).map((a) => [a]), ["claude-code", "codex", "gemini", "aider", "copilot", "cursor", "opencode"]];
const FLAGS: Array<{ guardrails?: boolean; mcp?: boolean }> = [{}, { guardrails: true }, { mcp: true }, { guardrails: true, mcp: true }];

function matrix(): Scenario[] {
  const out: Scenario[] = [];
  for (const [fixture, setup] of [["empty", {}], ["existing", EXISTING]] as const) {
    for (const agents of AGENT_SETS) {
      for (const flags of FLAGS) {
        const opts = { agents, ...flags };
        out.push({
          name: `matrix.${fixture}.${agents.join("+") || "none"}${flags.guardrails ? ".guardrails" : ""}${flags.mcp ? ".mcp" : ""}`,
          setup,
          steps: [{ ...opts }, { mode: "remove" }],
        });
      }
    }
  }
  return out;
}

const INSTALL_REMOVE: Step[] = [{}, { mode: "check" }, { mode: "remove" }];
const ALL_IN: Step[] = [{ guardrails: true, mcp: true }, { guardrails: true, mcp: true, mode: "check" }, { mode: "remove" }];
const p = (files: Record<string, Entry>): Setup => Object.fromEntries(Object.entries(files).map(([k, v]) => [`project/${k}`, v]));
const NOT_UTF8: Entry = { base64: Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x0a]).toString("base64") };
const MARKER = "<!-- varlatch: the Varlatch instructions are in AGENTS.md -->";

function special(): Scenario[] {
  const s: Array<[string, Setup, Step[]?]> = [
    // AGENTS.md
    ["agents-md.crlf", p({ "AGENTS.md": text("# Rules\r\n\r\nUse pnpm.\r\n") })],
    ["agents-md.bare-cr", p({ "AGENTS.md": text("User rules\r") })],
    ["agents-md.no-final-break", p({ "AGENTS.md": text("# Rules") })],
    ["agents-md.bom", p({ "AGENTS.md": text(`${BOM}# Rules\n`) })],
    ["agents-md.empty", p({ "AGENTS.md": text("") })],
    ["agents-md.stale-block", p({ "AGENTS.md": text("# Rules\n\n<!-- varlatch:begin -->\nold\n<!-- varlatch:end -->\n\n## After\n") })],
    ["agents-md.damaged-begin", p({ "AGENTS.md": text("<!-- varlatch:begin -->\nhalf\n") })],
    ["agents-md.damaged-end", p({ "AGENTS.md": text("half\n<!-- varlatch:end -->\n") })],
    ["agents-md.not-utf8", p({ "AGENTS.md": NOT_UTF8 })],
    ["agents-md.directory", p({ "AGENTS.md": { dir: true } })],
    ["agents-md.link-inside", p({ "docs/AGENTS.md": text("# Rules\n"), "AGENTS.md": { link: "docs/AGENTS.md" } })],
    ["agents-md.link-inside-missing", p({ "docs/.keep": text(""), "AGENTS.md": { link: "docs/AGENTS.md" } })],
    ["agents-md.link-outside", { "outside/AGENTS.md": text("# Rules\n"), "project/AGENTS.md": { link: "{{dir}}/outside/AGENTS.md" } }],
    ["agents-md.link-dangling-outside", { "project/AGENTS.md": { link: "{{dir}}/nowhere/AGENTS.md" } }],
    ["agents-md.link-to-root", p({ "AGENTS.md": { link: "." } })],
    // CLAUDE.md
    ["claude-md.link-to-agents", p({ "AGENTS.md": text("# Rules\n"), "CLAUDE.md": { link: "AGENTS.md" } })],
    ["claude-md.link-to-missing-agents", p({ "CLAUDE.md": { link: "AGENTS.md" } })],
    ["claude-md.hardlink", p({ "AGENTS.md": text("# Rules\n"), "CLAUDE.md": { hardlink: "project/AGENTS.md" } })],
    ["claude-md.agents-links-to-claude", p({ "CLAUDE.md": text("# Rules\n"), "AGENTS.md": { link: "CLAUDE.md" } })],
    ["claude-md.legacy-self-import", p({ "AGENTS.md": text(`# Rules\n\n${MARKER}\n@AGENTS.md\n`), "CLAUDE.md": { link: "AGENTS.md" } })],
    ["claude-md.link-other-inside", p({ "docs/claude.md": text("# Claude\n"), "CLAUDE.md": { link: "docs/claude.md" } })],
    ["claude-md.link-other-imports", p({ "docs/claude.md": text("@AGENTS.md\n"), "CLAUDE.md": { link: "docs/claude.md" } })],
    ["claude-md.link-other-marked", p({ "docs/claude.md": text(`${MARKER}\n@AGENTS.md\n`), "CLAUDE.md": { link: "docs/claude.md" } })],
    ["claude-md.link-outside", { "outside/claude.md": text("# Claude\n"), "project/CLAUDE.md": { link: "{{dir}}/outside/claude.md" } }],
    ["claude-md.dot-claude", p({ ".claude/CLAUDE.md": text("# Claude\n") })],
    ["claude-md.dot-claude-link-to-agents", p({ "AGENTS.md": text("# Rules\n"), ".claude/CLAUDE.md": { link: "../AGENTS.md" } })],
    ["claude-md.both", p({ "CLAUDE.md": text("# Root\n"), ".claude/CLAUDE.md": text("# Dot\n") })],
    ["claude-md.directory", p({ "CLAUDE.md": { dir: true } })],
    ["claude-md.not-utf8", p({ "CLAUDE.md": NOT_UTF8 })],
    ["claude-md.local", p({ "CLAUDE.local.md": text("# Local\n") })],
    ["claude-md.local-directory", p({ "CLAUDE.local.md": { dir: true } })],
    ["claude-md.imports", p({ "CLAUDE.md": text("# Claude\n\n  @./AGENTS.md \n") })],
    ["claude-md.crlf", p({ "CLAUDE.md": text("# Claude\r\n") })],
    ["claude-md.select-creates", {}, [{ agents: ["claude-code"] }, { mode: "remove" }]],
    // Gemini CLI
    ["gemini.not-canonical", p({ ".gemini/settings.json": text('{\n    "theme": "dark"\n}\n') })],
    ["gemini.no-final-break", p({ ".gemini/settings.json": text('{\n  "theme": "dark"\n}') })],
    ["gemini.invalid", p({ ".gemini/settings.json": text("{ theme: dark }\n") })],
    ["gemini.array", p({ ".gemini/settings.json": text("[]\n") })],
    ["gemini.bom", p({ ".gemini/settings.json": text(`${BOM}{}\n`) })],
    ["gemini.not-utf8", p({ ".gemini/settings.json": NOT_UTF8 })],
    ["gemini.has-agents", p({ ".gemini/settings.json": json({ context: { fileName: ["AGENTS.md"] } }) })],
    ["gemini.context-array", p({ ".gemini/settings.json": json({ context: ["a"] }) })],
    ["gemini.select-creates", {}, [{ agents: ["gemini"] }, { agents: ["gemini"], mode: "check" }, { mode: "remove" }]],
    ["gemini.select-mcp", {}, [{ agents: ["gemini"], mcp: true }, { mode: "remove" }]],
    // Aider
    ["aider.has-read", p({ ".aider.conf.yml": text("read: CONVENTIONS.md\n") })],
    ["aider.has-read-agents", p({ ".aider.conf.yml": text("read:\n  - AGENTS.md\n") })],
    ["aider.unsafe", p({ ".aider.conf.yml": text("model: |\n  x\n") })],
    ["aider.crlf", p({ ".aider.conf.yml": text("model: x\r\n") })],
    ["aider.no-final-break", p({ ".aider.conf.yml": text("model: x") })],
    ["aider.hidden-read", p({ ".aider.conf.yml": text(`# x${LS}read: y\n`) })],
    ["aider.installed-then-edited", p({ ".aider.conf.yml": text("model: x\nread: AGENTS.md # added by varlatch agents install\nmore: y\n") })],
    ["aider.not-utf8", p({ ".aider.conf.yml": NOT_UTF8 })],
    ["aider.select-creates", {}, [{ agents: ["aider"] }, { agents: ["aider"] }, { mode: "remove" }]],
    // Claude Code guardrails
    ["guardrails.claude.env-not-object", p({ ".claude/settings.json": json({ env: [] }) }), ALL_IN],
    ["guardrails.claude.env-other-value", p({ ".claude/settings.json": json({ env: { VARLATCH_ASSISTED: "0" } }) }), ALL_IN],
    ["guardrails.claude.env-null-value", p({ ".claude/settings.json": json({ env: { VARLATCH_ASSISTED: null } }) }), ALL_IN],
    ["guardrails.claude.env-object-value", p({ ".claude/settings.json": json({ env: { VARLATCH_ASSISTED: { a: [1, "x"] } } }) }), ALL_IN],
    ["guardrails.claude.null-containers", p({ ".claude/settings.json": json({ env: null, permissions: null, hooks: null }) }), ALL_IN],
    ["guardrails.claude.deny-not-list", p({ ".claude/settings.json": json({ permissions: { deny: "x" } }) }), ALL_IN],
    ["guardrails.claude.permissions-not-object", p({ ".claude/settings.json": json({ permissions: ["x"] }) }), ALL_IN],
    ["guardrails.claude.hooks-not-object", p({ ".claude/settings.json": json({ hooks: [] }) }), ALL_IN],
    ["guardrails.claude.pre-not-list", p({ ".claude/settings.json": json({ hooks: { PreToolUse: {} } }) }), ALL_IN],
    ["guardrails.claude.already-hooked", p({ ".claude/settings.json": json({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "varlatch agents hook --format claude" }] }] } }) }), ALL_IN],
    ["guardrails.claude.other-hooks", p({ ".claude/settings.json": json({ hooks: { PostToolUse: [], PreToolUse: [{ hooks: [{ command: "x" }, "y"] }, 3] }, z: 1 }) }), ALL_IN],
    ["guardrails.claude.shared-entry", p({ ".claude/settings.json": json({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ command: "keep" }, { command: "varlatch agents hook --format claude" }] }] } }) }), [{ mode: "remove" }]],
    ["guardrails.claude.not-canonical", p({ ".claude/settings.json": text('{"a":1}\n') }), ALL_IN],
    ["guardrails.claude.not-canonical-remove", p({ ".claude/settings.json": text('{"hooks":{"PreToolUse":[{"hooks":[{"command":"varlatch agents hook --format claude"}]}]}}') }), [{ mode: "remove" }]],
    ["guardrails.claude.invalid", p({ ".claude/settings.json": text("nope\n") }), ALL_IN],
    ["guardrails.claude.not-utf8", p({ ".claude/settings.json": NOT_UTF8 }), ALL_IN],
    ["guardrails.claude.no-final-break", p({ ".claude/settings.json": text('{\n  "a": 1\n}') }), ALL_IN],
    ["guardrails.claude.integer-keys", p({ ".claude/settings.json": json({ b: 1, 10: "ten", 2: "two", env: { 1: "one" } }) }), ALL_IN],
    // Codex guardrails and MCP
    ["codex.dir-only", p({ ".codex/.keep": text("") }), [{ guardrails: true }, { guardrails: true, mode: "check" }, { mode: "remove" }]],
    ...CODEX.filter((c): c is string => c !== null).map((c, i): [string, Setup, Step[]] => [`codex.config.${i}`, p({ ".codex/config.toml": text(c) }), [{ agents: ["codex"], guardrails: true, mcp: true }, { agents: ["codex"], guardrails: true, mcp: true, mode: "check" }, { mode: "remove" }]]),
    ["codex.config.not-utf8", p({ ".codex/config.toml": NOT_UTF8 }), [{ agents: ["codex"], guardrails: true, mcp: true }, { mode: "remove" }]],
    ["codex.hooks.not-canonical", p({ ".codex/hooks.json": text("{}") }), [{ agents: ["codex"], guardrails: true }, { mode: "remove" }]],
    ["codex.hooks.pre-not-list", p({ ".codex/hooks.json": json({ hooks: { PreToolUse: 1 } }) }), [{ agents: ["codex"], guardrails: true }, { mode: "remove" }]],
    ["codex.keeps-dir", p({ ".codex/other.txt": text("x\n") }), [{ agents: ["codex"], guardrails: true, mcp: true }, { mode: "remove" }]],
    // MCP JSON files
    ["mcp.container-not-object", p({ ".mcp.json": json({ mcpServers: [] }) }), ALL_IN],
    ["mcp.container-null", p({ ".mcp.json": json({ mcpServers: null }) }), ALL_IN],
    ["mcp.differs", p({ ".mcp.json": json({ mcpServers: { varlatch: { command: "varlatch", args: ["mcp", "-e", "dev"] } } }) }), ALL_IN],
    ["mcp.equal-reordered", p({ ".mcp.json": json({ mcpServers: { varlatch: { args: ["mcp"], command: "varlatch" } } }) }), ALL_IN],
    ["mcp.only-ours-not-canonical", p({ ".mcp.json": text('{"mcpServers":{"varlatch":{"command":"varlatch","args":["mcp"]}}}') }), ALL_IN],
    ["mcp.invalid", p({ ".mcp.json": text("{") }), ALL_IN],
    ["mcp.not-utf8", p({ ".mcp.json": NOT_UTF8 }), ALL_IN],
    ["mcp.no-final-break", p({ ".mcp.json": text('{\n  "mcpServers": {}\n}') }), ALL_IN],
    ["mcp.others-and-ours", p({ "opencode.json": json({ mcp: { varlatch: { type: "local", command: ["varlatch", "mcp"] }, x: {} }, y: 1 }) }), ALL_IN],
    ["mcp.agents-without-file", {}, [{ agents: ["devin", "aider"], mcp: true }, { mode: "remove" }]],
    ["mcp.vscode-pruned", {}, [{ agents: ["copilot"], mcp: true }, { mode: "remove" }]],
    // The skill directories
    ["skill.old-file", p({ ".agents/skills/varlatch/old.md": text("old\n"), ".claude/skills/varlatch/references/old.md": text("old\n") })],
    ["skill.edited", p({ ".agents/skills/varlatch/SKILL.md": text("edited\n") })],
    ["skill.file-is-directory", p({ ".agents/skills/varlatch/SKILL.md/x": text("x\n") })],
    ["skill.file-is-link", { "outside/SKILL.md": text("x\n"), "project/.agents/skills/varlatch/SKILL.md": { link: "{{dir}}/outside/SKILL.md" } }],
    ["skill.dir-link", { "outside/skill/a.md": text("a\n"), "project/.claude/skills/varlatch/linked": { link: "{{dir}}/outside/skill" } }],
    ["skill.base-is-file", p({ ".agents/skills/varlatch": text("x\n") })],
    ["skill.parent-has-other", p({ ".agents/skills/other/SKILL.md": text("x\n") })],
    // Scope and the command line
    ["user.install", {}, [{ scope: "user" }, { scope: "user", mode: "check" }, { scope: "user", mode: "remove" }]],
    ["user.keeps-other", { "home/.agents/other": text("x\n"), "home/.codex/.keep": text("") }, [{ scope: "user" }, { scope: "user", mode: "remove" }]],
    ["user.refusals", {}, [{ scope: "user", agents: ["codex"] }, { scope: "user", guardrails: true }, { scope: "user", mcp: true }, { agents: ["nosuch"] }, { agents: ["codex", "nosuch"] }]],
    ["init.summary", p({ "AGENTS.md": text("# Mine\n") }), [{ init: true }, { init: true }]],
    ["init.summary-link", p({ "AGENTS.md": text("# Mine\n"), "CLAUDE.md": { link: "AGENTS.md" } }), [{ init: true }]],
    ["remove.nothing", {}, [{ mode: "remove" }]],
    ["remove.with-agents", EXISTING, [{ agents: ["claude-code", "gemini"], guardrails: true, mcp: true }, { agents: ["codex"], mode: "remove" }]],
  ];
  return s.map(([name, setup, steps]) => ({ name: `special.${name}`, setup, steps: steps ?? INSTALL_REMOVE }));
}

describe("Go vectors for the agent files", () => {
  it.skipIf(RECORD_WINDOWS)("are what the TypeScript code answers", () => {
    process.umask(0o022);
    // The install scenarios are many: one compact line each.
    const head = JSON.stringify({ version: VERSION, ...pureEdits() }, null, 2);
    const install = [...matrix(), ...special()].map((s) => JSON.stringify(record(s))).join(",\n");
    const result = writeOrCompare(VECTORS, `${head.slice(0, -2)},\n  "install": [\n${install}\n]\n}\n`);
    expect(result.current, "agents.json is stale: regenerate it (see this file's comment)").toBe(true);
  }, 120_000);

  // On Windows: the install scenarios whose Linux recording names a path
  // below the directory, recorded again (goWindows.ts), into
  // vectors/windows/agents.json.
  it.runIf(RECORD_WINDOWS)("install scenarios that name a path, recorded on Windows", () => {
    const linux = readRecording<{ install: Array<{ name: string; steps: unknown }> }>(VECTORS);
    const needed = new Set(linux.install.filter((s) => PATH_BELOW_DIR.test(JSON.stringify(s.steps))).map((s) => s.name));
    const install = [...matrix(), ...special()]
      .filter((s) => needed.has(s.name))
      .map((s) => JSON.stringify(record(s)))
      .join(",\n");
    const head = JSON.stringify({ comment: WINDOWS_COMMENT, platform: "windows", version: VERSION }, null, 2);
    const result = writeOrCompare(windowsFile(VECTORS), `${head.slice(0, -2)},\n  "install": [\n${install}\n]\n}\n`);
    expect(result.current, "windows/agents.json is stale: record it again (goWindows.ts)").toBe(true);
  }, 300_000);
});
