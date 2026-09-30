// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { parse as parseToml } from "smol-toml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";
import { CLAUDE_DENY, hookCommand, withCodexEnv, withoutCodexEnv } from "../src/agents/guardrails.js";
import { runInstall, type InstallOptions } from "../src/agents/install.js";

/**
 * `varlatch agents install --guardrails` (ADR-0043 Decision 8): the hook
 * and settings land in Claude Code's and Codex's own files, merged into
 * what is there; a file the CLI would reformat is left to the human; and
 * --remove takes out the hooks, the marked TOML block byte for byte, and
 * names what it leaves.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-guardrails-"));
const bundle = join(dir, "varlatch.cjs");
let n = 0;

function project(files: Record<string, string> = {}): string {
  const root = join(dir, `p${n++}`);
  mkdirSync(root, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const path = join(d, entry.name);
      if (entry.isDirectory()) walk(path);
      else out[path.slice(root.length + 1)] = readFileSync(path, "utf8");
    }
  };
  if (existsSync(root)) walk(root);
  return out;
}

/** The files outside the skill directories and AGENTS.md: what guardrails touch. */
function settingsOf(root: string): Record<string, string> {
  return Object.fromEntries(Object.entries(snapshot(root)).filter(([p]) => !p.includes("skills/varlatch") && p !== "AGENTS.md"));
}

function install(root: string, extra: Partial<InstallOptions> = {}) {
  return runInstall({ scope: "project", root, version: "0.14.0-test", agents: [], mode: "install", guardrails: true, ...extra });
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
const read = (root: string, path: string) => JSON.parse(readFileSync(join(root, path), "utf8"));

const CLAUDE_HOOK = {
  matcher: "Bash|Read|Grep|Edit|MultiEdit|Write|NotebookEdit|mcp__.*",
  hooks: [{ type: "command", command: "varlatch agents hook --format claude", timeout: 30 }],
};
const CODEX_HOOK = { hooks: [{ type: "command", command: "varlatch agents hook --format codex", timeout: 30 }] };

beforeAll(async () => {
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile: bundle,
    logLevel: "silent",
  });
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("Claude Code", () => {
  it("a fresh project gets the environment variable, the deny rules, and the hook", () => {
    const root = project();
    const result = install(root);
    expect(read(root, ".claude/settings.json")).toEqual({
      env: { VARLATCH_ASSISTED: "1" },
      permissions: { deny: CLAUDE_DENY },
      hooks: { PreToolUse: [CLAUDE_HOOK] },
    });
    expect(existsSync(join(root, ".codex"))).toBe(false);
    expect(result.notices).toEqual([]);
  });

  it("merges into existing settings, keeps every other key, and adds nothing twice", () => {
    const existing = {
      model: "opus",
      env: { NODE_ENV: "development" },
      permissions: { allow: ["Bash(npm test)"], deny: ["Read(./.env)", "Read(./secrets/**)"] },
      hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "./lint.sh" }] }], Stop: [] },
    };
    const root = project({ ".claude/settings.json": json(existing) });
    install(root);
    const after = read(root, ".claude/settings.json");
    expect(after).toEqual({
      model: "opus",
      env: { NODE_ENV: "development", VARLATCH_ASSISTED: "1" },
      permissions: { allow: ["Bash(npm test)"], deny: ["Read(./.env)", "Read(./secrets/**)", ...CLAUDE_DENY.slice(1)] },
      hooks: { PreToolUse: [existing.hooks.PreToolUse[0], CLAUDE_HOOK], Stop: [] },
    });
    const bytes = readFileSync(join(root, ".claude/settings.json"), "utf8");
    expect(install(root).changes.filter((c) => c.action !== "unchanged")).toEqual([]);
    expect(readFileSync(join(root, ".claude/settings.json"), "utf8")).toBe(bytes);
  });

  it("leaves a VARLATCH_ASSISTED the human set, and says so", () => {
    const root = project({ ".claude/settings.json": json({ env: { VARLATCH_ASSISTED: "0" } }) });
    const result = install(root);
    expect(read(root, ".claude/settings.json").env).toEqual({ VARLATCH_ASSISTED: "0" });
    expect(result.manual).toEqual([expect.stringMatching(/sets VARLATCH_ASSISTED to "0"; the guardrails leave it/)]);
  });

  it("does not rewrite settings it would reformat; the human gets the exact entries", () => {
    for (const raw of ['{"model":"opus"}\n', '{\n  // mine\n  "model": "opus"\n}\n', "[]\n"]) {
      const root = project({ ".claude/settings.json": raw });
      const result = install(root);
      expect(readFileSync(join(root, ".claude/settings.json"), "utf8"), raw).toBe(raw);
      expect(result.manual, raw).toEqual([expect.stringMatching(/add the Claude Code guardrails to \.claude\/settings\.json by hand/)]);
    }
  });

  it("--remove takes out the hook and names the environment and deny entries it leaves", () => {
    const existing = { model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "./lint.sh" }] }] } };
    const root = project({ ".claude/settings.json": json(existing) });
    install(root);
    const removed = install(root, { mode: "remove", guardrails: false });
    expect(read(root, ".claude/settings.json")).toEqual({
      model: "opus",
      env: { VARLATCH_ASSISTED: "1" },
      permissions: { deny: CLAUDE_DENY },
      hooks: existing.hooks,
    });
    expect(removed.leftInPlace).toEqual([
      '"VARLATCH_ASSISTED": "1" under env in .claude/settings.json',
      `${CLAUDE_DENY.join(", ")} in permissions.deny in .claude/settings.json`,
    ]);
  });

  it("--remove drops hook containers it leaves empty", () => {
    const root = project({ ".claude/settings.json": json({ hooks: { PreToolUse: [CLAUDE_HOOK] } }) });
    install(root, { mode: "remove", guardrails: false });
    expect(existsSync(join(root, ".claude/settings.json"))).toBe(false);
  });
});

describe("Codex", () => {
  it("only when .codex exists or codex is named: the hook, the environment, and the trust notice", () => {
    const root = project({ ".codex/config.toml": 'model = "o5"\n' });
    const result = install(root);
    expect(read(root, ".codex/hooks.json")).toEqual({ hooks: { PreToolUse: [CODEX_HOOK] } });
    const config = readFileSync(join(root, ".codex/config.toml"), "utf8");
    expect(config.startsWith('model = "o5"\n')).toBe(true);
    expect(parseToml(config)).toEqual({ model: "o5", shell_environment_policy: { set: { VARLATCH_ASSISTED: "1" } } });
    expect(result.notices).toEqual([expect.stringMatching(/only once you trust the project/)]);

    const named = project();
    install(named, { agents: ["codex"] });
    expect(existsSync(join(named, ".codex/hooks.json"))).toBe(true);
    expect(existsSync(join(named, ".claude/settings.json"))).toBe(false);
  });

  it("appends to config.toml only when the parser says the result is the same file plus the one value", () => {
    const cases: [string, string | null][] = [
      ["", "append"],
      ['model = "o5"', "append"],
      ['[shell_environment_policy]\ninherit = "core"\n', "append"],
      ['[mcp_servers.x]\ncommand = "x"\n', "append"],
      ['[shell_environment_policy]\nset = { A = "b" }\n', null],
      ['shell_environment_policy.set.A = "b"\n', null],
      ["[shell_environment_policy.set]\nA = 'b'\n", null],
      ['shell_environment_policy = { inherit = "core" }\n', null],
      ["not toml at all = = \n", null],
      ['[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n', "unchanged"],
    ];
    for (const [text, expected] of cases) {
      const { next } = withCodexEnv(text);
      if (expected === null) expect(next, text).toBeNull();
      else if (expected === "unchanged") expect(next, text).toBe(text);
      else {
        expect(next?.startsWith(text), text).toBe(true);
        expect((parseToml(next as string) as { shell_environment_policy: { set: unknown } }).shell_environment_policy.set, text).toEqual({ VARLATCH_ASSISTED: "1" });
        expect(withoutCodexEnv(next as string), text).toBe(text);
      }
    }
  });

  it("control: appending to the refused files anyway breaks them", () => {
    for (const text of ['[shell_environment_policy]\nset = { A = "b" }\n', 'shell_environment_policy = { inherit = "core" }\n']) {
      expect(() => parseToml(`${text}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n`), text).toThrow();
    }
  });

  it("--remove gives config.toml back byte for byte and deletes what install created", () => {
    for (const original of ['model = "o5"', 'model = "o5"\n\n', 'model = "o5"\r\n', 'model = "o5"\r']) {
      const root = project({ ".codex/config.toml": original });
      install(root);
      install(root, { mode: "remove", guardrails: false });
      expect(readFileSync(join(root, ".codex/config.toml")).equals(Buffer.from(original)), JSON.stringify(original)).toBe(true);
      expect(existsSync(join(root, ".codex/hooks.json"))).toBe(false);
    }
    const created = project();
    install(created, { agents: ["codex"] });
    install(created, { mode: "remove", guardrails: false });
    expect(existsSync(join(created, ".codex"))).toBe(false);
  });
});

describe("--guardrails with install, --check, and --remove", () => {
  it("without --guardrails, install and --check leave the guardrails alone; --remove always takes them out", () => {
    const root = project();
    install(root, { agents: ["claude-code", "codex"] });
    const before = settingsOf(root);
    expect(install(root, { guardrails: false }).changes.filter((c) => c.action !== "unchanged")).toEqual([]);
    expect(install(root, { guardrails: false, mode: "check" }).drift).toBe(false);
    expect(install(root, { mode: "check", agents: ["claude-code", "codex"] }).drift).toBe(false);
    expect(settingsOf(root)).toEqual(before);
    install(root, { guardrails: false, mode: "remove" });
    expect(Object.keys(settingsOf(root))).toEqual([".claude/settings.json"]);
    expect(read(root, ".claude/settings.json").hooks).toBeUndefined();
  });

  it("--check --guardrails reports a missing hook", () => {
    const root = project();
    install(root, { guardrails: false });
    expect(install(root, { mode: "check" }).drift).toBe(true);
    install(root);
    expect(install(root, { mode: "check" }).drift).toBe(false);
  });

  it("a coding agent without guardrails gets a notice; user scope refuses them", () => {
    const root = project();
    const result = install(root, { agents: ["cursor"] });
    expect(result.notices).toEqual(["cursor has no guardrails yet; the skill and AGENTS.md still apply"]);
    expect(existsSync(join(root, ".claude/settings.json"))).toBe(false);
    expect(() => install(project(), { scope: "user" })).toThrow(/--guardrails applies to a project/);
  });
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd: string, stdin = "", env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg"), ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

describe("the CLI", () => {
  const event = (tool_name: string, tool_input: unknown) => JSON.stringify({ session_id: "s", cwd: dir, hook_event_name: "PreToolUse", tool_name, tool_input });

  it("agents hook answers a denial on stdout with status 0, and nothing for an allowed call", async () => {
    for (const format of ["claude", "codex"]) {
      const denied = await cli(["agents", "hook", "--format", format], dir, event("Bash", { command: "cat .env" }));
      expect(denied.code).toBe(0);
      expect(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
      const allowed = await cli(["agents", "hook", "--format", format], dir, event("Bash", { command: "npm test" }));
      expect(allowed).toEqual({ code: 0, stdout: "", stderr: "" });
    }
  });

  it("agents hook fails open on input it cannot read, and refuses a wrong command line", async () => {
    expect(await cli(["agents", "hook", "--format", "claude"], dir, "garbage")).toEqual({ code: 0, stdout: "", stderr: "" });
    for (const args of [["agents", "hook"], ["agents", "hook", "--format", "cursor"], ["agents", "hook", "--format", "claude", "extra"]]) {
      expect((await cli(args, dir, event("Bash", { command: "cat .env" }))).code, args.join(" ")).toBe(EXIT.usage);
    }
  });

  it("the hook command install writes is one the CLI runs", async () => {
    const root = project();
    install(root, { agents: ["claude-code", "codex"] });
    const commands = [
      read(root, ".claude/settings.json").hooks.PreToolUse[0].hooks[0].command,
      read(root, ".codex/hooks.json").hooks.PreToolUse[0].hooks[0].command,
    ];
    expect(commands).toEqual([hookCommand("claude"), hookCommand("codex")]);
    for (const command of commands) {
      const args = (command as string).split(" ");
      expect(args[0]).toBe("varlatch");
      const r = await cli(args.slice(1), root, event("Read", { file_path: join(root, ".env") }));
      expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, command).toBe("deny");
    }
  });

  it("agents install --guardrails writes the settings; --scope user refuses it with 64", async () => {
    const root = project();
    const r = await cli(["agents", "install", "--guardrails"], root);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/created \.claude\/settings\.json/);
    expect((await cli(["agents", "install", "--guardrails", "--check"], root)).code).toBe(0);
    expect((await cli(["agents", "install", "--guardrails", "--scope", "user"], project())).code).toBe(EXIT.usage);
  });
});
