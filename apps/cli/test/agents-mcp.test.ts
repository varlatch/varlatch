// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { parse as parseToml } from "smol-toml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";
import { runInstall, type InstallOptions } from "../src/agents/install.js";
import { REGION_BEGIN, REGION_END, withoutTomlPart, withTomlPart } from "../src/agents/toml.js";

/**
 * `varlatch agents install --mcp` (ADR-0043 Decisions 7 and 9): a
 * `varlatch` server running `varlatch mcp` in each project MCP file,
 * merged into what is there, composed with the other edits of the same run,
 * and taken back by --remove.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-mcp-config-"));
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

function install(root: string, extra: Partial<InstallOptions> = {}) {
  return runInstall({ scope: "project", root, version: "0.14.0-test", agents: [], mode: "install", mcp: true, ...extra });
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
const read = (root: string, path: string) => JSON.parse(readFileSync(join(root, path), "utf8"));
const text = (root: string, path: string) => readFileSync(join(root, path), "utf8");
const ENTRY = { command: "varlatch", args: ["mcp"] };

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

describe("where the entry goes", () => {
  it("a project without MCP files gets .mcp.json, and a notice that Claude Code asks first", () => {
    const root = project();
    const result = install(root);
    expect(read(root, ".mcp.json")).toEqual({ mcpServers: { varlatch: ENTRY } });
    expect(result.notices).toEqual(["Claude Code asks before it uses a project's .mcp.json servers"]);
  });

  it("every MCP file that exists gets the entry in its own format, next to what is there", () => {
    const root = project({
      ".cursor/mcp.json": json({ mcpServers: { other: { command: "x" } } }),
      ".vscode/mcp.json": json({ servers: {}, inputs: [] }),
      "opencode.json": json({ $schema: "https://opencode.ai/config.json", theme: "dark" }),
    });
    install(root);
    expect(read(root, ".cursor/mcp.json")).toEqual({ mcpServers: { other: { command: "x" }, varlatch: { type: "stdio", ...ENTRY } } });
    expect(read(root, ".vscode/mcp.json")).toEqual({ servers: { varlatch: { type: "stdio", ...ENTRY } }, inputs: [] });
    expect(read(root, "opencode.json")).toEqual({
      $schema: "https://opencode.ai/config.json",
      theme: "dark",
      mcp: { varlatch: { type: "local", command: ["varlatch", "mcp"] } },
    });
    expect(existsSync(join(root, ".mcp.json"))).toBe(false);
  });

  it("--agent names the files: copilot writes both of its own, aider has none and gets a notice", () => {
    const root = project();
    install(root, { agents: ["copilot"] });
    expect(existsSync(join(root, ".mcp.json"))).toBe(true);
    expect(read(root, ".vscode/mcp.json")).toEqual({ servers: { varlatch: { type: "stdio", ...ENTRY } } });
    const none = project();
    const result = install(none, { agents: ["aider"] });
    expect(existsSync(join(none, ".mcp.json"))).toBe(false);
    expect(result.notices).toEqual([expect.stringMatching(/^aider has no project MCP file the CLI writes/)]);
  });

  it("is idempotent, and leaves an existing varlatch server that differs", () => {
    const root = project({ ".mcp.json": json({ mcpServers: { varlatch: { command: "varlatch", args: ["mcp", "--allow-writes"] } } }) });
    const before = text(root, ".mcp.json");
    const result = install(root);
    expect(text(root, ".mcp.json")).toBe(before);
    expect(result.manual).toEqual([".mcp.json already has a \"varlatch\" server that differs from the CLI's; the CLI leaves it"]);
    const fresh = project();
    install(fresh);
    expect(install(fresh).changes.filter((c) => c.action !== "unchanged")).toEqual([]);
  });

  it("does not rewrite a file it would reformat", () => {
    for (const raw of ['{"mcpServers":{}}\n', "{\n  // mine\n}\n", '{ "mcpServers": [] }\n']) {
      const root = project({ ".mcp.json": raw });
      const result = install(root);
      expect(text(root, ".mcp.json"), raw).toBe(raw);
      expect(result.manual, raw).toEqual([expect.stringMatching(/add "varlatch": .* under mcpServers in \.mcp\.json/)]);
    }
  });
});

describe("edits of one file in one run build on each other", () => {
  it(".gemini/settings.json gets the AGENTS.md context and the MCP server together", () => {
    const root = project();
    install(root, { agents: ["gemini"] });
    expect(read(root, ".gemini/settings.json")).toEqual({
      context: { fileName: ["GEMINI.md", "AGENTS.md"] },
      mcpServers: { varlatch: ENTRY },
    });
  });

  it(".codex/config.toml gets the guardrail environment and the MCP server together, and --remove restores it byte for byte", () => {
    const original = 'model = "o5"\n';
    const root = project({ ".codex/config.toml": original });
    install(root, { guardrails: true });
    expect(parseToml(text(root, ".codex/config.toml"))).toEqual({
      model: "o5",
      shell_environment_policy: { set: { VARLATCH_ASSISTED: "1" } },
      mcp_servers: { varlatch: ENTRY },
    });
    expect(install(root, { guardrails: true }).changes.filter((c) => c.action !== "unchanged")).toEqual([]);
    install(root, { mode: "remove", mcp: false });
    expect(text(root, ".codex/config.toml")).toBe(original);
  });
});

describe("Codex's TOML", () => {
  it("leaves a file it cannot append to safely, or one with its own varlatch server", () => {
    for (const raw of ["mcp_servers = { other = { command = \"x\" } }\n", '[mcp_servers.varlatch]\ncommand = "other"\n', "= broken\n"]) {
      const root = project({ ".codex/config.toml": raw });
      const result = install(root, { agents: ["codex"] });
      expect(text(root, ".codex/config.toml"), raw).toBe(raw);
      expect(result.manual, raw).toEqual([expect.stringMatching(/\.codex\/config\.toml/)]);
    }
  });

  it("control: appending the block anyway to an inline mcp_servers table does not parse", () => {
    expect(() => parseToml('mcp_servers = { other = { command = "x" } }\n\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n')).toThrow();
  });
});

describe("the CLI's TOML region", () => {
  const env = (t: string | null) => withTomlPart(t, "[shell_environment_policy.set]", ['VARLATCH_ASSISTED = "1"'], (b) => ({ ...b, shell_environment_policy: { set: { VARLATCH_ASSISTED: "1" } } })).next;
  const mcp = (t: string | null) => withTomlPart(t, "[mcp_servers.varlatch]", ['command = "varlatch"', 'args = ["mcp"]'], (b) => ({ ...b, mcp_servers: { varlatch: ENTRY } })).next;
  const OWNED = { "[shell_environment_policy.set]": ['VARLATCH_ASSISTED = "1"'], "[mcp_servers.varlatch]": ['command = "varlatch"', 'args = ["mcp"]'] } as const;
  const drop = (t: string, h: "[shell_environment_policy.set]" | "[mcp_servers.varlatch]") => withoutTomlPart(t, h, OWNED[h]).next;

  it("holds both tables in one region, in the same order whichever came first", () => {
    const original = 'model = "o5"\n';
    const a = mcp(env(original)) as string;
    const b = env(mcp(original)) as string;
    expect(a).toBe(b);
    expect(a).toBe(`${original}\n${REGION_BEGIN}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n${REGION_END}\n`);
  });

  it("taking tables out in either order gives the file back byte for byte", () => {
    for (const original of [null, "", 'model = "o5"', 'model = "o5"\n', 'model = "o5"\n\n\n', 'model = "o5"\r\n', '[profiles.x]\nmodel = "o5"\n', "# only a comment\n"]) {
      const both = mcp(env(original)) as string;
      for (const order of [["[shell_environment_policy.set]", "[mcp_servers.varlatch]"], ["[mcp_servers.varlatch]", "[shell_environment_policy.set]"]] as const) {
        const half = drop(both, order[0]) as string;
        expect(half, JSON.stringify(original)).toContain(order[1]);
        expect(half, JSON.stringify(original)).not.toContain(order[0]);
        expect(drop(half, order[1]), `${JSON.stringify(original)} ${order.join(" then ")}`).toBe(original === null ? null : original);
      }
    }
  });

  it("keeps what the human added after the region when it is taken out", () => {
    // In the middle of the file, the line break before the region stays: it
    // cannot be told apart from the end of the human's line before it.
    const original = 'model = "o5"\n';
    const withRegion = env(original) as string;
    const edited = `${withRegion}\n[profiles.mine]\nmodel = "x"\n`;
    expect(drop(edited, "[shell_environment_policy.set]")).toBe(`${original}\n\n[profiles.mine]\nmodel = "x"\n`);
  });

  it("refuses a change that parses but does not say what was expected", () => {
    // The guard behind every add: the file after must equal the file before plus the intended value.
    const wrong = withTomlPart('model = "o5"\n', "[mcp_servers.varlatch]", ['command = "varlatch"'], (b) => ({ ...b, mcp_servers: { varlatch: ENTRY } }));
    expect(wrong).toEqual({ refused: "adding to it would change what it says" });
    const right = withTomlPart('model = "o5"\n', "[mcp_servers.varlatch]", ['command = "varlatch"', 'args = ["mcp"]'], (b) => ({ ...b, mcp_servers: { varlatch: ENTRY } }));
    expect(right.next).toContain("[mcp_servers.varlatch]");
  });

  it("leaves a file whose region is damaged, or holds a table the CLI did not write: a refusal, never a deletion", () => {
    const foreign = `model = "o5"\n\n${REGION_BEGIN}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n\n[my_own_table]\nkey = 1\n${REGION_END}\n`;
    for (const damaged of [`model = "o5"\n${REGION_BEGIN}\n[mcp_servers.varlatch]\n`, `model = "o5"\n${REGION_END}\n`, `${REGION_BEGIN}\nstray = 1\n${REGION_END}\n`, foreign]) {
      const set = withTomlPart(damaged, "[mcp_servers.varlatch]", ['command = "varlatch"'], (b) => b);
      const removed = withoutTomlPart(damaged, "[mcp_servers.varlatch]", OWNED["[mcp_servers.varlatch]"]);
      for (const edit of [set, removed]) {
        expect(edit, JSON.stringify(damaged)).toEqual({ refused: expect.stringMatching(/damaged, or holds a table the CLI did not write/) });
        expect("next" in edit).toBe(false);
      }
    }
  });

  it("leaves a table the human edited inside the region, rather than taking their lines with it", () => {
    const edited = `model = "o5"\n\n${REGION_BEGIN}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\nenv = { X = "1" }\n${REGION_END}\n`;
    expect(withoutTomlPart(edited, "[mcp_servers.varlatch]", OWNED["[mcp_servers.varlatch]"])).toEqual({ refused: "its [mcp_servers.varlatch] table holds settings the CLI did not write" });
    // After the end marker (a comment), a setting still belongs to the region's last table.
    const appended = `model = "o5"\n\n${REGION_BEGIN}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n${REGION_END}\nenv = { X = "1" }\n`;
    expect(withoutTomlPart(appended, "[mcp_servers.varlatch]", OWNED["[mcp_servers.varlatch]"])).toEqual({ refused: "its [mcp_servers.varlatch] table holds settings the CLI did not write" });
  });
});

describe("--remove", () => {
  it("gives every file back as it was, and deletes the files install created", () => {
    const originals = {
      ".cursor/mcp.json": json({ mcpServers: { other: { command: "x" } } }),
      "opencode.json": json({ theme: "dark" }),
      ".codex/config.toml": 'model = "o5"\r\n',
    };
    const root = project(originals);
    install(root, { agents: ["claude-code", "copilot"] });
    expect(existsSync(join(root, ".mcp.json"))).toBe(true);
    install(root, { mode: "remove", mcp: false });
    for (const [path, content] of Object.entries(originals)) expect(text(root, path), path).toBe(content);
    expect(existsSync(join(root, ".mcp.json"))).toBe(false);
    expect(existsSync(join(root, ".vscode"))).toBe(false);
  });

  it("leaves a varlatch server that differs from the CLI's, and names it", () => {
    const raw = json({ mcpServers: { varlatch: { command: "varlatch", args: ["mcp", "--allow-writes"] } } });
    const root = project({ ".mcp.json": raw });
    const result = install(root, { mode: "remove", mcp: false });
    expect(text(root, ".mcp.json")).toBe(raw);
    expect(result.leftInPlace).toEqual(['the "varlatch" server in .mcp.json, which differs from the one the CLI writes']);
  });

  it("without --mcp, install and --check leave the MCP entries alone", () => {
    const root = project();
    install(root);
    const before = text(root, ".mcp.json");
    expect(install(root, { mcp: false }).changes.filter((c) => c.action !== "unchanged")).toEqual([]);
    expect(install(root, { mcp: false, mode: "check" }).drift).toBe(false);
    expect(install(root, { mode: "check" }).drift).toBe(false);
    expect(text(root, ".mcp.json")).toBe(before);
  });
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd: string): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg") },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("--remove and install never lose a human's TOML (review of #68), through the planner and the CLI", () => {
  const CONFIG = join(".codex", "config.toml");
  const human = 'model = "o5"\napproval_policy = "never"\n';

  it("a damaged region: --remove leaves the file byte for byte and names it; it is never deleted", async () => {
    for (const damaged of [
      `${human}\n${REGION_BEGIN}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n`,
      `${human}\n${REGION_BEGIN}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n`,
    ]) {
      const planned = project({ [CONFIG]: damaged });
      const result = install(planned, { mode: "remove", mcp: false });
      expect(text(planned, CONFIG)).toBe(damaged);
      expect(result.leftInPlace.join("\n")).toMatch(/\.codex\/config\.toml \(its varlatch:begin\/varlatch:end block is damaged/);
      const viaCli = project({ [CONFIG]: damaged });
      const r = await cli(["agents", "install", "--remove"], viaCli);
      expect(r.code, r.stderr).toBe(0);
      expect(existsSync(join(viaCli, CONFIG))).toBe(true);
      expect(text(viaCli, CONFIG)).toBe(damaged);
      expect(r.stdout).toMatch(/Left in place: .*\.codex\/config\.toml/);
    }
  });

  it("a table the human put inside the region: --remove refuses, and the file keeps their table", async () => {
    const root = project({ [CONFIG]: human });
    expect((await cli(["agents", "install", "--agent", "codex", "--mcp"], root)).code).toBe(0);
    const withTheirs = text(root, CONFIG).replace(REGION_END, `\n[my_own_table]\nkey = 1\n${REGION_END}`);
    writeFileSync(join(root, CONFIG), withTheirs);
    const r = await cli(["agents", "install", "--remove"], root);
    expect(r.code, r.stderr).toBe(0);
    expect(text(root, CONFIG)).toBe(withTheirs);
    expect((parseToml(text(root, CONFIG)) as { my_own_table?: { key: number } }).my_own_table?.key).toBe(1);
    expect(r.stdout).toMatch(/Left in place: \[mcp_servers\.varlatch\] in \.codex\/config\.toml/);
  });

  it("an existing varlatch entry with args of another type is the human's: named, untouched, no stack trace", async () => {
    const own = `${human}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = 12\n`;
    const root = project({ [CONFIG]: own });
    const r = await cli(["agents", "install", "--agent", "codex", "--mcp"], root);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout + r.stderr).not.toMatch(/TypeError|not iterable|\bat \w+ \(/);
    expect(r.stdout).toMatch(/already has an mcp_servers\.varlatch entry that differs from "varlatch mcp"; the CLI leaves it/);
    expect(text(root, CONFIG)).toBe(own);
  });

  it("a setting appended after the end marker belongs to the last table: removal refuses, for the MCP table and the guardrail table", async () => {
    const keep = 'model = "keep"\n';
    for (const [flags, appended, path] of [
      [["--mcp"], 'env = { CUSTOM_SETTING = "keep-me" }\n', ["mcp_servers", "varlatch", "env"]],
      [["--guardrails"], 'CUSTOM_SETTING = "keep-me"\n', ["shell_environment_policy", "set", "CUSTOM_SETTING"]],
    ] as [string[], string, string[]][]) {
      const root = project({ [CONFIG]: keep });
      const installed = await cli(["agents", "install", "--agent", "codex", ...flags], root);
      expect(installed.code, installed.stderr).toBe(0);
      const customized = `${text(root, CONFIG)}${appended}`;
      writeFileSync(join(root, CONFIG), customized);
      const r = await cli(["agents", "install", "--remove"], root);
      expect(r.code, r.stderr).toBe(0);
      expect(text(root, CONFIG), flags.join(" ")).toBe(customized);
      expect(r.stdout).toMatch(/Left in place: .*\.codex\/config\.toml .*holds settings the CLI did not write/);
      const parsed = parseToml(text(root, CONFIG)) as Record<string, Record<string, Record<string, unknown>>>;
      const value = path.reduce<unknown>((at, k) => (at as Record<string, unknown>)?.[k], parsed);
      expect(JSON.stringify(value)).toMatch(/keep-me/);
      expect(parsed.model).toBe("keep");
    }
  });

  it("combined removal: the untouched table goes, the customized one stays with the human's setting, meaning unchanged", async () => {
    const root = project({ [CONFIG]: 'model = "keep"\n' });
    expect((await cli(["agents", "install", "--agent", "codex", "--guardrails", "--mcp"], root)).code).toBe(0);
    writeFileSync(join(root, CONFIG), `${text(root, CONFIG)}env = { CUSTOM_SETTING = "keep-me" }\n`);
    const r = await cli(["agents", "install", "--remove"], root);
    expect(r.code, r.stderr).toBe(0);
    const parsed = parseToml(text(root, CONFIG)) as { model: string; shell_environment_policy?: unknown; mcp_servers: { varlatch: { command: string; args: string[]; env: { CUSTOM_SETTING: string } } } };
    expect(parsed.shell_environment_policy).toBeUndefined();
    expect(parsed.mcp_servers.varlatch).toEqual({ command: "varlatch", args: ["mcp"], env: { CUSTOM_SETTING: "keep-me" } });
    expect(parsed.model).toBe("keep");
    expect(r.stdout).toMatch(/Left in place: \[mcp_servers\.varlatch\] in \.codex\/config\.toml/);
  });

  it("a known table given twice in the region (the human's edited copy first): left byte for byte, never silently deleted", async () => {
    const twice = `model = "keep"\n\n${REGION_BEGIN}\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\nenv = { MINE = "1" }\n\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n${REGION_END}\n`;
    const root = project({ [CONFIG]: twice });
    const r = await cli(["agents", "install", "--remove"], root);
    expect(r.code, r.stderr).toBe(0);
    expect(text(root, CONFIG)).toBe(twice);
    expect(r.stdout).toMatch(/Left in place: \[mcp_servers\.varlatch\] in \.codex\/config\.toml \(its varlatch:begin\/varlatch:end block is damaged/);
  });

  it("control: an unrelated table added after the untouched region does not stop the removal", async () => {
    const root = project({ [CONFIG]: 'model = "keep"\n' });
    expect((await cli(["agents", "install", "--agent", "codex", "--guardrails", "--mcp"], root)).code).toBe(0);
    writeFileSync(join(root, CONFIG), `${text(root, CONFIG)}\n[profiles.mine]\nmodel = "x"\n`);
    const r = await cli(["agents", "install", "--remove"], root);
    expect(r.code, r.stderr).toBe(0);
    expect(parseToml(text(root, CONFIG))).toEqual({ model: "keep", profiles: { mine: { model: "x" } } });
    expect(r.stdout).not.toMatch(/Left in place: .*config\.toml/);
  });

  it("control: a region the CLI wrote, untouched, is still taken out byte for byte", async () => {
    const root = project({ [CONFIG]: human });
    expect((await cli(["agents", "install", "--agent", "codex", "--mcp"], root)).code).toBe(0);
    expect(text(root, CONFIG)).toContain("[mcp_servers.varlatch]");
    expect((await cli(["agents", "install", "--remove"], root)).code).toBe(0);
    expect(text(root, CONFIG)).toBe(human);
  });
});

describe("the CLI", () => {
  it("agents install --mcp writes .mcp.json, and the command it names is one the CLI runs", async () => {
    const root = project();
    const r = await cli(["agents", "install", "--mcp"], root);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/created \.mcp\.json/);
    const entry = read(root, ".mcp.json").mcpServers.varlatch as { command: string; args: string[] };
    expect(entry.command).toBe("varlatch");
    const help = await cli([...entry.args, "--help"], root);
    expect(help.code).toBe(0);
    expect(help.stdout).toMatch(/varlatch mcp/);
    expect((await cli(["agents", "install", "--mcp", "--check"], root)).code).toBe(0);
  });

  it("--mcp with --scope user is a usage error", async () => {
    expect((await cli(["agents", "install", "--mcp", "--scope", "user"], project())).code).toBe(EXIT.usage);
  });
});
