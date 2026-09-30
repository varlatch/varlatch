// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";
import {
  agentsBlock,
  changedTargets,
  runInstall,
  withAiderRead,
  withBlock,
  withClaudeImport,
  withGeminiContext,
  type InstallOptions,
} from "../src/agents/install.js";
import { SKILL_FILES } from "../src/agents/skillFiles.generated.js";

/**
 * `varlatch agents install` and `init`'s default (ADR-0043 Decision 7): the
 * skill lands in both shared paths, AGENTS.md changes only inside its
 * marked block, adapters edit a file only when the edit keeps everything
 * else, `--check` reports drift, and `--remove` gives back the files as
 * they were.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-agents-"));
const bundle = join(dir, "varlatch.cjs");
let n = 0;

function project(files: Record<string, string> = {}): string {
  const root = join(dir, `p${n++}`);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  mkdirSync(root, { recursive: true });
  return root;
}

/** Every file under root, relative, with its content. */
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

function install(root: string, extra: Partial<InstallOptions> = {}) {
  return runInstall({ scope: "project", root, version: "0.14.0-test", agents: [], mode: "install", ...extra });
}

const SKILL_PATHS = Object.keys(SKILL_FILES).flatMap((p) => [`.agents/skills/varlatch/${p}`, `.claude/skills/varlatch/${p}`]);

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

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd: string, env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg"), ...env },
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

describe("the AGENTS.md block", () => {
  const user = "# Project\n\nUse pnpm, not npm.\n";

  it("is appended after the file's own content, and removing it gives the file back byte for byte", () => {
    const added = withBlock(user, false) as string;
    expect(added.startsWith(user)).toBe(true);
    expect(added).toBe(`${user}\n${agentsBlock()}\n`);
    expect(withBlock(added, true)).toBe(user);
  });

  it("is replaced in place, keeping what is before and after it", () => {
    const stale = `${user}\n<!-- varlatch:begin -->\nold text\n<!-- varlatch:end -->\n\n## After\n\nMore rules.\n`;
    const replaced = withBlock(stale, false) as string;
    expect(replaced).toBe(`${user}\n${agentsBlock()}\n\n## After\n\nMore rules.\n`);
    expect(withBlock(replaced, false)).toBe(replaced);
    expect(withBlock(replaced, true)).toBe(`${user}\n## After\n\nMore rules.\n`);
  });

  it("keeps CRLF line endings", () => {
    const crlf = user.replaceAll("\n", "\r\n");
    const added = withBlock(crlf, false) as string;
    expect(added.replaceAll("\r\n", "")).not.toContain("\n");
    expect(withBlock(added, true)).toBe(crlf);
  });

  it("makes a new file when there is none, and removing it leaves nothing", () => {
    expect(withBlock(null, false)).toBe(`${agentsBlock()}\n`);
    expect(withBlock(`${agentsBlock()}\n`, true)).toBeNull();
  });

  it("refuses a file with one marker but not the other, instead of adding a second block", () => {
    expect(() => withBlock(`${user}<!-- varlatch:begin -->\nhalf\n`, false)).toThrow(/without <!-- varlatch:end -->/);
    expect(() => withBlock(`${user}half\n<!-- varlatch:end -->\n`, false)).toThrow(/without <!-- varlatch:begin -->/);
  });
});

describe("adapters", () => {
  it("CLAUDE.md gains one marked import, never a second, and loses only that", () => {
    const own = "Use pnpm.\n";
    const added = withClaudeImport(own, false) as string;
    expect(added).toMatch(/^Use pnpm\.\n\n<!-- varlatch: .* -->\n@AGENTS\.md\n$/);
    expect(withClaudeImport(added, false)).toBe(added);
    expect(withClaudeImport(added, true)).toBe(own);
    // The human's own import is theirs: install adds nothing, remove takes nothing.
    for (const theirs of ["Rules.\n@AGENTS.md\n", "Rules.\n@./AGENTS.md\n"]) {
      expect(withClaudeImport(theirs, false)).toBe(theirs);
      expect(withClaudeImport(theirs, true)).toBe(theirs);
    }
    expect(withClaudeImport("", false, "AGENTS.md")).toMatch(/^<!-- varlatch: .* -->\n@AGENTS\.md\n$/);
    expect(withClaudeImport(withClaudeImport("", false) as string, true)).toBeNull();
    expect(withClaudeImport("Nested.\n", false, "../AGENTS.md")).toContain("\n@../AGENTS.md\n");
  });

  it("Gemini CLI settings add AGENTS.md to context.fileName and keep GEMINI.md", () => {
    expect(withGeminiContext({})).toEqual({ context: { fileName: ["GEMINI.md", "AGENTS.md"] } });
    expect(withGeminiContext({ theme: "x", context: { fileName: "RULES.md", other: 1 } })).toEqual({
      theme: "x",
      context: { fileName: ["RULES.md", "AGENTS.md"], other: 1 },
    });
    expect(withGeminiContext({ context: { fileName: ["GEMINI.md", "AGENTS.md"] } })).toBeNull();
  });

  it(".aider.conf.yml gains one marked read: line and loses only that", () => {
    const own = "model: x\n";
    const added = withAiderRead(own, false) as string;
    expect(added).toBe("model: x\nread: AGENTS.md # added by varlatch agents install\n");
    expect(withAiderRead(added, true)).toBe(own);
    expect(withAiderRead(withAiderRead(null, false), true)).toBeNull();
  });
});

describe("runInstall", () => {
  it("writes the skill to both shared paths, the AGENTS.md block, and nothing else", () => {
    const root = project();
    const result = install(root);
    const files = snapshot(root);
    expect(Object.keys(files).sort()).toEqual([...SKILL_PATHS, "AGENTS.md"].sort());
    expect(files[".agents/skills/varlatch/SKILL.md"]).toBe(files[".claude/skills/varlatch/SKILL.md"]);
    expect(files[".agents/skills/varlatch/SKILL.md"]).toContain("generator: varlatch 0.14.0-test");
    expect(files["AGENTS.md"]).toBe(`${agentsBlock()}\n`);
    expect(result.drift).toBe(true);
    expect(changedTargets(result)).toEqual([".agents/skills/varlatch/", ".claude/skills/varlatch/", "AGENTS.md"]);
  });

  it("is idempotent: a second install changes nothing", () => {
    const root = project({ "AGENTS.md": "# Mine\n", "CLAUDE.md": "Mine.\n" });
    install(root);
    const after = snapshot(root);
    const again = install(root);
    expect(again.drift).toBe(false);
    expect(again.changes.every((c) => c.action === "unchanged")).toBe(true);
    expect(snapshot(root)).toEqual(after);
  });

  it("--check reports drift without writing: a missing file, an edited one, an extra one", () => {
    const root = project();
    const fresh = install(root, { mode: "check" });
    expect(fresh.drift).toBe(true);
    expect(snapshot(root)).toEqual({});
    install(root);
    expect(install(root, { mode: "check" }).drift).toBe(false);
    writeFileSync(join(root, ".claude/skills/varlatch/SKILL.md"), "edited\n");
    writeFileSync(join(root, ".agents/skills/varlatch/old.md"), "from an older version\n");
    rmSync(join(root, ".agents/skills/varlatch/references/run.md"));
    const before = snapshot(root);
    const check = install(root, { mode: "check" });
    expect(check.drift).toBe(true);
    expect(check.changes.filter((c) => c.action !== "unchanged")).toEqual([
      { path: ".agents/skills/varlatch/references/run.md", action: "create" },
      { path: ".agents/skills/varlatch/old.md", action: "remove" },
      { path: ".claude/skills/varlatch/SKILL.md", action: "update" },
    ]);
    expect(snapshot(root)).toEqual(before);
    install(root);
    expect(install(root, { mode: "check" }).drift).toBe(false);
  });

  it("a new CLI version rewrites the skill, and the check before it reports the difference", () => {
    const root = project();
    install(root);
    expect(install(root, { version: "0.15.0", mode: "check" }).drift).toBe(true);
    install(root, { version: "0.15.0" });
    expect(readFileSync(join(root, ".agents/skills/varlatch/SKILL.md"), "utf8")).toContain("generator: varlatch 0.15.0");
  });

  it("--remove gives back every file as it was, and deletes the ones install created", () => {
    const own = {
      "AGENTS.md": "# Mine\n\nKeep this.\n",
      "CLAUDE.md": "Claude rules.\n",
      ".aider.conf.yml": "model: x\n",
      ".agents/skills/other/SKILL.md": "someone else's skill\n",
      "README.md": "readme\n",
    };
    const root = project(own);
    install(root);
    expect(snapshot(root)).not.toEqual(own);
    const removed = install(root, { mode: "remove" });
    expect(removed.leftInPlace).toEqual([]);
    expect(snapshot(root)).toEqual(own);
    expect(existsSync(join(root, ".claude"))).toBe(false);
    expect(existsSync(join(root, ".agents/skills/other"))).toBe(true);
    expect(install(root, { mode: "remove" }).drift).toBe(false);
  });

  it("--remove on a project install created from nothing leaves nothing", () => {
    const root = project();
    install(root, { agents: ["claude-code", "gemini", "aider"] });
    expect(Object.keys(snapshot(root))).toEqual(expect.arrayContaining(["CLAUDE.md", ".gemini/settings.json", ".aider.conf.yml"]));
    const removed = install(root, { mode: "remove" });
    // The Gemini CLI entry is JSON, which has no place to mark it as the CLI's.
    expect(removed.leftInPlace).toEqual(['"AGENTS.md" in context.fileName in .gemini/settings.json']);
    expect(Object.keys(snapshot(root))).toEqual([".gemini/settings.json"]);
  });

  it("imports AGENTS.md into an existing CLAUDE.md, else .claude/CLAUDE.md; creates one only for --agent claude-code", () => {
    const rootFile = project({ "CLAUDE.md": "Root.\n", ".claude/CLAUDE.md": "Nested.\n" });
    install(rootFile);
    expect(readFileSync(join(rootFile, "CLAUDE.md"), "utf8")).toContain("\n@AGENTS.md\n");
    expect(readFileSync(join(rootFile, ".claude/CLAUDE.md"), "utf8")).toBe("Nested.\n");

    const nested = project({ ".claude/CLAUDE.md": "Nested.\n" });
    install(nested);
    expect(readFileSync(join(nested, ".claude/CLAUDE.md"), "utf8")).toContain("\n@../AGENTS.md\n");
    expect(existsSync(join(nested, "CLAUDE.md"))).toBe(false);

    const none = project();
    install(none);
    expect(existsSync(join(none, "CLAUDE.md"))).toBe(false);
    install(none, { agents: ["claude-code"] });
    expect(readFileSync(join(none, "CLAUDE.md"), "utf8")).toMatch(/^<!-- varlatch: .* -->\n@AGENTS\.md\n$/);

    const local = project({ "CLAUDE.local.md": "Mine.\n" });
    const result = install(local);
    expect(readFileSync(join(local, "CLAUDE.local.md"), "utf8")).toBe("Mine.\n");
    expect(result.manual).toEqual([expect.stringMatching(/CLAUDE\.local\.md/)]);
  });

  it("edits .gemini/settings.json only when the edit keeps its formatting; otherwise leaves the edit to the human", () => {
    const canonical = `${JSON.stringify({ theme: "Dracula", context: { fileName: "GEMINI.md" } }, null, 2)}\n`;
    const root = project({ ".gemini/settings.json": canonical });
    install(root);
    expect(JSON.parse(readFileSync(join(root, ".gemini/settings.json"), "utf8"))).toEqual({
      theme: "Dracula",
      context: { fileName: ["GEMINI.md", "AGENTS.md"] },
    });

    for (const raw of ['{"theme":"Dracula"}\n', '{\n  // my theme\n  "theme": "Dracula"\n}\n', "[1]\n"]) {
      const kept = project({ ".gemini/settings.json": raw });
      const result = install(kept);
      expect(readFileSync(join(kept, ".gemini/settings.json"), "utf8"), raw).toBe(raw);
      expect(result.manual, raw).toEqual([expect.stringMatching(/context\.fileName in \.gemini\/settings\.json/)]);
      expect(result.changes.some((c) => c.path === ".gemini/settings.json"), raw).toBe(false);
    }

    const absent = project();
    install(absent);
    expect(existsSync(join(absent, ".gemini"))).toBe(false);
    install(absent, { agents: ["gemini"] });
    expect(JSON.parse(readFileSync(join(absent, ".gemini/settings.json"), "utf8"))).toEqual({ context: { fileName: ["GEMINI.md", "AGENTS.md"] } });
  });

  it("adds read: to .aider.conf.yml only when it has none; an existing read: entry is the human's to extend", () => {
    const root = project({ ".aider.conf.yml": "model: x\n" });
    install(root);
    expect(readFileSync(join(root, ".aider.conf.yml"), "utf8")).toBe("model: x\nread: AGENTS.md # added by varlatch agents install\n");
    const theirs = "read: [CONVENTIONS.md]\n";
    const kept = project({ ".aider.conf.yml": theirs });
    const result = install(kept);
    expect(readFileSync(join(kept, ".aider.conf.yml"), "utf8")).toBe(theirs);
    expect(result.manual).toEqual(["add AGENTS.md to the read: entry in .aider.conf.yml"]);
  });

  it("user scope writes only the two user-level skill directories", () => {
    const home = project({ "AGENTS.md": "global\n" });
    install(home, { scope: "user" });
    expect(Object.keys(snapshot(home)).sort()).toEqual([...SKILL_PATHS, "AGENTS.md"].sort());
    expect(readFileSync(join(home, "AGENTS.md"), "utf8")).toBe("global\n");
    expect(() => install(home, { scope: "user", agents: ["codex"] })).toThrow(/--agent applies to a project/);
  });

  it("refuses an unknown coding agent", () => {
    expect(() => install(project(), { agents: ["nosuch"] })).toThrow(/unknown coding agent nosuch/);
  });
});

describe("the CLI", () => {
  it("agents guide prints the skill or a reference on stdout; an unknown topic is a usage error", async () => {
    const cwd = project();
    const all = await cli(["--assisted", "agents", "guide"], cwd);
    expect(all.code).toBe(0);
    expect(all.stdout.startsWith("# Varlatch\n")).toBe(true);
    const setup = await cli(["agents", "guide", "setup"], cwd);
    expect(setup.code).toBe(0);
    expect(setup.stdout).toBe(SKILL_FILES["references/setup.md"]);
    const bad = await cli(["agents", "guide", "nosuch"], cwd);
    expect(bad.code).toBe(EXIT.usage);
    expect(bad.stderr).toMatch(/no guide topic nosuch/);
    expect(snapshot(cwd)).toEqual({});
  });

  it("agents install writes at the varlatch.toml root from a subdirectory; --check exits 1 on drift, 0 when clean", async () => {
    const root = project({ "varlatch.toml": 'organization = "acme"\nproject = "web"\n', "src/app/index.ts": "" });
    const cwd = join(root, "src/app");
    expect((await cli(["agents", "install", "--check"], cwd)).code).toBe(EXIT.failure);
    const r = await cli(["agents", "install", "--json"], cwd);
    expect(r.code).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc).toMatchObject({ version: 1, scope: "project", root, drift: true, manual: [], leftInPlace: [] });
    expect(existsSync(join(root, ".agents/skills/varlatch/SKILL.md"))).toBe(true);
    expect(existsSync(join(cwd, ".agents"))).toBe(false);
    const clean = await cli(["agents", "install", "--check"], cwd);
    expect(clean.code).toBe(0);
    expect(clean.stdout).toBe("The agent files are up to date.\n");
    writeFileSync(join(root, ".agents/skills/varlatch/SKILL.md"), "edited\n");
    const drift = await cli(["agents", "install", "--check"], cwd);
    expect(drift.code).toBe(EXIT.failure);
    expect(drift.stdout).toBe("differs: .agents/skills/varlatch/SKILL.md\n");
  });

  it("agents install --scope user writes under HOME", async () => {
    const home = join(dir, "home-user");
    const r = await cli(["agents", "install", "--scope", "user"], project(), { HOME: home });
    expect(r.code).toBe(0);
    expect(Object.keys(snapshot(home)).sort()).toEqual(SKILL_PATHS.sort());
  });

  it("wrong command lines exit 64, and a damaged AGENTS.md exits 78, each writing nothing", async () => {
    const cwd = project();
    for (const args of [
      ["agents"],
      ["agents", "nosuch"],
      ["agents", "install", "--check", "--remove"],
      ["agents", "install", "--scope", "system"],
      ["agents", "install", "--agent", "nosuch"],
      ["agents", "install", "--scope", "user", "--agent", "codex"],
    ]) {
      const r = await cli(args, cwd);
      expect(r.code, args.join(" ")).toBe(EXIT.usage);
    }
    expect(snapshot(cwd)).toEqual({});
    const damaged = project({ "AGENTS.md": "<!-- varlatch:begin -->\nhalf\n" });
    const r = await cli(["agents", "install"], damaged);
    expect(r.code).toBe(EXIT.config);
    expect(r.stderr).toMatch(/without <!-- varlatch:end -->/);
    expect(snapshot(damaged)).toEqual({ "AGENTS.md": "<!-- varlatch:begin -->\nhalf\n" });
  });

  it("init writes the agent files by default, and --no-agent-files skips them", async () => {
    const withFiles = project({ "AGENTS.md": "# Mine\n" });
    const r = await cli(["init", "--org", "acme", "--project", "web"], withFiles);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Wrote the Varlatch skill and instructions for coding agents: \.agents\/skills\/varlatch\/, \.claude\/skills\/varlatch\/, AGENTS\.md\./);
    expect(Object.keys(snapshot(withFiles)).sort()).toEqual([...SKILL_PATHS, "AGENTS.md", "varlatch.toml"].sort());
    expect(readFileSync(join(withFiles, "AGENTS.md"), "utf8")).toBe(`# Mine\n\n${agentsBlock()}\n`);

    const without = project();
    const s = await cli(["init", "--org", "acme", "--project", "web", "--no-agent-files"], without);
    expect(s.code).toBe(0);
    expect(Object.keys(snapshot(without))).toEqual(["varlatch.toml"]);
  });

  it("init still succeeds when the agent files cannot be written, and says how to retry", async () => {
    const damaged = project({ "AGENTS.md": "<!-- varlatch:end -->\n" });
    const r = await cli(["init", "--org", "acme", "--project", "web"], damaged);
    expect(r.code).toBe(0);
    expect(existsSync(join(damaged, "varlatch.toml"))).toBe(true);
    expect(r.stderr).toMatch(/files for coding agents were not written .* run varlatch agents install to try again/);
  });
});
