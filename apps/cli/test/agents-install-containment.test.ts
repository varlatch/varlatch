// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";
import { AgentsInstallError, runInstall, type InstallOptions } from "../src/agents/install.js";
import { SKILL_FILES } from "../src/agents/skillFiles.generated.js";

/**
 * `varlatch agents install` never reads, writes or removes anything through
 * a directory below the scope's root that is a symbolic link: the whole run
 * is refused (78) before anything is touched, inside the root or outside
 * it. Files are replaced by renaming a synced temporary file over them,
 * keeping their mode and the names install gives one file.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-agents-contain-"));
const bundle = join(dir, "varlatch.cjs");
let n = 0;

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

function fresh(): string {
  const d = join(dir, `t${n++}`);
  mkdirSync(d, { recursive: true });
  return d;
}

function writeAt(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/** Every entry under root: each file's mode and content, each directory, each link's target. */
function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const path = join(d, entry.name);
      const rel = relative(root, path);
      const info = lstatSync(path);
      if (info.isSymbolicLink()) out[rel] = `link ${readlinkSync(path)}`;
      else if (info.isDirectory()) {
        out[`${rel}/`] = (info.mode & 0o777).toString(8);
        walk(path);
      } else out[rel] = `${(info.mode & 0o777).toString(8)} ${readFileSync(path, "utf8")}`;
    }
  };
  if (existsSync(root)) walk(root);
  return out;
}

function refusal(fn: () => unknown): AgentsInstallError {
  try {
    fn();
  } catch (err) {
    if (err instanceof AgentsInstallError) return err;
    throw err;
  }
  throw new Error("the run was not refused");
}

describe("a directory below the root that is a symbolic link", () => {
  const cases: {
    name: string;
    scope?: "project" | "user";
    mode: InstallOptions["mode"];
    extra?: Partial<InstallOptions>;
    link: string;
    outside: Record<string, string>;
  }[] = [
    { name: ".claude, --guardrails", mode: "install", extra: { guardrails: true }, link: ".claude", outside: { "settings.json": "{}\n", "skills/varlatch/personal.txt": "mine\n" } },
    { name: ".claude, plain install", mode: "install", link: ".claude", outside: { "skills/varlatch/personal.txt": "mine\n" } },
    { name: "skills", mode: "install", link: ".claude/skills", outside: { "varlatch/personal.txt": "mine\n" } },
    { name: "skills/varlatch", mode: "install", link: ".agents/skills/varlatch", outside: { "personal.txt": "mine\n", "sub/notes.md": "mine\n" } },
    { name: "a directory inside the skill", mode: "install", link: ".agents/skills/varlatch/references", outside: { "run.md": "mine\n" } },
    { name: "--remove through a linked parent", mode: "remove", link: ".agents", outside: { "skills/varlatch/SKILL.md": "mine\n", "skills/varlatch/references/run.md": "mine\n" } },
    { name: "--remove, a linked directory it only prunes", mode: "remove", link: ".vscode", outside: {} },
    { name: "--check does not read through it either", mode: "check", link: ".agents/skills", outside: { "varlatch/SKILL.md": "mine\n" } },
    { name: ".codex, --mcp", mode: "install", extra: { mcp: true, agents: ["codex"] }, link: ".codex", outside: { "config.toml": 'model = "o3"\n' } },
    { name: ".gemini, read by every project install", mode: "install", link: ".gemini", outside: { "settings.json": "{}\n" } },
    { name: "user scope, a linked skill directory", scope: "user", mode: "install", link: ".claude", outside: { "skills/varlatch/personal.txt": "mine\n" } },
    { name: "user scope --remove, a linked ~/.codex", scope: "user", mode: "remove", link: ".codex", outside: { "config.toml": "x = 1\n", "empty/.keep": "" } },
  ];

  for (const c of cases) {
    it(`refuses the whole run, changing nothing inside or outside the root: ${c.name}`, () => {
      const base = fresh();
      const root = join(base, "root");
      const outside = join(base, "outside");
      mkdirSync(outside, { recursive: true });
      for (const [path, content] of Object.entries(c.outside)) writeAt(join(outside, path), content);
      writeAt(join(root, "AGENTS.md"), "# Rules\n");
      mkdirSync(dirname(join(root, c.link)), { recursive: true });
      symlinkSync(outside, join(root, c.link));
      const beforeRoot = snapshot(root);
      const beforeOutside = snapshot(outside);
      const err = refusal(() => runInstall({ scope: c.scope ?? "project", root, version: "1", agents: [], mode: c.mode, ...c.extra }));
      expect(err.usage).toBe(false);
      expect(err.message).toMatch(new RegExp(`^${c.link.replaceAll(".", "\\.")} is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed\\. Replace it with a directory, then run this again`));
      expect(snapshot(outside)).toEqual(beforeOutside);
      expect(snapshot(root)).toEqual(beforeRoot);
    });
  }

  it("a refused --remove lists the skill files to remove by hand, none of them behind a link", () => {
    const base = fresh();
    const home = join(base, "home");
    const outside = join(base, "outside");
    runInstall({ scope: "user", root: home, version: "1", agents: [], mode: "install" });
    writeAt(join(outside, "config.toml"), "x = 1\n");
    symlinkSync(outside, join(home, ".codex"));
    const before = snapshot(base);
    const err = refusal(() => runInstall({ scope: "user", root: home, version: "1", agents: [], mode: "remove" }));
    expect(err.message.startsWith(
      ".codex is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed. " +
        "Replace it with a directory, then run this again, or remove these files by hand:\n",
    )).toBe(true);
    const listed = Object.keys(SKILL_FILES).flatMap((p) => [join(home, ".agents", "skills", "varlatch", p), join(home, ".claude", "skills", "varlatch", p)]);
    for (const path of listed) expect(err.message).toContain(`\n  ${path}`);
    expect(err.message.split("\n  ").length - 1).toBe(listed.length);
    expect(snapshot(base)).toEqual(before);
  });

  it("a user-scope install ignores a linked directory it does not use", () => {
    const base = fresh();
    const home = join(base, "home");
    const outside = join(base, "outside");
    writeAt(join(outside, "config.toml"), "x = 1\n");
    mkdirSync(home, { recursive: true });
    symlinkSync(outside, join(home, ".codex"));
    const before = snapshot(outside);
    runInstall({ scope: "user", root: home, version: "1", agents: [], mode: "install" });
    expect(snapshot(outside)).toEqual(before);
    expect(existsSync(join(home, ".agents", "skills", "varlatch", "SKILL.md"))).toBe(true);
  });

  it("the CLI exits 78 with the refusal, in every mode, and writes nothing through the link", async () => {
    const base = fresh();
    const root = join(base, "root");
    const outside = join(base, "outside");
    writeAt(join(outside, "personal.txt"), "mine\n");
    writeAt(join(root, "varlatch.toml"), 'server = "http://127.0.0.1:9"\n');
    mkdirSync(join(root, ".claude", "skills"), { recursive: true });
    symlinkSync(outside, join(root, ".claude", "skills", "varlatch"));
    const before = snapshot(outside);
    for (const args of [["agents", "install"], ["agents", "install", "--check"], ["agents", "install", "--remove"]]) {
      const r = await cli(args, root);
      expect(r.code, args.join(" ")).toBe(EXIT.config);
      expect(r.stderr).toContain(".claude/skills/varlatch is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed.");
      expect(r.stdout).toBe("");
    }
    expect(snapshot(outside)).toEqual(before);
    expect(existsSync(join(root, "AGENTS.md"))).toBe(false);
  });
});

describe("replacements", () => {
  it("keep the mode the person gave a file, and leave no temporary file", () => {
    const root = fresh();
    writeAt(join(root, "AGENTS.md"), "# Rules\n");
    chmodSync(join(root, "AGENTS.md"), 0o600);
    writeAt(join(root, ".claude", "settings.json"), "{}\n");
    chmodSync(join(root, ".claude", "settings.json"), 0o640);
    runInstall({ scope: "project", root, version: "1", agents: [], mode: "install", guardrails: true });
    if (process.platform !== "win32") {
      expect(statSync(join(root, "AGENTS.md")).mode & 0o777).toBe(0o600);
      expect(statSync(join(root, ".claude", "settings.json")).mode & 0o777).toBe(0o640);
    }
    expect(readFileSync(join(root, "AGENTS.md"), "utf8").startsWith("# Rules\n\n<!-- varlatch:begin -->")).toBe(true);
    expect(Object.keys(snapshot(root)).filter((p) => p.includes(".varlatch-"))).toEqual([]);
  });

  it("are renamed over the file, never written in place", () => {
    const root = fresh();
    writeAt(join(root, ".claude", "settings.json"), "{}\n");
    const before = statSync(join(root, ".claude", "settings.json")).ino;
    runInstall({ scope: "project", root, version: "1", agents: [], mode: "install", guardrails: true });
    expect(statSync(join(root, ".claude", "settings.json")).ino).not.toBe(before);
  });

  it("keep an AGENTS.md and the CLAUDE.md that is it one file", () => {
    const root = fresh();
    writeAt(join(root, "AGENTS.md"), "# Rules\n");
    linkSync(join(root, "AGENTS.md"), join(root, "CLAUDE.md"));
    runInstall({ scope: "project", root, version: "1", agents: [], mode: "install" });
    const a = readFileSync(join(root, "AGENTS.md"), "utf8");
    expect(readFileSync(join(root, "CLAUDE.md"), "utf8")).toBe(a);
    expect(a).toContain("<!-- varlatch:begin -->");
    expect(statSync(join(root, "AGENTS.md")).ino).toBe(statSync(join(root, "CLAUDE.md")).ino);
    expect(Object.keys(snapshot(root)).filter((p) => p.includes(".varlatch-"))).toEqual([]);
  });

  it("refuse, before anything changes, a file with a name the CLI cannot see", () => {
    for (const alsoClaude of [false, true]) {
      const base = fresh();
      const root = join(base, "root");
      const outside = join(base, "outside");
      writeAt(join(outside, "notes.md"), "# Mine\n");
      mkdirSync(root, { recursive: true });
      linkSync(join(outside, "notes.md"), join(root, "AGENTS.md"));
      if (alsoClaude) linkSync(join(root, "AGENTS.md"), join(root, "CLAUDE.md"));
      const before = snapshot(base);
      const err = refusal(() => runInstall({ scope: "project", root, version: "1", agents: [], mode: "install" }));
      expect(err.usage).toBe(false);
      expect(err.message).toBe(
        "AGENTS.md has another name (a hard link) the CLI cannot see, so nothing was changed; replace it with a plain copy of itself, then run this again",
      );
      // Nothing to change: AGENTS.md holds no block.
      runInstall({ scope: "project", root, version: "1", agents: [], mode: "remove" });
      expect(snapshot(base)).toEqual(before);
    }
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
