// SPDX-License-Identifier: Apache-2.0
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `varlatch scan` end to end: the CLI bundled from this checkout's source,
 * a recording fake server, and real Git repositories. Covers the staged
 * index (A-S1), the pre-commit hook with real commits (A-S4), not-scanned
 * files (A-S5), the single audited disclosure with purpose "scan", and that
 * values reach neither the output nor the disk.
 */

const API_KEY = "tok-api-aaaabbbbccccdddd";
const API_KEY_OLD = "tok-old-xxxxyyyyzzzz0000";
const DB_PASS = "hunter2-hunter2-hunter2";
const PIN = "1234567";
const VALUES = [API_KEY, API_KEY_OLD, DB_PASS];

const dir = mkdtempSync(join(tmpdir(), "varlatch-scan-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const bin = join(dir, "bin");
let server: http.Server;
let port = 0;

interface Recorded {
  method: string;
  url: string;
  body: unknown;
}
let requests: Recorded[] = [];
let serverMode: { capability: boolean; deny: boolean } = { capability: true, deny: false };

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    requests.push({ method: req.method ?? "", url, body: raw ? JSON.parse(raw) : null });
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url === "/v1/meta") {
      return json(200, {
        apiMajor: 1,
        serverVersion: serverMode.capability ? "0.11.0" : "0.10.1",
        capabilities: serverMode.capability ? ["secrets.requested-disclosure", "secrets.disclosure-purpose"] : ["secrets.requested-disclosure"],
      });
    }
    if (url.endsWith("/disclosures") && req.method === "POST") {
      if (serverMode.deny) {
        return json(403, { error: { code: "PERMISSION_DENIED", message: "secret.reveal required", requestId: "req_denied" } });
      }
      return json(200, {
        items: [
          { name: "API_KEY", versionId: "ver_api2", value: API_KEY, retiring: { versionId: "ver_api1", value: API_KEY_OLD } },
          { name: "DB_PASS", versionId: "ver_db", value: DB_PASS },
          { name: "PIN", versionId: "ver_pin", value: PIN },
        ],
        withheld: [],
      });
    }
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: url, requestId: "req_404" } });
  });
}

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
  // The hook calls `varlatch` from PATH, as an installed CLI would be.
  mkdirSync(bin);
  mkdirSync(env.TMPDIR);
  writeFileSync(join(bin, "varlatch"), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(bundle)} "$@"\n`, { mode: 0o755 });
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  serverMode = { capability: true, deny: false };
});

const env = {
  PATH: `${bin}:${process.env.PATH}`,
  HOME: dir,
  VARLATCH_CONFIG_DIR: join(dir, "config"),
  VARLATCH_TOKEN: "vlt_test",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: join(dir, "gitconfig-empty"),
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.com",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.com",
  TMPDIR: join(dir, "tmp"),
};

let repoCount = 0;
/** A fresh Git repository whose varlatch.toml sits at `projectDir` inside it. */
function newRepo(projectDir = "."): { top: string; project: string } {
  const top = join(dir, `repo-${++repoCount}`);
  mkdirSync(top);
  git(top, "init", "-q", "-b", "main");
  const project = join(top, projectDir);
  mkdirSync(project, { recursive: true });
  writeFileSync(
    join(project, "varlatch.toml"),
    `organization = "acme"\nproject = "web"\nserver = "http://127.0.0.1:${port}"\ndefault_environment = "production"\n`,
  );
  return { top, project };
}

function git(cwd: string, ...args: string[]) {
  const r = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}

/**
 * Run a command asynchronously: the fake server answers from this process,
 * so a synchronous spawn would block it.
 */
function run(
  cmd: string,
  args: string[],
  cwd: string,
  /** Added to the suite's environment; `undefined` leaves a variable out. */
  extraEnv: Record<string, string | undefined> = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const merged: Record<string, string> = {};
    for (const [k, v] of Object.entries({ ...env, ...extraEnv })) if (v !== undefined) merged[k] = v;
    const child = spawn(cmd, args, { cwd, env: merged, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function varlatch(cwd: string, ...args: string[]) {
  return run(process.execPath, [bundle, ...args], cwd);
}

function commit(cwd: string, ...args: string[]) {
  return run("git", ["commit", ...args], cwd);
}

function disclosures(): Recorded[] {
  return requests.filter((r) => r.url.endsWith("/disclosures"));
}

function expectNoValues(text: string) {
  for (const v of [...VALUES, PIN]) expect(text).not.toContain(v);
  expect(text).not.toContain("CANARY");
}

describe("varlatch scan --staged reads the Git index, not the working tree (A-S1)", () => {
  it("finds staged-then-edited and staged-then-deleted Secrets, ignores unstaged ones, with one audited disclosure", async () => {
    const { top } = newRepo();
    writeFileSync(join(top, "README.md"), "hello\n");
    git(top, "add", "README.md", "varlatch.toml");
    git(top, "commit", "-q", "-m", "init", "--no-verify");

    writeFileSync(join(top, "config.env"), `CANARY_LEFT API_KEY=${API_KEY} CANARY_RIGHT\n`);
    git(top, "add", "config.env");
    writeFileSync(join(top, "config.env"), "API_KEY=\n"); // edited after staging
    writeFileSync(join(top, "notes.txt"), `line one\nold key ${API_KEY_OLD}\n`);
    git(top, "add", "notes.txt");
    unlinkSync(join(top, "notes.txt")); // deleted after staging
    writeFileSync(join(top, "untracked.txt"), DB_PASS); // never staged
    writeFileSync(join(top, "README.md"), `hello\n${DB_PASS}\n`); // modified, not staged

    const run = await varlatch(top, "scan", "--staged", "--json");
    expect(run.code, run.stderr).toBe(1);
    const report = JSON.parse(run.stdout);
    expect(report.findings.map((f: { path: string; item: string; versionId: string; retiring: boolean; line: number; column: number }) => [f.path, f.item, f.versionId, f.retiring, f.line, f.column])).toEqual([
      ["config.env", "API_KEY", "ver_api2", false, 1, 21],
      ["notes.txt", "API_KEY", "ver_api1", true, 2, 9],
    ]);
    expect(report).toMatchObject({ version: 1, mode: "staged", environment: "production", exitCode: 1, filesScanned: 2, skippedItems: ["PIN"] });
    expectNoValues(run.stdout + run.stderr);
    // One disclosure, declared as a scan, of every Secret this identity may retrieve.
    expect(disclosures()).toEqual([
      {
        method: "POST",
        url: "/v1/organizations/acme/projects/web/environments/production/disclosures",
        body: { scope: "all-authorized-secrets", purpose: "scan" },
      },
    ]);
  });

  it("works before the first commit, and asks for nothing when nothing is staged", async () => {
    const { top } = newRepo();
    let run = await varlatch(top, "scan", "--staged");
    expect(run.code, run.stderr).toBe(0);
    expect(run.stdout).toContain("nothing is staged");
    expect(requests).toEqual([]);

    writeFileSync(join(top, "a.txt"), `${DB_PASS}\n`);
    git(top, "add", "a.txt");
    run = await varlatch(top, "scan", "--staged");
    expect(run.code).toBe(1);
    expect(run.stdout).toContain("a.txt:1:1: DB_PASS (version ver_db), as written");
    expectNoValues(run.stdout + run.stderr);
  });

  it("reports a staged file over the bound as not scanned, and exits 2 when nothing is found", async () => {
    const { top } = newRepo();
    writeFileSync(join(top, "big.bin"), Buffer.alloc(2048, 1));
    writeFileSync(join(top, "ok.txt"), "clean\n");
    git(top, "add", ".");
    const run = await varlatch(top, "scan", "--staged", "--max-file-size", "1K");
    expect(run.code, run.stderr).toBe(2);
    expect(run.stdout).toContain("big.bin: larger than the per-file bound (2 KiB > 1 KiB)");
    expect(run.stdout).toContain("varlatch scan: 2 staged file(s) checked against 3 Secret value(s) of production: no findings. 1 not scanned.");
    expect(disclosures()).toHaveLength(1);

    // When no file fits the bounds, nothing is read and nothing is disclosed.
    requests = [];
    const none = await varlatch(top, "scan", "--staged", "--max-file-size", "5");
    expect(none.code, none.stderr).toBe(2);
    expect(none.stdout).toContain("Not scanned (3), so not known to be clean:");
    expect(requests).toEqual([]);
  });
});

describe("varlatch scan <path> walks build output (A-S5)", () => {
  it("scans binary files as bytes and reports what it could not read, never as clean", async () => {
    const { project } = newRepo();
    const out = join(project, "dist");
    mkdirSync(join(out, "assets"), { recursive: true });
    writeFileSync(join(out, "app.js"), `var k="${Buffer.from(`user:${API_KEY}`).toString("base64")}";\n`);
    writeFileSync(join(out, "assets", "blob.bin"), Buffer.concat([Buffer.from([0, 0, 0xff]), Buffer.from(DB_PASS), Buffer.from([0])]));
    writeFileSync(join(out, "clean.txt"), "nothing here\n");
    const locked = join(out, "locked.txt");
    writeFileSync(locked, DB_PASS);
    chmodSync(locked, 0o000);
    symlinkSync("/etc/hostname", join(out, "link"));
    const run = await varlatch(project, "scan", "dist", "missing-dir", "--json");
    chmodSync(locked, 0o600);
    const report = JSON.parse(run.stdout);
    expect(report.findings.map((f: { path: string; item: string; form: string }) => [f.path, f.item, f.form])).toEqual([
      ["dist/app.js", "API_KEY", "base64"],
      ["dist/assets/blob.bin", "DB_PASS", "raw"],
    ]);
    const notScanned = Object.fromEntries(report.notScanned.map((n: { path: string; reason: string }) => [n.path, n.reason]));
    expect(notScanned["dist/link"]).toContain("symbolic link, not followed");
    expect(notScanned["missing-dir"]).toBe("does not exist");
    if (process.getuid?.() !== 0) expect(notScanned["dist/locked.txt"]).toBe("unreadable (EACCES)");
    expect(run.code).toBe(1);
    expectNoValues(run.stdout + run.stderr);

    // Without findings, anything not scanned still makes the scan incomplete.
    const clean = await varlatch(project, "scan", "dist/clean.txt", "missing-dir");
    expect(clean.code).toBe(2);
    expect(clean.stdout).toContain("Not scanned (1), so not known to be clean:");
    const all = await varlatch(project, "scan", "dist/clean.txt");
    expect(all.code).toBe(0);
    expect(all.stdout).toContain("no findings.");
  });

  it("keeps values in memory only: no file the scan could write holds any of them", async () => {
    const { project } = newRepo();
    const fixture = join(project, "build", "out.txt");
    mkdirSync(join(project, "build"));
    writeFileSync(fixture, `CANARY ${API_KEY} ${DB_PASS} ${API_KEY_OLD}\n`);
    const run = await varlatch(project, "scan", "build", "--write-baseline");
    expect(run.code, run.stderr).toBe(0);
    expectNoValues(run.stdout + run.stderr);
    // Nothing the scan could have written holds a value: the project (baseline
    // included), the CLI's configuration directory, and its temporary directory.
    const leaks: string[] = [];
    const walk = (d: string) => {
      if (!existsSync(d)) return;
      for (const name of readdirSync(d)) {
        const p = join(d, name);
        const st = statSync(p, { throwIfNoEntry: false });
        if (!st) continue;
        if (st.isDirectory()) walk(p);
        else if (p !== fixture) {
          const content = readFileSync(p);
          for (const v of [...VALUES, PIN]) if (content.includes(v)) leaks.push(p);
        }
      }
    };
    walk(project);
    walk(join(dir, "config"));
    walk(env.TMPDIR);
    expect(leaks).toEqual([]);
    const baseline = JSON.parse(readFileSync(join(project, "varlatch-scan-baseline.json"), "utf8"));
    expect(baseline).toEqual({
      version: 1,
      entries: [
        { path: "build/out.txt", item: "API_KEY", versionId: "ver_api1" },
        { path: "build/out.txt", item: "API_KEY", versionId: "ver_api2" },
        { path: "build/out.txt", item: "DB_PASS", versionId: "ver_db" },
      ],
    });
    // The baseline now allows exactly those findings.
    const again = await varlatch(project, "scan", "build");
    expect(again.code).toBe(0);
    expect(again.stdout).toContain("3 allowed by a marker or the baseline");
  });
});

describe("retrieval", () => {
  it("an identity without secret.reveal scans nothing and exits 1", async () => {
    serverMode.deny = true;
    const { project } = newRepo();
    writeFileSync(join(project, "a.txt"), "x\n");
    const run = await varlatch(project, "scan", "a.txt");
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("nothing was scanned: this identity may not retrieve Secrets in production");
    expect(run.stderr).toContain("secret.reveal");
  });

  it("an older server that records no purpose is named, and the scan still runs", async () => {
    serverMode.capability = false;
    const { project } = newRepo();
    writeFileSync(join(project, "a.txt"), `${DB_PASS}\n`);
    const run = await varlatch(project, "scan", "a.txt");
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("does not record a disclosure purpose");
  });

  it("names the values too short to check", async () => {
    const { project } = newRepo();
    writeFileSync(join(project, "a.txt"), `pin=${PIN}\n`);
    const run = await varlatch(project, "scan", "a.txt");
    expect(run.code).toBe(0);
    expect(run.stderr).toContain("values shorter than 8 bytes are not checked: PIN");
    expectNoValues(run.stdout + run.stderr);
  });

  it("refuses bad usage before asking the server for anything", async () => {
    const { project } = newRepo();
    for (const args of [["scan"], ["scan", "--staged", "a.txt"], ["scan", "--bogus", "a"], ["scan", "a", "--max-file-size", "lots"]]) {
      const run = await varlatch(project, ...args);
      expect(run.code, args.join(" ")).toBe(1);
      expect(run.stderr).toContain("Usage: varlatch scan");
    }
    expect(requests).toEqual([]);
  });
});

describe("the pre-commit hook, with real commits (A-S4)", () => {
  it("is installed only on request, runs varlatch scan --staged, and blocks a commit that stages a Secret", async () => {
    const { top, project } = newRepo("services/api");
    const hook = join(top, ".git", "hooks", "pre-commit");
    expect(existsSync(hook)).toBe(false);
    // A scan never installs it.
    await varlatch(project, "scan", "--staged");
    expect(existsSync(hook)).toBe(false);

    const install = await varlatch(project, "scan", "--install-hook");
    expect(install.code, install.stderr).toBe(0);
    const script = readFileSync(hook, "utf8");
    expect(script).toContain("exec varlatch scan --staged");
    expect(script).toContain("cd 'services/api'");
    expect(statSync(hook).mode & 0o111).not.toBe(0);

    // A commit that stages a Secret is stopped, and nothing is recorded.
    writeFileSync(join(top, "leak.txt"), `CANARY ${DB_PASS}\n`);
    git(top, "add", "leak.txt", "services/api/varlatch.toml");
    let committed = await commit(top, "-m", "leak");
    expect(committed.code).not.toBe(0);
    expect(committed.stdout + committed.stderr).toContain("../../leak.txt:1:8: DB_PASS (version ver_db)");
    expectNoValues(committed.stdout + committed.stderr);
    expect(spawnSync("git", ["rev-parse", "--verify", "HEAD"], { cwd: top, env }).status).not.toBe(0);
    expect(disclosures()).toHaveLength(1);
    expect(disclosures()[0]!.body).toEqual({ scope: "all-authorized-secrets", purpose: "scan" });

    // Staging the fixed file lets the commit through.
    writeFileSync(join(top, "leak.txt"), "fixed\n");
    git(top, "add", "leak.txt");
    committed = await commit(top, "-q", "-m", "clean");
    expect(committed.code, committed.stdout + committed.stderr).toBe(0);

    // `git commit -a` stages through a temporary index; the hook sees it.
    writeFileSync(join(top, "leak.txt"), `again ${API_KEY}\n`);
    committed = await commit(top, "-a", "-m", "leak via -a");
    expect(committed.code).not.toBe(0);
    expect(committed.stdout + committed.stderr).toContain("leak.txt:1:7: API_KEY (version ver_api2)");
    expect(git(top, "log", "--oneline")).not.toContain("leak via -a");

    // --no-verify skips it, as with any hook.
    committed = await commit(top, "-q", "-a", "--no-verify", "-m", "skipped");
    expect(committed.code).toBe(0);
  });

  it("never replaces a hook it did not write, and updates its own", async () => {
    const { top, project } = newRepo();
    const hook = join(top, ".git", "hooks", "pre-commit");
    mkdirSync(join(top, ".git", "hooks"), { recursive: true });
    writeFileSync(hook, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    const refused = await varlatch(project, "scan", "--install-hook");
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("was not written by varlatch; it was left unchanged");
    expect(refused.stderr).toContain("varlatch scan --staged || exit 1");
    expect(readFileSync(hook, "utf8")).toBe("#!/bin/sh\nexit 0\n");

    unlinkSync(hook);
    expect((await varlatch(project, "scan", "--install-hook")).code).toBe(0);
    const again = await varlatch(project, "scan", "--install-hook", "-e", "staging");
    expect(again.code).toBe(0);
    expect(readFileSync(hook, "utf8")).toContain("exec varlatch scan --staged --environment 'staging'");
    expect(requests).toEqual([]);
  });
});

describe("varlatch scan <path> outside the project", () => {
  it("scans a file outside the project directory, such as a shell history, with the project's context", async () => {
    const { project } = newRepo();
    const history = join(dir, `history-${repoCount}`);
    writeFileSync(history, `ls\nexport DB_PASS=${DB_PASS}\n`);
    const run = await varlatch(project, "scan", history);
    expect(run.code, run.stderr).toBe(1);
    expect(run.stdout).toContain(`../history-${repoCount}:2:16: DB_PASS (version ver_db), as written`);
    expect(disclosures()).toHaveLength(1);
    expectNoValues(run.stdout + run.stderr);
  });
});

describe("varlatch scan --find-files lists likely copies by name (ADR-0054 Decision 8)", () => {
  /**
   * A tree with every case: a Git repository with ignored, unignored, and
   * committed copies, a nested repository, links, a template, an unreadable
   * file, and no varlatch.toml anywhere.
   */
  function copiesTree(): { top: string; outside: string } {
    const top = join(dir, `copies-${++repoCount}`);
    mkdirSync(top);
    git(top, "init", "-q", "-b", "main");
    writeFileSync(join(top, ".gitignore"), ".env\n");
    writeFileSync(join(top, ".env"), `API_KEY=${API_KEY}\n`);
    writeFileSync(join(top, ".env.example"), "API_KEY=\n");
    mkdirSync(join(top, "config"));
    writeFileSync(join(top, "config", ".env.local"), `DB_PASS=${DB_PASS}\n`);
    mkdirSync(join(top, "certs"));
    writeFileSync(join(top, "certs", "server.key"), "CANARY\n");
    git(top, "add", ".gitignore", ".env.example", "certs/server.key");
    git(top, "commit", "-q", "-m", "init");
    writeFileSync(join(top, "locked.pem"), "CANARY\n");
    chmodSync(join(top, "locked.pem"), 0o000);
    mkdirSync(join(top, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(top, "node_modules", "pkg", ".env"), "CANARY\n");
    const nested = join(top, "vendor", "tool");
    mkdirSync(nested, { recursive: true });
    git(nested, "init", "-q", "-b", "main");
    writeFileSync(join(nested, ".env.production"), "CANARY\n");
    const outside = join(dir, `outside-${repoCount}`);
    mkdirSync(outside);
    writeFileSync(join(outside, ".env"), "CANARY\n");
    symlinkSync(outside, join(top, "linked-dir"));
    symlinkSync(join(outside, ".env"), join(top, ".env.link"));
    return { top, outside };
  }

  const expected = [
    { path: ".env", kind: "dotenv", symlink: false, git: "ignored" },
    { path: ".env.link", kind: "dotenv", symlink: true, git: "not-ignored" },
    { path: "certs/server.key", kind: "key", symlink: false, git: "not-ignored" },
    { path: "config/.env.local", kind: "dotenv", symlink: false, git: "not-ignored" },
    { path: "locked.pem", kind: "key", symlink: false, git: "not-ignored" },
    { path: "vendor/tool/.env.production", kind: "dotenv", symlink: false, git: "not-ignored" },
  ];

  it("names each file and its Git state, needs no project, credential, or server, and opens no file", async () => {
    const { top, outside } = copiesTree();
    // Record every call that opens, reads, or follows a path in the CLI process.
    const preload = join(dir, "fs-recorder.cjs");
    const log = join(dir, `fs-log-${repoCount}.txt`);
    writeFileSync(
      preload,
      `const fs = require("node:fs");
const fsp = require("node:fs/promises");
const calls = [];
const wrap = (target, name, label) => {
  const orig = target[name];
  target[name] = Object.assign(function (p, ...rest) { calls.push(label + " " + String(p)); return orig.call(this, p, ...rest); }, orig);
};
for (const n of ["open", "openSync", "readFile", "readFileSync", "createReadStream", "stat", "statSync", "realpath", "realpathSync", "access", "accessSync"]) wrap(fs, n, n);
for (const n of ["open", "readFile", "stat", "realpath", "access"]) wrap(fsp, n, "promises." + n);
const write = fs.writeFileSync;
process.on("exit", () => write(process.env.FS_LOG, calls.join("\\n")));
`,
    );
    const found = await run(process.execPath, ["-r", preload, bundle, "scan", "--find-files", "--json"], top, {
      FS_LOG: log,
      VARLATCH_TOKEN: "",
      VARLATCH_ASSISTED: "0",
    });
    chmodSync(join(top, "locked.pem"), 0o600);
    expect(found.code, found.stderr).toBe(1);
    const report = JSON.parse(found.stdout);
    expect(report).toMatchObject({ version: 1, mode: "find-files", exitCode: 1, root: realpathSync(top), notSearched: [], stopped: false });
    expect(report.files).toEqual(expected);
    expect(requests).toEqual([]);
    expectNoValues(found.stdout + found.stderr);

    const calls = readFileSync(log, "utf8").split("\n").filter(Boolean);
    // The recorder works: the starting directory itself is resolved.
    expect(calls).toContain(`promises.realpath ${top}`);
    // No matched file, and nothing behind a link, is opened, read, or followed;
    // only directories are resolved (the Git top level of the nested repository).
    const matched = new Set([...expected.map((f) => join(top, f.path)), join(top, ".env.example"), join(top, "node_modules", "pkg", ".env")]);
    const touched = calls.filter((c) => {
      const path = c.slice(c.indexOf(" ") + 1);
      return matched.has(path) || path.startsWith(outside) || path.startsWith(join(top, "linked-dir"));
    });
    expect(touched).toEqual([]);

    // A directory outside any Git repository.
    const plain = await run(process.execPath, [bundle, "scan", "--find-files", outside, "--json"], top, { VARLATCH_ASSISTED: "0" });
    expect(plain.code, plain.stderr).toBe(1);
    expect(JSON.parse(plain.stdout).files).toEqual([{ path: ".env", kind: "dotenv", symlink: false, git: "no-repository" }]);
  });

  it("prints the same list in assisted mode as outside it, with the next steps", async () => {
    const { top } = copiesTree();
    chmodSync(join(top, "locked.pem"), 0o600);
    const human = await run(process.execPath, [bundle, "scan", "--find-files"], top, { VARLATCH_ASSISTED: "0" });
    expect(human.code, human.stderr).toBe(1);
    expect(human.stdout).toContain("  .env: ignored by Git\n");
    expect(human.stdout).toContain("  certs/server.key: not ignored by Git, so it can be committed\n");
    expect(human.stdout).toContain("  .env.link: a symbolic link, not followed; not ignored by Git, so it can be committed\n");
    expect(human.stdout).toContain("  vendor/tool/.env.production: not ignored by Git");
    expect(human.stdout).not.toContain(".env.example");
    expect(human.stdout).not.toContain("node_modules");
    expect(human.stdout).not.toContain("linked-dir");
    expect(human.stdout).toContain("varlatch scan: 6 file(s) look like copies of secrets (5 not ignored by Git)");
    expect(human.stdout).toContain("may already be committed (git log --all -- <file>)");
    expect(human.stdout).toContain("varlatch import <file> --delete-source");
    expect(human.stdout).toContain("varlatch values set <ITEM> --from-file <file>");
    expect(human.stderr).toBe("");

    // Assisted mode, by a coding agent's marker and by the option, changes nothing.
    const marker = await run(process.execPath, [bundle, "scan", "--find-files"], top, { CLAUDECODE: "1" });
    const option = await run(process.execPath, [bundle, "--assisted", "scan", "--find-files"], top, { VARLATCH_ASSISTED: "0" });
    for (const assisted of [marker, option]) {
      expect(assisted.code, assisted.stderr).toBe(1);
      expect(assisted.stdout).toBe(human.stdout);
      expect(assisted.stderr).toBe("");
    }
    expect(requests).toEqual([]);

    // Nothing to find: exit 0.
    const clean = join(dir, `clean-${repoCount}`);
    mkdirSync(clean);
    writeFileSync(join(clean, ".env.schema"), "# @required\nAPI_KEY=\n");
    const none = await run(process.execPath, [bundle, "scan", "--find-files", clean], top, { VARLATCH_ASSISTED: "0" });
    expect(none.code, none.stderr).toBe(0);
    expect(none.stdout).toMatch(/^varlatch scan: no file looks like a copy of a secret; 1 entries checked by name, without reading their contents\.\n$/);
  });

  it("refuses the value scan's options, more than one directory, and a file", async () => {
    const { top } = copiesTree();
    chmodSync(join(top, "locked.pem"), 0o600);
    for (const args of [
      ["--find-files", "--staged"],
      ["--find-files", "a", "b"],
      ["--find-files", ".", "-e", "production"],
      ["--find-files", "--install-hook"],
    ]) {
      const r = await run(process.execPath, [bundle, "scan", ...args], top, { VARLATCH_ASSISTED: "0" });
      expect(r.code, args.join(" ")).toBe(1);
      expect(r.stderr).toContain("Usage: varlatch scan");
      expect(r.stdout).toBe("");
    }
    const file = await run(process.execPath, [bundle, "scan", "--find-files", ".env"], top, { VARLATCH_ASSISTED: "0" });
    expect(file.code).toBe(1);
    expect(file.stderr).toContain("--find-files takes a directory; .env is not one");
    expect(requests).toEqual([]);
  });
});

describe("varlatch scan --find-files uses Git as little as possible (one check-ignore --no-index)", () => {
  /**
   * A repository holding `.env` as a FIFO: any process that opens it for
   * reading blocks, so a Git that reads it never answers. `config/.env.local`
   * is the matched file whose state is asked.
   */
  function fifoRepo(gitignore = ""): string {
    const top = join(dir, `fifo-${++repoCount}`);
    mkdirSync(top);
    git(top, "init", "-q", "-b", "main");
    const made = spawnSync("mkfifo", [join(top, ".env")]);
    if (made.status !== 0) throw new Error(`mkfifo: ${made.stderr}`);
    mkdirSync(join(top, "config"));
    writeFileSync(join(top, "config", ".env.local"), "CANARY\n");
    if (gitignore) writeFileSync(join(top, ".gitignore"), gitignore);
    return top;
  }

  function appendConfig(top: string, text: string | Buffer) {
    writeFileSync(join(top, ".git", "config"), Buffer.concat([readFileSync(join(top, ".git", "config")), Buffer.from(text)]));
  }

  async function findFiles(cwd: string, extraEnv: Record<string, string | undefined> = {}) {
    const started = Date.now();
    const r = await run(process.execPath, [bundle, "scan", "--find-files", "--json"], cwd, { VARLATCH_ASSISTED: "0", ...extraEnv });
    return { ...r, ms: Date.now() - started, report: r.stdout ? JSON.parse(r.stdout) : null };
  }

  /** The state of config/.env.local, and how long the search took. */
  async function stateOf(cwd: string, extraEnv: Record<string, string | undefined> = {}) {
    const r = await findFiles(cwd, extraEnv);
    const file = r.report?.files.find((f: { path: string }) => f.path.endsWith(".env.local"));
    return { ms: r.ms, git: file?.git, gitError: file?.gitError as string | undefined, stderr: r.stderr };
  }

  it("does not run Git for a repository with anything unusual, and says why", async () => {
    const cases: [string, (top: string) => void, string][] = [
      ["include.path", (top) => appendConfig(top, "[include]\n\tpath = ../.env\n"), "includes other files, which Git would read"],
      ["includeIf", (top) => appendConfig(top, '[includeIf "gitdir:/"]\n\tpath = ../.env\n'), "includes other files"],
      ["an include path that is not UTF-8", (top) => appendConfig(top, Buffer.concat([Buffer.from("[include]\n\tpath = ../"), Buffer.from([0xfe]), Buffer.from(".env\n")])), "includes other files"],
      ["core.excludesFile named like a copy", (top) => appendConfig(top, `[core]\n\texcludesFile = ${join(top, ".env")}\n`), "has the name of a secret copy"],
      [
        "core.excludesFile linked to a copy under another name",
        (top) => {
          symlinkSync(join(top, ".env"), join(top, "ignore-list"));
          appendConfig(top, `[core]\n\texcludesFile = ${join(top, "ignore-list")}\n`);
        },
        "has the name of a secret copy",
      ],
      [
        "core.excludesFile that is not UTF-8",
        (top) => appendConfig(top, Buffer.concat([Buffer.from(`[core]\n\texcludesFile = ${top}/`), Buffer.from([0xfe]), Buffer.from("ignore\n")])),
        "sets a core.excludesFile that is not UTF-8",
      ],
      ["a relative core.excludesFile", (top) => appendConfig(top, "[core]\n\texcludesFile = ignore-list\n"), "is not an absolute path"],
      ["core.worktree", (top) => appendConfig(top, `[core]\n\tworktree = ${top}\n`), "sets core.worktree"],
      [
        "a linked info/exclude",
        (top) => {
          rmSync(join(top, ".git", "info", "exclude"), { force: true });
          symlinkSync(join(top, ".env"), join(top, ".git", "info", "exclude"));
        },
        "info/exclude is a symbolic link",
      ],
      [
        "a hard-linked info/exclude",
        (top) => {
          writeFileSync(join(top, "other"), "# not a copy\n");
          rmSync(join(top, ".git", "info", "exclude"), { force: true });
          spawnSync("ln", [join(top, "other"), join(top, ".git", "info", "exclude")]);
        },
        "has another name (a hard link)",
      ],
      [
        "a linked config",
        (top) => {
          rmSync(join(top, ".git", "config"));
          symlinkSync(join(top, ".env"), join(top, ".git", "config"));
        },
        ".git/config is a symbolic link",
      ],
      ["commondir linked to .env", (top) => symlinkSync("../.env", join(top, ".git", "commondir")), ".git/commondir is a symbolic link"],
      [
        "objects/info/alternates linked to .env",
        (top) => {
          mkdirSync(join(top, ".git", "objects", "info"), { recursive: true });
          symlinkSync(join(top, ".env"), join(top, ".git", "objects", "info", "alternates"));
        },
        "uses another object store",
      ],
    ];
    for (const [label, setup, reason] of cases) {
      const top = fifoRepo();
      setup(top);
      const r = await stateOf(top);
      expect(r.git, `${label}: ${r.stderr}`).toBe("unknown");
      expect(r.gitError, label).toContain(reason);
      expect(r.ms, label).toBeLessThan(10_000);
    }
  });

  it("gives Git none of the caller's GIT_ variables, and reads no index", async () => {
    const top = fifoRepo("*.local\n");
    // The usual answer first.
    expect((await stateOf(top)).git).toBe("ignored");

    // An object store elsewhere whose alternates file is a link to the FIFO.
    const external = join(dir, `objects-${repoCount}`);
    mkdirSync(join(external, "info"), { recursive: true });
    symlinkSync(join(top, ".env"), join(external, "info", "alternates"));
    const envs: Record<string, string>[] = [
      { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "include.path", GIT_CONFIG_VALUE_0: join(top, ".env") },
      { GIT_CONFIG_PARAMETERS: `'include.path'='${join(top, ".env")}'` },
      { GIT_OBJECT_DIRECTORY: external },
      { GIT_ALTERNATE_OBJECT_DIRECTORIES: external },
      { GIT_INDEX_FILE: join(top, ".env") },
      { GIT_DIR: join(top, ".env") },
    ];
    for (const extra of envs) {
      const r = await stateOf(top, extra);
      expect(r.git, `${JSON.stringify(extra)}: ${r.stderr}`).toBe("ignored");
      expect(r.ms).toBeLessThan(10_000);
    }

    // A split index whose shared index is a link to the FIFO, and an index that is one: neither is read.
    git(top, "add", ".gitignore");
    git(top, "update-index", "--split-index");
    const shared = readdirSync(join(top, ".git")).filter((n) => n.startsWith("sharedindex."));
    expect(shared.length).toBeGreaterThan(0);
    for (const n of shared) {
      rmSync(join(top, ".git", n));
      symlinkSync(join(top, ".env"), join(top, ".git", n));
    }
    let r = await stateOf(top);
    expect([r.git, r.ms < 10_000]).toEqual(["ignored", true]);
    rmSync(join(top, ".git", "index"));
    symlinkSync(join(top, ".env"), join(top, ".git", "index"));
    r = await stateOf(top);
    expect([r.git, r.ms < 10_000]).toEqual(["ignored", true]);
  });

  it("reads only core.excludesFile from the global configuration, and never gives it to Git", async () => {
    const top = fifoRepo("*.local\n");
    writeFileSync(join(top, "config", ".env.other"), "CANARY\n");
    const globalDir = join(dir, `global-${repoCount}`);
    mkdirSync(globalDir);
    const gitconfig = join(globalDir, "gitconfig");
    const other = async (extraEnv: Record<string, string>) => {
      const r = await findFiles(top, extraEnv);
      expect(r.ms).toBeLessThan(10_000);
      return Object.fromEntries(r.report.files.map((f: { path: string; git: string; gitError?: string }) => [f.path, [f.git, f.gitError]]));
    };

    // Its excludes file is used.
    writeFileSync(join(globalDir, "ignore"), "*.other\n");
    writeFileSync(gitconfig, `[core]\n\texcludesFile = ${join(globalDir, "ignore")}\n`);
    expect(await other({ GIT_CONFIG_GLOBAL: gitconfig })).toEqual({
      "config/.env.local": ["ignored", undefined],
      "config/.env.other": ["ignored", undefined],
    });

    // Includes in it are not read, by Git or here, and one could replace the excludes file: every state is unknown.
    writeFileSync(join(globalDir, "other.cfg"), `[core]\n\texcludesFile = ${join(globalDir, "empty")}\n`);
    writeFileSync(gitconfig, `[core]\n\texcludesFile = ${join(globalDir, "ignore")}\n[include]\n\tpath = ${join(globalDir, "other.cfg")}\n`);
    const includes = expect.stringContaining("includes other files, which are not read");
    expect(await other({ GIT_CONFIG_GLOBAL: gitconfig })).toEqual({
      "config/.env.local": ["unknown", includes],
      "config/.env.other": ["unknown", includes],
    });
    writeFileSync(gitconfig, `[include]\n\tpath = ${join(top, ".env")}\n`);
    expect(await other({ GIT_CONFIG_GLOBAL: gitconfig })).toEqual({
      "config/.env.local": ["unknown", includes],
      "config/.env.other": ["unknown", includes],
    });

    // A global configuration file that is a link to a copy is not read at all.
    symlinkSync(join(top, ".env"), join(globalDir, "linked-gitconfig"));
    const linked = await other({ GIT_CONFIG_GLOBAL: join(globalDir, "linked-gitconfig") });
    expect(linked["config/.env.local"]).toEqual(["unknown", expect.stringContaining("has the name of a secret copy")]);
  });

  it("reads ~/.gitconfig after the XDG file, as Git does, so ~/.gitconfig wins", async () => {
    const home = join(dir, `home-${++repoCount}`);
    mkdirSync(join(home, ".config", "git"), { recursive: true });
    writeFileSync(join(home, "xdg-ignore"), "*.key\n");
    writeFileSync(join(home, "empty-ignore"), "");
    writeFileSync(join(home, ".config", "git", "config"), `[core]\n\texcludesFile = ${join(home, "xdg-ignore")}\n`);
    const top = join(home, "repo");
    mkdirSync(top);
    git(top, "init", "-q", "-b", "main");
    writeFileSync(join(top, "test.key"), "CANARY\n");
    const state = async () => {
      const r = await findFiles(top, { HOME: home, GIT_CONFIG_GLOBAL: undefined, XDG_CONFIG_HOME: undefined });
      return r.report.files.map((f: { path: string; git: string }) => [f.path, f.git]);
    };
    expect(await state()).toEqual([["test.key", "ignored"]]);
    writeFileSync(join(home, ".gitconfig"), `[core]\n\texcludesFile = ${join(home, "empty-ignore")}\n`);
    expect(await state()).toEqual([["test.key", "not-ignored"]]);
  });

  it("does not run Git when a .gitignore that applies is a hard link, a link, or not a regular file", async () => {
    const cases: [string, (top: string) => void, string, string][] = [
      [
        "a .gitignore hard-linked to a .env holding *.key",
        (top) => {
          writeFileSync(join(top, "config", ".env"), "*.key\n");
          spawnSync("ln", [join(top, "config", ".env"), join(top, "config", ".gitignore")]);
        },
        ".",
        "has another name (a hard link)",
      ],
      ["a FIFO .gitignore", (top) => spawnSync("mkfifo", [join(top, "config", ".gitignore")]), ".", "is not a regular file"],
      ["a linked .gitignore", (top) => symlinkSync(join(top, ".env"), join(top, "config", ".gitignore")), ".", "is a symbolic link"],
      [
        "a FIFO .gitignore above the directory searched",
        (top) => spawnSync("mkfifo", [join(top, ".gitignore")]),
        "config",
        "is not a regular file",
      ],
    ];
    for (const [label, setup, sub, reason] of cases) {
      const top = fifoRepo();
      setup(top);
      const r = await stateOf(join(top, sub));
      expect(r.git, `${label}: ${r.stderr}`).toBe("unknown");
      expect(r.gitError, label).toContain(reason);
      expect(r.ms, label).toBeLessThan(10_000);
    }
  });

  it("never shows Git's own messages, only that it refused or failed and its exit status", async () => {
    const top = fifoRepo();
    appendConfig(top, "[core]\n\trepositoryformatversion = 99\n");
    const r = await stateOf(top);
    expect(r).toMatchObject({ git: "unknown", gitError: "Git refused or failed (exit status 128)", stderr: "" });
  });

  it("answers for a linked worktree, and keeps names that are not UTF-8 apart", async () => {
    const top = join(dir, `bytes-${++repoCount}`);
    mkdirSync(top);
    git(top, "init", "-q", "-b", "main");
    const fe = Buffer.from([0xfe, 0x2e, 0x6b, 0x65, 0x79]);
    const ff = Buffer.from([0xff, 0x2e, 0x6b, 0x65, 0x79]);
    const topBytes = Buffer.from(top);
    writeFileSync(Buffer.concat([topBytes, Buffer.from("/"), fe]), "CANARY\n");
    writeFileSync(Buffer.concat([topBytes, Buffer.from("/"), ff]), "CANARY\n");
    writeFileSync(join(top, ".env.\u009b31m"), "CANARY\n");
    // Only the 0xfe name is ignored, by its exact bytes.
    writeFileSync(join(top, ".gitignore"), Buffer.concat([Buffer.from("/"), fe, Buffer.from("\n")]));

    const human = await run(process.execPath, [bundle, "scan", "--find-files"], top, { VARLATCH_ASSISTED: "0" });
    expect(human.code, human.stderr).toBe(1);
    expect(human.stdout).toContain('  "\\xfe.key": ignored by Git\n');
    expect(human.stdout).toContain('  "\\xff.key": not ignored by Git');
    expect(human.stdout).toContain('  ".env.\\u009b31m": not ignored by Git');
    expect(human.stdout).not.toMatch(/[\u007f-\u009f]/);

    const json = await findFiles(top);
    expect(json.stdout).not.toMatch(/[\u007f-\u009f]/);
    const byBytes = Object.fromEntries(
      json.report.files.map((f: { path: string; pathBase64?: string; git: string }) => [f.pathBase64 ?? Buffer.from(f.path).toString("base64"), f.git]),
    );
    expect(byBytes).toEqual({
      [fe.toString("base64")]: "ignored",
      [ff.toString("base64")]: "not-ignored",
      [Buffer.from(".env.\u009b31m").toString("base64")]: "not-ignored",
    });

    // A linked worktree: its repository is found through the .git file and commondir.
    git(top, "add", ".gitignore");
    git(top, "commit", "-q", "-m", "init");
    const linked = join(dir, `linked-${repoCount}`);
    git(top, "worktree", "add", "-q", linked);
    writeFileSync(join(linked, ".gitignore"), ".env\n");
    writeFileSync(join(linked, ".env"), "CANARY\n");
    const wt = await findFiles(linked);
    expect(wt.report.files.find((f: { path: string }) => f.path === ".env"), wt.stderr).toMatchObject({ git: "ignored" });
  });
});
