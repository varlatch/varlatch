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
  extraEnv: Record<string, string> = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, env: { ...env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
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
   * tracked copies, a nested repository, links, a template, an unreadable
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
    { path: "certs/server.key", kind: "key", symlink: false, git: "tracked" },
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
    expect(human.stdout).toContain("  certs/server.key: tracked by Git, so it is in the repository's history\n");
    expect(human.stdout).toContain("  .env.link: a symbolic link, not followed; not ignored by Git, so a commit could add it\n");
    expect(human.stdout).toContain("  vendor/tool/.env.production: not ignored by Git");
    expect(human.stdout).not.toContain(".env.example");
    expect(human.stdout).not.toContain("node_modules");
    expect(human.stdout).not.toContain("linked-dir");
    expect(human.stdout).toContain("varlatch scan: 6 file(s) look like copies of secrets (1 tracked by Git, 4 not ignored)");
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
    expect(none.stdout).toMatch(/^varlatch scan: no file looks like a copy of a secret; 1 entries checked by name\. No file was opened\.\n$/);
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
