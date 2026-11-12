// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { installSh } from "../src/http/cliDownload.js";

/**
 * install.sh as a person runs it (ADR-0058 Decision 3, Acceptance): against
 * a loopback http: server, with its own HOME and a PATH built for each
 * case, and without a terminal (setsid), so a question it would ask must
 * stop it instead. Each case checks what was installed, not only the exit.
 */

const VERSION = "0.99.0";
const CLI = Buffer.from(`console.log(${JSON.stringify(`varlatch ${VERSION} (migration 1)`)})\n`);
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

const root = mkdtempSync(join(tmpdir(), "varlatch-install-sh-"));
let server: Server;
let origin: string;
let serve: { status: number; body: Buffer; location?: string } = { status: 200, body: CLI };
let redirected = 0;

// The tools the script uses, linked one by one: a PATH without node, or
// with another node first, is then exact. Links are only ever executed.
const tools = join(root, "tools");
const TOOLS = ["setsid", "sh", "curl", "mktemp", "cut", "cp", "chmod", "mv", "mkdir", "rm", "grep", "readlink", "sha256sum", "cat"];

beforeAll(async () => {
  mkdirSync(tools);
  for (const tool of TOOLS) {
    const found = spawnSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).stdout.trim();
    if (!found) throw new Error(`${tool} is needed for this test`);
    symlinkSync(found, join(tools, tool));
  }
  server = createServer((req, res) => {
    if (req.url === "/cli/varlatch.cjs") {
      res.writeHead(serve.status, serve.location ? { Location: serve.location } : {});
      res.end(serve.body);
    } else if (req.url === "/elsewhere.cjs") {
      redirected++;
      res.writeHead(200);
      res.end(CLI);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(root, { recursive: true, force: true });
});

let n = 0;
function home(): string {
  const dir = join(root, `home${n++}`);
  mkdirSync(dir);
  return dir;
}

/**
 * Runs the script as `curl ... | sh` would, without a controlling terminal.
 * Asynchronously: the server above answers from this same process.
 */
function install(opts: { home: string; path: string[]; sha256?: string }): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const script = installSh({ file: CLI, sha256: opts.sha256 ?? sha(CLI), version: VERSION, origin, loopbackHttp: true });
  return new Promise((resolve, reject) => {
    // By its full path: the child's PATH is the case's, not this process's.
    const child = spawn(join(tools, "setsid"), ["-w", join(tools, "sh")], { env: { HOME: opts.home, PATH: opts.path.join(":") } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(script);
  });
}

const nodeDir = dirname(process.execPath);
const target = (h: string) => join(h, ".local", "bin", "varlatch");

describe("install.sh", () => {
  it("installs the checked file for the current user, says the PATH line to add, and names the next step", async () => {
    serve = { status: 200, body: CLI };
    const h = home();
    const r = await install({ home: h, path: [nodeDir, tools] });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(readFileSync(target(h))).toEqual(CLI);
    expect(r.stdout).toContain(`Installed varlatch ${VERSION} at ${target(h)}.`);
    expect(r.stdout).toContain(`${join(h, ".local", "bin")} is not on your PATH.`);
    expect(r.stdout).toContain(`Next: varlatch login --server ${origin}`);

    const again = await install({ home: h, path: [nodeDir, tools, join(h, ".local", "bin")] });
    expect(again.code).toBe(0);
    expect(again.stdout).toContain(`varlatch ${VERSION} is already installed at ${target(h)}.`);
    expect(again.stdout).not.toContain("not on your PATH");
  });

  it("never replaces a different copy without an answer from a terminal", async () => {
    serve = { status: 200, body: CLI };
    const h = home();
    mkdirSync(dirname(target(h)), { recursive: true });
    writeFileSync(target(h), "console.log('varlatch 0.1.0 (migration 1)')\n");
    const r = await install({ home: h, path: [nodeDir, tools] });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(`${target(h)} exists: varlatch 0.1.0 (migration 1).`);
    expect(r.stderr).toContain("replacing it needs your answer in a terminal; nothing was installed");
    expect(readFileSync(target(h), "utf8")).toContain("0.1.0");
  });

  it("installs nothing when the download does not match its SHA-256", async () => {
    serve = { status: 200, body: Buffer.from("console.log('something else')\n") };
    const h = home();
    const r = await install({ home: h, path: [nodeDir, tools] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("the download does not match its SHA-256; nothing was installed");
    expect(existsSync(target(h))).toBe(false);
  });

  it("follows no redirect over loopback http:", async () => {
    serve = { status: 302, body: Buffer.alloc(0), location: "http://example.com/varlatch.cjs" };
    const h = home();
    const r = await install({ home: h, path: [nodeDir, tools] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`could not download ${origin}/cli/varlatch.cjs (HTTP 302; a redirect is never followed)`);
    expect(existsSync(target(h))).toBe(false);
  });

  it("ignores ~/.curlrc, so a redirect stays refused even when it says to follow them", async () => {
    serve = { status: 302, body: Buffer.alloc(0), location: `${origin}/elsewhere.cjs` };
    redirected = 0;
    const h = home();
    writeFileSync(join(h, ".curlrc"), "location\ninsecure\n");
    const r = await install({ home: h, path: [nodeDir, tools] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("(HTTP 302; a redirect is never followed)");
    expect(redirected).toBe(0);
    expect(existsSync(target(h))).toBe(false);
  });

  it("finds a Homebrew copy in a PATH directory with a space in its name", async () => {
    serve = { status: 200, body: CLI };
    const brew = join(root, "Brew Dir");
    mkdirSync(brew, { recursive: true });
    writeFileSync(join(brew, "varlatch"), '#!/bin/bash\necho "varlatch: installed with Homebrew; update with: brew upgrade varlatch" >&2\n');
    chmodSync(join(brew, "varlatch"), 0o755);
    const h = home();
    const r = await install({ home: h, path: [nodeDir, tools, brew] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`varlatch is installed with Homebrew at ${join(brew, "varlatch")}`);
    expect(existsSync(target(h))).toBe(false);
  });

  it("installs nothing when the file runs as another version", async () => {
    const other = Buffer.from("console.log('varlatch 0.98.0 (migration 1)')\n");
    serve = { status: 200, body: other };
    const h = home();
    const r = await install({ home: h, path: [nodeDir, tools], sha256: sha(other) });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("reports 'varlatch 0.98.0 (migration 1)', not 0.99.0; nothing was installed");
    expect(existsSync(target(h))).toBe(false);
  });

  it("stops without Node.js, or with one older than 22, and never installs it", async () => {
    serve = { status: 200, body: CLI };
    const none = await install({ home: home(), path: [tools] });
    expect(none.code).toBe(1);
    expect(none.stderr).toContain("needs Node.js 22, 24 or 26");
    const old = join(root, "old-node");
    mkdirSync(old, { recursive: true });
    writeFileSync(join(old, "node"), "#!/bin/sh\ncase \"$1\" in -p) echo 20 ;; *) echo v20.11.0 ;; esac\n");
    chmodSync(join(old, "node"), 0o755);
    const h = home();
    const r = await install({ home: h, path: [old, tools] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("needs Node.js 22 or newer; this is v20.11.0");
    expect(existsSync(target(h))).toBe(false);
  });

  it("leaves a Homebrew copy to Homebrew", async () => {
    serve = { status: 200, body: CLI };
    const brew = join(root, "brew-bin");
    mkdirSync(brew, { recursive: true });
    writeFileSync(join(brew, "varlatch"), '#!/bin/bash\necho "varlatch: installed with Homebrew; update with: brew upgrade varlatch" >&2\n');
    chmodSync(join(brew, "varlatch"), 0o755);
    const h = home();
    const r = await install({ home: h, path: [brew, nodeDir, tools] });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`varlatch is installed with Homebrew at ${join(brew, "varlatch")}; update it with: brew upgrade varlatch`);
    expect(existsSync(target(h))).toBe(false);
  });

  it("says when another copy comes first on PATH", async () => {
    serve = { status: 200, body: CLI };
    const other = join(root, "other-bin");
    mkdirSync(other, { recursive: true });
    writeFileSync(join(other, "varlatch"), "#!/bin/sh\necho other\n");
    chmodSync(join(other, "varlatch"), 0o755);
    const h = home();
    const r = await install({ home: h, path: [other, nodeDir, tools, join(h, ".local", "bin")] });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`Another varlatch comes first on your PATH: ${join(other, "varlatch")}.`);
  });
});
