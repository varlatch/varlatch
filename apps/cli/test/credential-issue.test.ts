// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";

/**
 * `varlatch credential issue` end to end against a local server: the token
 * goes only to the --out file (new, mode 0600, in an existing directory),
 * never to stdout or stderr; an existing file or a server without the
 * identity.credentials.issue capability is refused before anything is issued.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-credential-issue-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const CREDS = "/v1/organizations/acme/identities/idn_svc/credentials";
// What the server returns as the token: it must appear in the file and nowhere else.
const ISSUED = "vlt_svc_issued-canary-81";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let requests: { method: string; url: string; body: unknown }[] = [];

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    requests.push({ method: req.method ?? "", url, body });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.15.2", capabilities });
    if (url === CREDS && req.method === "POST") {
      return json(201, {
        id: "crd_new",
        kind: "service",
        name: body?.name,
        token: ISSUED,
        expiresAt: body?.ttlSeconds ? "2026-10-09T12:00:00.000Z" : null,
        maxUses: body?.maxUses ?? null,
      });
    }
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Not found", requestId: "req_1" } });
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
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  // No default environment: issuing a credential needs none.
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["identity.lifecycle", "identity.credentials.issue"];
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** The CLI's result; whatever happened, the token never reaches its output. */
async function cli(args: string[], env: Record<string, string> = {}): Promise<Result> {
  const r = await run(args, env);
  expect(r.stdout + r.stderr).not.toContain("canary");
  return r;
}

function run(args: string[], env: Record<string, string>): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

let n = 0;
/** A path in the repository that does not exist yet. */
function fresh(): string {
  return join(repo, `token-${++n}`);
}
const posts = () => requests.filter((r) => r.method === "POST");

describe("varlatch credential issue", () => {
  it("writes the token only to a new 0600 file and prints the credential's id, name, and expiry", async () => {
    const out = fresh();
    const r = await cli(["credential", "issue", "idn_svc", "--name", "backup job", "--ttl", "86400", "--max-uses", "5", "--out", out]);
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(readFileSync(out, "utf8")).toBe(`${ISSUED}\n`);
    if (process.platform !== "win32") expect(statSync(out).mode & 0o777).toBe(0o600);
    expect(r.stdout).toContain("crd_new");
    expect(r.stdout).toContain("backup job");
    expect(r.stdout).toContain("expires 2026-10-09T12:00:00.000Z");
    expect(r.stdout).toContain("5 uses");
    expect(r.stdout).toContain(out);
    expect(posts()).toEqual([{ method: "POST", url: CREDS, body: { name: "backup job", ttlSeconds: 86400, maxUses: 5 } }]);
  });

  it("--json prints one document naming the credential, without the token", async () => {
    const out = fresh();
    const r = await cli(["credential", "issue", "idn_svc", "--name", "metrics", "--out", out, "--json"]);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({
      version: 1,
      identity: "idn_svc",
      credential: { id: "crd_new", kind: "service", name: "metrics", expiresAt: null, maxUses: null },
      out,
    });
    expect(posts()[0]?.body).toEqual({ name: "metrics" });
    expect(readFileSync(out, "utf8")).toBe(`${ISSUED}\n`);
  });

  it("works in assisted mode, and says the file is a credential", async () => {
    const out = fresh();
    const r = await cli(["--assisted", "credential", "issue", "idn_svc", "--name", "agent-driven", "--out", out]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("do not print or read it");
    expect(readFileSync(out, "utf8")).toBe(`${ISSUED}\n`);
  });

  it("refuses an existing file, leaves it alone, and issues nothing", async () => {
    const out = fresh();
    writeFileSync(out, "already here\n");
    const r = await cli(["credential", "issue", "idn_svc", "--name", "x", "--out", out]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("already exists");
    expect(r.stderr).toContain("Nothing was issued");
    expect(readFileSync(out, "utf8")).toBe("already here\n");
    expect(requests).toEqual([]);
  });

  it("refuses a directory that does not exist, and issues nothing", async () => {
    const out = join(repo, "no-such-dir", "token");
    const r = await cli(["credential", "issue", "idn_svc", "--name", "x", "--out", out]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("does not exist");
    expect(existsSync(join(repo, "no-such-dir"))).toBe(false);
    expect(requests).toEqual([]);
  });

  it("refuses a server without the capability, before issuing or creating the file", async () => {
    capabilities = ["identity.lifecycle"];
    const out = fresh();
    const r = await cli(["credential", "issue", "idn_svc", "--name", "x", "--out", out]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("identity.credentials.issue");
    expect(r.stderr).toContain("0.15.2");
    expect(r.stderr).toContain("Nothing was issued");
    expect(existsSync(out)).toBe(false);
    expect(requests.map((q) => `${q.method} ${q.url}`)).toEqual(["GET /v1/meta"]);
  });

  it("an identity that cannot hold a service credential: a clear error, and no file left behind", async () => {
    const out = fresh();
    const r = await cli(["credential", "issue", "idn_agent", "--name", "x", "--out", out]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("no machine identity idn_agent");
    expect(existsSync(out)).toBe(false);
  });

  it.each([
    ["no identity", ["--name", "x", "--out", "f"]],
    ["no --name", ["idn_svc", "--out", "f"]],
    ["an empty --name", ["idn_svc", "--name", "", "--out", "f"]],
    ["no --out", ["idn_svc", "--name", "x"]],
    ["--out to standard output", ["idn_svc", "--name", "x", "--out", "-"]],
    ["a --ttl that is not whole seconds", ["idn_svc", "--name", "x", "--ttl", "1.5", "--out", "f"]],
    ["a --ttl beyond the server's limit", ["idn_svc", "--name", "x", "--ttl", "315360001", "--out", "f"]],
    ["a --max-uses of 0", ["idn_svc", "--name", "x", "--max-uses", "0", "--out", "f"]],
    ["an unknown option", ["idn_svc", "--name", "x", "--out", "f", "--force"]],
    ["--out given twice", ["idn_svc", "--name", "x", "--out", "f", "--out", "g"]],
  ])("%s: 64 before any request or file", async (_name, rest) => {
    const r = await cli(["credential", "issue", ...rest]);
    expect(r.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
    expect(existsSync(join(repo, "f"))).toBe(false);
  });

  it("is in the usage, and in `credential --help`", async () => {
    const r = await cli(["credential", "--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/varlatch credential issue <identity-id> --name <name> .*--out <file>/);
    expect(requests).toEqual([]);
  });
});
