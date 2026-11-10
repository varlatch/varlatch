// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The expiry warning for a VARLATCH_TOKEN credential (ADR-0054 Decision 8),
 * end to end: the CLI, bundled from this checkout's source, runs against a
 * local fake server that names the credential's expiry in
 * Varlatch-Credential-Expires on every response. The warning goes to stderr
 * once per process, stdout stays byte for byte what it is without it, and
 * `varlatch run` prints it before the command starts (ADR-0032).
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-token-expiry-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const child = join(dir, "child.cjs");
// Relative to the run: the subprocesses compare it with the real clock.
const EXPIRES = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
/** Always in the past, for the "expired" wording. */
const EXPIRED = "2026-01-01T00:00:00.000Z";
let server: http.Server;
let serverUrl = "";
/** The header the fake server sends with every response; null for none. */
let expiresHeader: string | null = null;
let requests = 0;

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = req.url ?? "";
  requests += 1;
  const headers = { "Content-Type": "application/json", ...(expiresHeader ? { "Varlatch-Credential-Expires": expiresHeader } : {}) };
  const json = (body: unknown): void => {
    res.writeHead(200, headers).end(JSON.stringify(body));
  };
  req.resume();
  if (url === "/v1/meta") return json({ serverVersion: "0.20.1", capabilities: ["retrieval.strict"] });
  if (url === "/v1/organizations/acme/projects/web/environments") {
    return json({
      items: [
        { name: "development", tier: "development", kind: "root" },
        { name: "production", tier: "production", kind: "root" },
      ],
      nextCursor: null,
    });
  }
  if (url.endsWith("/environments/development/effective-configuration?include=values")) {
    return json({
      environmentId: "env_1",
      items: [{ name: "PORT", sensitive: false, source: "self", versionId: "ver_2", value: "8080" }],
    });
  }
  if (url.endsWith("/environments/development/disclosures")) return json({ items: [], withheld: [] });
  res.writeHead(404, headers);
  res.end(JSON.stringify({ error: { code: "NOT_FOUND", message: url, requestId: "req_1" } }));
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
  serverUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(
    join(repo, "varlatch.toml"),
    `organization = "acme"\nproject = "web"\nserver = "${serverUrl}"\ndefault_environment = "development"\n`,
  );
  // The command says on stderr that it started, and prints what it got on stdout.
  writeFileSync(child, `process.stderr.write("child started\\n"); process.stdout.write("PORT=" + process.env.PORT + "\\n");`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], env: Record<string, string> = { VARLATCH_TOKEN: "vlt_svc_runner" }): Promise<Result> {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      // Explicit mode for this suite: no coding-agent marker reaches the CLI.
      env: { PATH: process.env.PATH ?? "", HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    proc.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function withHeader(value: string | null, run: () => Promise<Result>): Promise<Result> {
  expiresHeader = value;
  try {
    return await run();
  } finally {
    expiresHeader = null;
  }
}

const warning = (server: string) =>
  `varlatch: credential for ${server} (VARLATCH_TOKEN) expires ${EXPIRES}; issue a new one (\`varlatch credential issue\`) and replace VARLATCH_TOKEN before then`;
const count = (text: string, part: string) => text.split(part).length - 1;

describe("VARLATCH_TOKEN expiry warning", () => {
  it("varlatch run: once on stderr, before the command starts, and stdout unchanged", async () => {
    const args = ["run", "--", process.execPath, child];
    const before = requests;
    const warned = await withHeader(EXPIRES, () => cli(args));
    // Every response named the expiry; the warning came once.
    expect(requests - before).toBeGreaterThanOrEqual(2);
    const plain = await withHeader(null, () => cli(args));
    expect(warned, warned.stderr).toMatchObject({ code: 0 });
    expect(plain.code).toBe(0);
    expect(count(warned.stderr, warning(serverUrl))).toBe(1);
    expect(count(warned.stderr, "(VARLATCH_TOKEN)")).toBe(1);
    expect(warned.stderr.indexOf(warning(serverUrl))).toBeLessThan(warned.stderr.indexOf("child started"));
    expect(warned.stdout).toBe("PORT=8080\n");
    expect(warned.stdout).toBe(plain.stdout);
    expect(plain.stderr).not.toContain("VARLATCH_TOKEN");
  });

  it("varlatch env list: the frozen stdout is unchanged, the warning is on stderr once", async () => {
    const warned = await withHeader(EXPIRES, () => cli(["env", "list"]));
    const plain = await withHeader(null, () => cli(["env", "list"]));
    expect(warned.code).toBe(0);
    expect(warned.stdout).toBe("development  (development, root, selected)\nproduction  (production, root)\n");
    expect(warned.stdout).toBe(plain.stdout);
    expect(warned.stderr).toBe(`${warning(serverUrl)}\n`);
    expect(plain.stderr).toBe("");
  });

  it("is on stderr for a refused request too, and says when the credential already expired", async () => {
    const past = EXPIRED;
    // The fake server answers GET /v1/organizations with 404.
    const refused = await withHeader(past, () => cli(["org", "list"]));
    expect(refused.code).not.toBe(0);
    expect(refused.stderr).toContain(
      `varlatch: credential for ${serverUrl} (VARLATCH_TOKEN) expired ${past}; issue a new one (\`varlatch credential issue\`) and replace VARLATCH_TOKEN\n`,
    );
    expect(refused.stdout).not.toContain("VARLATCH_TOKEN");
  });

  it("leaves the stored credential to its own rule: no header-based warning without VARLATCH_TOKEN", async () => {
    const config = join(dir, "stored-config");
    mkdirSync(config, { recursive: true });
    writeFileSync(join(config, "credentials.json"), JSON.stringify({ servers: { [serverUrl]: { token: "vlt_cli_stored" } } }));
    const stored = await withHeader(EXPIRES, () => cli(["env", "list"], { VARLATCH_CONFIG_DIR: config }));
    expect(stored.code).toBe(0);
    expect(stored.stderr).toBe("");
  });

  it("stays silent inside an agent-safe run, whose agent-run credential ends with the run", async () => {
    const config = join(dir, "agent-config");
    mkdirSync(config, { recursive: true });
    const inRun = await withHeader(EXPIRES, () =>
      cli(["env", "list"], { VARLATCH_TOKEN: "vlt_agr_run", VARLATCH_AGENT_RUN: "run_0123456789abcdef", VARLATCH_CONFIG_DIR: config }),
    );
    expect(inRun.code).toBe(0);
    expect(inRun.stderr).not.toContain("VARLATCH_TOKEN");
  });
});
