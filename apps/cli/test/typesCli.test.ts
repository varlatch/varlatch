// SPDX-License-Identifier: Apache-2.0
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ITEMS, revision } from "./fixtures.js";

/**
 * The shipped CLI bundle against a local HTTP server that records every
 * request: `varlatch types` makes exactly one, to fetch the Contract, uses no
 * temporary directory, and its output does not depend on the selected
 * Environment.
 */

const CLI = fileURLToPath(new URL("../dist/varlatch.cjs", import.meta.url));

let server: Server;
let origin: string;
let repo: string;
let served = revision(ITEMS);
const requests: string[] = [];

beforeAll(async () => {
  if (!existsSync(CLI)) throw new Error("the CLI bundle is not built: run pnpm --filter @varlatch/cli build");
  server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url} ${req.headers.authorization ?? "(no credential)"}`);
    if (req.method === "GET" && req.url === "/v1/organizations/acme/projects/api/contract") {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(served));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" }).end(
      JSON.stringify({ error: { code: "RESOURCE_NOT_FOUND", message: "not here", requestId: "r" } }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  origin = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
  repo = mkdtempSync(join(tmpdir(), "varlatch-types-cli-"));
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "api"\nserver = "${origin}"\n`);
  mkdirSync(join(repo, "config"));
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(repo, { recursive: true, force: true });
});

function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      {
        cwd: repo,
        env: {
          PATH: process.env.PATH,
          HOME: repo,
          VARLATCH_CONFIG_DIR: join(repo, ".config"),
          VARLATCH_TOKEN: "vlt_test_token",
          // No shared temporary directory: one that does not exist must not matter.
          TMPDIR: join(repo, "no-such-directory"),
        },
      },
      (error, stdout, stderr) => resolve({ code: error ? Number(error.code ?? 1) : 0, stdout, stderr }),
    );
  });
}

/**
 * Each test spawns the built CLI (a new Node process running the whole
 * bundle) one to three times. That takes about 0.2 s each on an idle
 * machine but several seconds on a loaded CI runner, as the 5 s default
 * already proved too short for a spawn-heavy test (#73). A targeted limit
 * per spawn, here only: the CLI-wide default stays 5 s for unit tests.
 */
const PER_SPAWN_MS = 10_000;

describe("varlatch types, end to end", () => {
  it("makes one request, for the Contract, and writes the same file for every Environment", async () => {
    const out = join(repo, "config", "varlatch.ts");
    requests.length = 0;
    const first = await cli(["types", "--out", "config/varlatch.ts", "-e", "development"]);
    expect(first.stderr).toBe("");
    expect(first.code).toBe(0);
    expect(requests).toEqual(["GET /v1/organizations/acme/projects/api/contract Bearer vlt_test_token"]);
    const bytes = readFileSync(out);

    const past = new Date("2026-01-01T00:00:00Z");
    utimesSync(out, past, past);
    requests.length = 0;
    const other = await cli(["types", "--out", "config/varlatch.ts", "--environment", "production"]);
    expect(other.code).toBe(0);
    expect(other.stdout).toContain("left unchanged");
    expect(requests).toHaveLength(1);
    expect(readFileSync(out).equals(bytes)).toBe(true);
    expect(statSync(out).mtime.getTime()).toBe(past.getTime());

    // Without any Environment selected at all.
    expect((await cli(["types", "--out", "config/varlatch.ts", "--check"])).code).toBe(0);
  }, 3 * PER_SPAWN_MS);

  it("--check exits 1 once the Contract changes, and leaves the file alone", async () => {
    const out = join(repo, "config", "check.ts");
    served = revision(ITEMS);
    expect((await cli(["types", "--out", "config/check.ts"])).code).toBe(0);
    const before = readFileSync(out);
    served = revision(ITEMS.map((i) => (i.name === "DEBUG" ? { ...i, type: "string" } : i)));
    const stale = await cli(["types", "--out", "config/check.ts", "--check"]);
    expect(stale.code).toBe(1);
    expect(stale.stderr).toContain("is stale");
    expect(readFileSync(out).equals(before)).toBe(true);
  }, 2 * PER_SPAWN_MS);

  it("refuses a version 1 Contract with the fix, and writes nothing", async () => {
    served = revision(ITEMS, { semanticsVersion: 1 });
    const result = await cli(["types", "--out", "config/v1.ts"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("which defines no conversion");
    expect(existsSync(join(repo, "config", "v1.ts"))).toBe(false);
  }, PER_SPAWN_MS);
});
