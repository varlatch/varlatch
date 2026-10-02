// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";

/**
 * `varlatch login --token-stdin` (ADR-0043 Decision 2): the credential
 * comes from a pipe, is verified against the server like --token, is stored,
 * and never appears in the CLI's output.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-token-stdin-"));
const bundle = join(dir, "varlatch.cjs");
const TOKEN = "vlt_stdin-canary-credential";
let server: http.Server;
let origin = "";
let seen: string[] = [];

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
  server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push(req.headers.authorization ?? "");
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      };
      if (req.headers.authorization !== `Bearer ${TOKEN}`) {
        return json(401, { error: { code: "UNAUTHENTICATED", message: "unauthenticated", requestId: "req_1" } });
      }
      if (req.url === "/v1/meta") return json(200, { serverVersion: "0.14.0", apiMajor: 1 });
      if (req.url === "/v1/organizations") return json(200, { items: [] });
      json(404, { error: { code: "NOT_FOUND", message: "not found", requestId: "req_2" } });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
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

function cli(args: string[], stdin: string, config: string): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: config },
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

let n = 0;
const configDir = () => join(dir, `config-${n++}`);
const stored = (config: string) =>
  (JSON.parse(readFileSync(join(config, "varlatch", "credentials.json"), "utf8")) as { servers: Record<string, { token: string }> }).servers;

describe("login --token-stdin", () => {
  it("reads the credential from the pipe, verifies it, stores it, and never prints it", async () => {
    for (const piped of [TOKEN, `${TOKEN}\n`, `${TOKEN}\r\n`]) {
      seen = [];
      const config = configDir();
      const r = await cli(["login", "--server", origin, "--token-stdin"], piped, config);
      expect(r.code, JSON.stringify(piped)).toBe(0);
      expect(r.stdout).toMatch(/Logged in to/);
      expect(`${r.stdout}${r.stderr}`).not.toContain(TOKEN);
      expect(seen.every((a) => a === `Bearer ${TOKEN}`)).toBe(true);
      expect(stored(config)[origin]?.token).toBe(TOKEN);
    }
  });

  it("control: a credential the server rejects is not stored", async () => {
    const config = configDir();
    const r = await cli(["login", "--server", origin, "--token-stdin"], "vlt_wrong_credential", config);
    expect(r.code).toBe(EXIT.denied);
    expect(existsSync(join(config, "varlatch", "credentials.json"))).toBe(false);
  });

  it("refuses an empty or multi-part credential, and a second source, storing nothing", async () => {
    const cases: [string[], string, RegExp][] = [
      [["--token-stdin"], "", /read no credential/],
      [["--token-stdin"], "\n", /read no credential/],
      [["--token-stdin"], `${TOKEN} extra`, /contains whitespace/],
      [["--token-stdin"], `${TOKEN}\n${TOKEN}\n`, /contains whitespace/],
      [["--token-stdin", "--token", TOKEN], "", /not more than one/],
      [["--token-stdin", "--oidc"], TOKEN, /not more than one/],
    ];
    for (const [extra, piped, message] of cases) {
      const config = configDir();
      const r = await cli(["login", "--server", origin, ...extra], piped, config);
      expect(r.code, extra.join(" ")).toBe(EXIT.usage);
      expect(r.stderr, extra.join(" ")).toMatch(message);
      expect(existsSync(join(config, "varlatch", "credentials.json")), extra.join(" ")).toBe(false);
    }
  });
});
