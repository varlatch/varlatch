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
 * The CLI prints only checked text from server responses (issue #119), end
 * to end: a server puts credential and value canaries, a line break that
 * would fake an output line, an escape sequence and a bidirectional override
 * into a sign-in's expiry and version, an API error's code, message and
 * request id, and the names of organizations, projects, environments and
 * identities. None of them reaches stdout or stderr unescaped or unmasked;
 * ordinary values print exactly as before.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-server-text-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const config = join(dir, "config");

/** A credential stored for another server: the CLI holds it, so it is masked. */
const STORED = "stored-credential-canary-4f2a9c";
/** The bearer of the requests (VARLATCH_TOKEN), not in a Varlatch token format. */
const BEARER = "bearer-canary-env-token-7d3e";
/** A value the CLI sends with values set. */
const SENT = "sent-value-canary-a81b";
/** The browser sign-in's session bearer, exchanged for the CLI credential. */
const HANDOFF = "handoff-bearer-canary-61c0";
const ISSUED = "vlt_cli_issuedcredentialcanary0123456789abcdefghijk";
const FAKE_LINE = "\nError FAKE_LINE: a line the server forged";
const ESC = "\u001b[31m";
const RLO = "‮";
const EVIL = `${FAKE_LINE}${ESC}${RLO}`;
const REQUEST_ID = "req_0b6c2f1e-3d4a-4c5b-9e8f-7a6b5c4d3e2f";

/** Which answers the server gives: ordinary ones, or ones carrying the canaries. */
let evil = false;

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let body = "";
  req.on("data", (d: Buffer) => (body += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const auth = req.headers.authorization ?? "";
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    const error = (status: number, code: string, message: string, requestId = REQUEST_ID) => json(status, { error: { code, message, requestId } });
    // Browser sign-in: the exchange, then the probe with the issued credential.
    if (req.method === "POST" && url === "/v1/me/credentials/cli" && auth === `Bearer ${HANDOFF}`) {
      return json(201, { id: "cred_1", token: ISSUED, expiresAt: evil ? `${HANDOFF}${EVIL}` : "2026-12-01T00:00:00.000Z" });
    }
    if (url === "/v1/meta") {
      return json(200, evil ? { serverVersion: `0.21.0${EVIL}${STORED}`, apiMajor: `1 ${HANDOFF}`, capabilities: [] } : { serverVersion: "0.21.0", apiMajor: 1, capabilities: [] });
    }
    if (url.startsWith("/v1/organizations/acme/projects/web/environments/development/effective-configuration")) {
      // Every field of an API error: the request's own bearer, a stored credential and a Varlatch token in the
      // message, a forged line and controls; the bearer in the code and the request id too.
      if (evil) return error(403, `PERMISSION_DENIED${ESC}${auth}`, `denied for ${auth} and ${STORED}, token vlt_cli_${"Ab3_-".repeat(9)}${EVIL}`, `req_${BEARER}`);
      return error(403, "PERMISSION_DENIED", "This identity may not read values here");
    }
    if (url === "/v1/organizations") {
      return json(200, { items: [{ id: "org_1", slug: "acme", name: evil ? `Acme${EVIL}` : "Acme" }] });
    }
    if (url === "/v1/organizations/acme/projects") {
      return json(200, { items: [{ slug: evil ? `web${EVIL}` : "web", name: evil ? `Web ${ESC}` : "Web", contractAuthority: "git" }] });
    }
    if (url === "/v1/organizations/acme/projects/web/environments") {
      return json(200, {
        items: [
          { id: "env_1", name: evil ? `development${EVIL}` : "development", kind: "shared", tier: "development", parentEnvironmentId: null },
          { id: "env_2", name: "production", kind: evil ? `shared${ESC}` : "shared", tier: "production", parentEnvironmentId: null },
        ],
      });
    }
    if (url === "/v1/organizations/acme/identities") {
      return json(200, {
        items: [
          { id: "idn_1", name: evil ? `ci${EVIL}` : "ci", kind: "service", disabled: false, lastSeenAt: evil ? `${STORED}${EVIL}` : "2026-09-30T10:00:00.000Z" },
          { id: "idn_2", name: "old", kind: "service", disabled: true },
        ],
      });
    }
    // values set: the server echoes the value it was sent in its error message.
    if (req.method === "PUT" && url.endsWith("/values/API_KEY")) {
      const sent = (JSON.parse(body) as { value: string }).value;
      return error(422, "VALIDATION_FAILED", `the value ${sent} is not accepted${EVIL}`);
    }
    error(404, "RESOURCE_NOT_FOUND", "not found");
  });
}

let server: http.Server;
let origin = "";

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
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
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

/** A fresh credential store holding STORED for another server. */
function freshStore(): void {
  rmSync(config, { recursive: true, force: true });
  mkdirSync(config);
  writeFileSync(join(config, "credentials.json"), JSON.stringify({ servers: { "https://other.example": { token: STORED } } }));
}

function cli(args: string[], env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: config, VARLATCH_TOKEN: BEARER, VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/** The browser sign-in to the end, answering the callback as the sign-in page does. */
async function browserLogin(): Promise<Result> {
  const child = spawn(process.execPath, [bundle, "login", "--server", origin], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0", VARLATCH_NO_BROWSER: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
  const exited = new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  try {
    const printed = await new Promise<string>((resolve, reject) => {
      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString();
        if (stdout.split("\n").length > 2) resolve(stdout);
      });
      void exited.then(() => reject(new Error(`login exited before printing the address:\n${stdout}${stderr}`)));
    });
    const callback = new URL((printed.split("\n")[1] ?? "").trim()).searchParams.get("callback") ?? "";
    await fetch(callback, { method: "POST", body: JSON.stringify({ token: HANDOFF }) });
    const code = await exited;
    return { code, stdout, stderr };
  } finally {
    child.kill();
  }
}

/** Every canary that must never be printed as it is. */
function leaks(r: Result): string[] {
  const out = r.stdout + r.stderr;
  return [
    ...[STORED, BEARER, SENT, HANDOFF, ISSUED].filter((canary) => out.includes(canary)),
    ...(out.includes("\u001b") ? ["an escape character"] : []),
    ...(out.includes(RLO) ? ["a bidirectional override"] : []),
    ...(/^Error FAKE_LINE/m.test(out) ? ["a forged line"] : []),
  ];
}

describe("varlatch login prints only checked fields", () => {
  it("an expiry, a version and an API major of the wrong shape become fixed phrases", async () => {
    freshStore();
    evil = true;
    const r = await browserLogin();
    expect(r.code, r.stderr).toBe(0);
    expect(leaks(r)).toEqual([]);
    expect(r.stdout).toContain("Issued CLI credential (expires an unrecognized time).\n");
    expect(r.stdout).toContain(`Logged in to ${origin} (server an unrecognized version, an unrecognized API version).\n`);
  });

  it("control: ordinary fields print exactly as before", async () => {
    freshStore();
    evil = false;
    const r = await browserLogin();
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Issued CLI credential (expires 2026-12-01T00:00:00.000Z).\n");
    expect(r.stdout).toContain(`Logged in to ${origin} (server 0.21.0, API v1).\n`);
  });
});

describe("an API error prints only checked text", () => {
  it("the code if the protocol defines it, the message escaped with every known secret masked, a request id only in the server's format", async () => {
    freshStore();
    evil = true;
    const r = await cli(["values", "list"]);
    expect(r.code).toBe(77);
    expect(leaks(r)).toEqual([]);
    // One line: the forged line break is shown as an escape; no request id.
    expect(r.stderr).toBe(
      "Error UNRECOGNIZED_ERROR: denied for Bearer [redacted] and [redacted], token [redacted]\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e\n",
    );
  });

  it("masks a value the CLI sent, echoed back in the message", async () => {
    freshStore();
    evil = true;
    const r = await cli(["values", "set", "API_KEY", SENT]);
    expect(r.code).toBe(1);
    expect(leaks(r)).toEqual([]);
    expect(r.stderr).toBe(
      `Error VALIDATION_FAILED: the value [redacted] is not accepted\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e (request ${REQUEST_ID})\n`,
    );
  });

  it("control: an ordinary error prints exactly as before", async () => {
    freshStore();
    evil = false;
    const r = await cli(["values", "list"]);
    expect(r.code).toBe(77);
    expect(r.stderr).toBe(`Error PERMISSION_DENIED: This identity may not read values here (request ${REQUEST_ID})\n`);
  });
});

describe("names from the server are escaped", () => {
  it("organizations, projects, environments and identities", async () => {
    freshStore();
    evil = true;
    const results = await Promise.all([
      cli(["org", "list", "--server", origin]),
      cli(["project", "list"]),
      cli(["env", "list"]),
      cli(["identity", "list"]),
    ]);
    for (const r of results) {
      expect(r.code, r.stderr).toBe(0);
      expect(leaks(r)).toEqual([]);
    }
    const [orgs, projects, envs, identities] = results as [Result, Result, Result, Result];
    expect(orgs.stdout).toBe("acme  (Acme\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e)\n");
    expect(projects.stdout).toBe("web\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e  (Web \\u001b[31m, git)\n");
    expect(envs.stdout).toBe(
      "development\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e  (development, shared)\nproduction  (production, shared\\u001b[31m)\n",
    );
    expect(identities.stdout).toBe(
      "idn_1  ci\\u000aError FAKE_LINE: a line the server forged\\u001b[31m\\u202e  (service, active, last seen an unrecognized time)\n" +
        "idn_2  old  (service, retired, last seen never)\n",
    );
  });

  it("control: ordinary names print exactly as before, the frozen env list format included", async () => {
    freshStore();
    evil = false;
    const [orgs, projects, envs, identities] = await Promise.all([
      cli(["org", "list", "--server", origin]),
      cli(["project", "list"]),
      cli(["env", "list"]),
      cli(["identity", "list"]),
    ]);
    expect(orgs.stdout).toBe("acme  (Acme)\n");
    expect(projects.stdout).toBe("web  (Web, git)\n");
    expect(envs.stdout).toBe("development  (development, shared, selected)\nproduction  (production, shared)\n");
    expect(identities.stdout).toBe("idn_1  ci  (service, active, last seen 2026-09-30T10:00:00.000Z)\nidn_2  old  (service, retired, last seen never)\n");
  });
});
