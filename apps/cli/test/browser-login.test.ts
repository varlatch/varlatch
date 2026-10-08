// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * `varlatch login --server <url>`, the browser sign-in, as a desktop app
 * runs it: with VARLATCH_NO_BROWSER set the CLI opens nothing, prints the
 * sign-in address in the two lines the apps read, and finishes the sign-in
 * when the page calls back. On macOS and Linux a stand-in `open` and
 * `xdg-open` on PATH record whether the CLI started one.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-browser-login-"));
const bundle = join(dir, "varlatch.cjs");
const bin = join(dir, "bin");
const HANDOFF = "vlt_browser-session-handoff";
const ISSUED = "vlt_issued-cli-credential";
let server: http.Server;
let origin = "";
const seen: string[] = [];

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
  mkdirSync(bin);
  for (const opener of ["open", "xdg-open"]) {
    writeFileSync(join(bin, opener), `#!/bin/sh\necho "$*" >> "$VARLATCH_TEST_OPENED"\n`, { mode: 0o755 });
  }
  server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push(`${req.method} ${req.url} ${req.headers.authorization ?? ""}`);
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      };
      if (req.method === "POST" && req.url === "/v1/me/credentials/cli" && req.headers.authorization === `Bearer ${HANDOFF}`) {
        return json(201, { id: "cred_1", token: ISSUED, expiresAt: "2026-12-01T00:00:00.000Z" });
      }
      if (req.headers.authorization !== `Bearer ${ISSUED}`) {
        return json(401, { error: { code: "UNAUTHENTICATED", message: "unauthenticated", requestId: "req_1" } });
      }
      if (req.url === "/v1/meta") return json(200, { serverVersion: "0.15.1", apiMajor: 1 });
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

let n = 0;

/** Runs the browser sign-in to the end, answering the callback the way the sign-in page does. */
async function browserLogin(noBrowser: string | undefined) {
  const run = join(dir, `run-${n++}`);
  mkdirSync(run);
  const opened = join(run, "opened.txt");
  const child = spawn(process.execPath, [bundle, "login", "--server", origin], {
    cwd: dir,
    env: {
      PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
      HOME: join(run, "home"),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      VARLATCH_CONFIG_DIR: join(run, "config"),
      VARLATCH_ASSISTED: "0",
      VARLATCH_TEST_OPENED: opened,
      ...(noBrowser === undefined ? {} : { VARLATCH_NO_BROWSER: noBrowser }),
    },
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
    const [first, second = ""] = printed.split("\n");
    const callback = new URL(second.trim()).searchParams.get("callback") ?? "";
    const answer = await fetch(callback, { method: "POST", body: JSON.stringify({ token: HANDOFF }) });
    const code = await exited;
    const credentials = JSON.parse(readFileSync(join(run, "config", "credentials.json"), "utf8")) as {
      servers: Record<string, { token: string }>;
    };
    return { first, second, callbackStatus: answer.status, code, stdout, stderr, credentials, opened };
  } finally {
    child.kill();
  }
}

/** What the stand-in opener recorded, waiting briefly for it: it runs detached. */
async function openedWith(file: string): Promise<string | null> {
  for (let i = 0; i < 50 && !existsSync(file); i++) await new Promise((r) => setTimeout(r, 100));
  return existsSync(file) ? readFileSync(file, "utf8").trim() : null;
}

describe("browser login", () => {
  it("with VARLATCH_NO_BROWSER, prints the address in the documented two lines and signs in when the page calls back", async () => {
    const r = await browserLogin("1");
    expect(r.first).toBe("Complete passkey sign-in in your browser:");
    expect(r.second).toMatch(/^ {2}http:\/\/127\.0\.0\.1:\d+\/enroll\?callback=http%3A%2F%2F127\.0\.0\.1%3A\d+%2F$/);
    expect(r.second.startsWith(`  ${origin}/enroll?callback=`)).toBe(true);
    expect(r.callbackStatus).toBe(200);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain(`Logged in to ${origin}`);
    expect(seen).toContain(`POST /v1/me/credentials/cli Bearer ${HANDOFF}`);
    expect(r.credentials.servers[origin]?.token).toBe(ISSUED);
    expect(existsSync(r.opened)).toBe(false);
  });

  it.skipIf(process.platform === "win32")("control: without it, starts the opener with the printed address", async () => {
    const r = await browserLogin(undefined);
    expect(r.code, r.stderr).toBe(0);
    expect(r.first).toBe("Complete passkey sign-in in your browser:");
    expect(await openedWith(r.opened)).toBe(r.second.trim());
  });

  it.skipIf(process.platform === "win32")("VARLATCH_NO_BROWSER=0 opens the browser as if unset", async () => {
    const r = await browserLogin("0");
    expect(r.code, r.stderr).toBe(0);
    expect(await openedWith(r.opened)).toBe(r.second.trim());
  });
});
