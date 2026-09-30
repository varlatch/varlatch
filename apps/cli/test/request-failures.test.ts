// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generatePlaceholder, startBroker, type BrokerEvent, type RunningBroker } from "../src/broker.js";

/**
 * `varlatch request`'s failure paths, against the production Broker (in
 * process, with a short idle cutoff) and a TLS destination: a response cut
 * off by the Broker or by the destination fails the command and never
 * leaves a partial `-o` file; an output that cannot be written fails it; the
 * Broker's own replies, its authentication challenge included, are told
 * apart from destination responses by the marker the Broker owns, which a
 * destination can neither spoof nor trigger with a matching body.
 */

const CANARY = "sk_live_failure_canary_52aa";
const dir = mkdtempSync(join(tmpdir(), "varlatch-request-failures-"));
const bundle = join(dir, "varlatch.cjs");
const out = join(dir, "out");
let upstream: https.Server;
let dest = "";
let broker: RunningBroker;
const placeholder = generatePlaceholder();
const events: BrokerEvent[] = [];
const received: string[] = [];
const originalCa = https.globalAgent.options.ca;

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    received.push(url);
    if (url.startsWith("/stall")) {
      // Headers and part of the body, then nothing: the Broker's idle cutoff ends it.
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write("partial response\n");
      return;
    }
    if (url.startsWith("/disconnect")) {
      res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": "100" });
      res.write("only part\n", () => setTimeout(() => req.socket.destroy(), 50));
      return;
    }
    if (url.startsWith("/collide")) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("varlatch-broker: a destination error, not a broker denial\n");
      return;
    }
    if (url.startsWith("/spoof")) {
      res.writeHead(200, { "Content-Type": "application/json", "Varlatch-Broker": "refused" });
      res.end('{"ok":true}');
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("complete body\n");
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
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
    { stdio: "ignore" },
  );
  const cert = readFileSync(join(dir, "cert.pem"));
  https.globalAgent.options.ca = cert;
  upstream = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert }, answer);
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  dest = `127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const targets = { STRIPE_KEY: ["header:authorization"] };
  broker = await startBroker({
    placeholders: new Map([[placeholder, "STRIPE_KEY"]]),
    destinations: [dest],
    targets,
    limits: { idleMs: 150 },
    report: (event) => events.push(event),
    exercise: async () => ({ values: new Map([["STRIPE_KEY", CANARY]]), targets }),
  });
  mkdirSync(out);
}, 60_000);

afterAll(async () => {
  https.globalAgent.options.ca = originalCa;
  await broker?.close();
  upstream?.closeAllConnections();
  await new Promise((resolve) => upstream?.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

function request(args: string[], proxy = broker.proxyUrl): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, "request", ...args], {
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_AGENT_RUN: "run_0123456789abcdef", HTTPS_PROXY: proxy, VARLATCH_ASSISTED: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const auth = () => ["-H", `Authorization: Bearer ${placeholder}`];
const leftovers = () => readdirSync(out).filter((f) => f.includes(".varlatch-"));

describe("a response that does not arrive whole", () => {
  it("cut off by the Broker (idle cutoff on a substituted request): exit 1 with the reason; the partial body is flagged", async () => {
    const r = await request([...auth(), `https://${dest}/stall-stdout`]);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe("partial response\n");
    expect(r.stderr).toMatch(/varlatch request: the response was cut off before it was complete.*; the output is incomplete/);
    expect(events.some((e) => e.kind === "aborted")).toBe(true);
    expect(r.stdout + r.stderr).not.toContain(CANARY);
  });

  it("cut off by the Broker with -o: exit 1, and the named file is never written", async () => {
    const file = join(out, "stall.txt");
    const r = await request([...auth(), "-o", file, `https://${dest}/stall-file`]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(new RegExp(`the output is incomplete, and ${file.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")} was not written`));
    expect(existsSync(file)).toBe(false);
    expect(leftovers()).toEqual([]);
  });

  it("cut off by the destination (a disconnect mid-body, passed through): exit 1, -o never written", async () => {
    const piped = await request([`https://${dest}/disconnect-stdout`]);
    expect(piped.code).toBe(1);
    expect(piped.stderr).toMatch(/the response was cut off before it was complete/);
    const file = join(out, "disconnect.txt");
    const r = await request(["-o", file, `https://${dest}/disconnect-file`]);
    expect(r.code).toBe(1);
    expect(existsSync(file)).toBe(false);
    expect(leftovers()).toEqual([]);
  });

  it("an output that cannot be written: exit 1 naming it", async () => {
    const r = await request(["-o", join(out, "missing-dir", "x.txt"), `https://${dest}/ok-unwritable`]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/cannot write .*missing-dir\/x\.txt \(ENOENT\)/);
  });

  it("a complete response with -o replaces the named file whole, leaving nothing else behind", async () => {
    const file = join(out, "complete.txt");
    writeFileSync(file, "previous content that is longer than the new one\n");
    const r = await request(["-o", file, `https://${dest}/ok-file`]);
    expect(r.code, r.stderr).toBe(0);
    expect(readFileSync(file, "utf8")).toBe("complete body\n");
    expect(leftovers()).toEqual([]);
  });
});

describe("the Broker's replies, told apart by the marker it owns", () => {
  it("its authentication challenge (a wrong per-run credential): exit 77, reaching nothing", async () => {
    const before = received.length;
    const wrong = broker.proxyUrl.replace(/vlt:[^@]+@/, "vlt:not-the-token@");
    const r = await request([`https://${dest}/never`], wrong);
    expect(r.code).toBe(77);
    expect(r.stdout).toBe("");
    expect(r.stderr).toMatch(/the per-run proxy credential in HTTPS_PROXY was not accepted/);
    expect(r.stderr).toMatch(/the Broker refused the request \(407\)/);
    expect(received.slice(before)).toEqual([]);
  });

  it("a destination error whose body starts like a Broker message is the destination's: relayed, exit 0", async () => {
    const r = await request(["-i", `https://${dest}/collide`]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^HTTP\/1\.1 500 /);
    expect(r.stdout).toContain("varlatch-broker: a destination error, not a broker denial\n");
    expect(r.stderr).toBe("");
  });

  it.each([
    ["a passed-through request", []],
    ["a substituted, scrubbed request", ["-H", `Authorization: Bearer ${placeholder}`]],
  ])("a destination cannot spoof the marker (%s): stripped, relayed, exit 0", async (_name, extra) => {
    const r = await request(["-i", ...(extra as string[]), `https://${dest}/spoof`]);
    expect(r.code).toBe(0);
    expect(r.stdout).not.toMatch(/varlatch-broker/i);
    expect(r.stdout.endsWith('{"ok":true}')).toBe(true);
  });
});
