// SPDX-License-Identifier: Apache-2.0
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { BROKER_REPLY_HEADER } from "../src/scrub.js";

/**
 * A client that resets its connection around a refused CONNECT must not end
 * the Broker. The ADR-0043 agent evaluation found it: an Agent ran curl
 * against an allowed destination, curl reset the connection after the
 * Broker's 502, the unhandled socket error ended the Broker, and with it the
 * tunnels carrying the Agent's own traffic. Each refusal (407 without the
 * proxy credential, 502 for an allowed destination, 403 in strict mode) is
 * followed by a real reset, after the reply and before it, several times;
 * the Broker runs in its own process, so a crash is a dead process, and a
 * live Broker answers the next request.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-broker-reset-"));
const bundle = join(dir, "broker-child.cjs");

interface Child {
  process: ChildProcess;
  port: number;
  token: string;
  stderr: () => string;
}

beforeAll(async () => {
  const entry = join(dir, "broker-child.ts");
  writeFileSync(
    entry,
    `import { startBroker } from ${JSON.stringify(fileURLToPath(new URL("../src/broker.ts", import.meta.url)))};
startBroker({
  placeholders: new Map(),
  destinations: ["api.example.com:443"],
  targets: {},
  strict: process.argv[2] === "strict",
  exercise: async () => ({ values: new Map(), targets: {} }),
}).then((b) => process.stdout.write(JSON.stringify({ port: b.port, token: b.token }) + "\\n"));
`,
  );
  await build({ entryPoints: [entry], bundle: true, platform: "node", format: "cjs", target: "node22", outfile: bundle, logLevel: "silent" });
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

function startChild(mode: "default" | "strict"): Promise<Child> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, mode], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.stdout.once("data", (d: Buffer) => {
      const { port, token } = JSON.parse(d.toString()) as { port: number; token: string };
      resolve({ process: child, port, token, stderr: () => stderr });
    });
    child.on("error", reject);
  });
}

const alive = (child: Child) => child.process.exitCode === null && child.process.signalCode === null;

/** Sends `request` on a fresh connection and resets it (RST), after the first reply bytes or right after sending. */
function connectAndReset(port: number, request: string, when: "after-reply" | "before-reply"): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    let reply = "";
    socket.on("error", () => resolve(reply));
    socket.on("connect", () => {
      socket.write(request);
      if (when === "before-reply") {
        socket.resetAndDestroy();
        resolve("");
      }
    });
    socket.on("data", (d: Buffer) => {
      reply += d.toString();
      if (when === "after-reply" && !socket.destroyed) {
        socket.resetAndDestroy();
        resolve(reply);
      }
    });
    socket.on("close", () => resolve(reply));
  });
}

/** A plain request to the Broker without the proxy credential: a live Broker answers 407. */
function nextRequestStatus(port: number): Promise<number | string> {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: "http://api.example.com/next", timeout: 3000 }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve(String(err)));
  });
}

const auth = (token: string) => `Proxy-Authorization: Basic ${Buffer.from(`vlt:${token}`).toString("base64")}\r\n`;

const REFUSALS: { name: string; mode: "default" | "strict"; status: number; request: (token: string) => string }[] = [
  { name: "407: no proxy credential", mode: "default", status: 407, request: () => "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n" },
  { name: "502: an allowed destination (substitution needs the plain request)", mode: "default", status: 502, request: (t) => `CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n${auth(t)}\r\n` },
  { name: "403: strict mode, another destination", mode: "strict", status: 403, request: (t) => `CONNECT other.example.org:443 HTTP/1.1\r\nHost: other.example.org:443\r\n${auth(t)}\r\n` },
];

describe("a client reset around a refused CONNECT", () => {
  for (const refusal of REFUSALS) {
    it(`${refusal.name}: the Broker keeps running and serves the next request`, async () => {
      const child = await startChild(refusal.mode);
      try {
        for (let i = 0; i < 10; i++) {
          const reply = await connectAndReset(child.port, refusal.request(child.token), "after-reply");
          await connectAndReset(child.port, refusal.request(child.token), "before-reply");
          await new Promise((r) => setTimeout(r, 20));
          // A crash shows here, with the Broker's own error output.
          expect(alive(child), `the Broker exited after reset ${i + 1}:\n${child.stderr()}`).toBe(true);
          // The refusal itself is unchanged: its status and the Broker's marker.
          expect(reply).toMatch(new RegExp(`^HTTP/1\\.1 ${refusal.status} `));
          expect(reply.toLowerCase()).toContain(`${BROKER_REPLY_HEADER.toLowerCase()}: refused`);
        }
        await new Promise((r) => setTimeout(r, 200));
        expect(alive(child), child.stderr()).toBe(true);
        expect(await nextRequestStatus(child.port)).toBe(407);
        expect(child.stderr()).not.toMatch(/Unhandled 'error' event|ECONNRESET/);
      } finally {
        child.process.kill();
      }
    }, 30_000);
  }
});
