// SPDX-License-Identifier: Apache-2.0
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { BROKER_REPLY_HEADER } from "../src/scrub.js";
import { cliCommand } from "./cliUnderTest.js";

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
 *
 * Against a Go CLI (VARLATCH_TEST_CLI), the Broker is the one a real
 * `varlatch run --agent-safe` starts, against a fake server, for an Agent
 * that hands back its proxy address and waits: the process that must stay
 * alive is the run.
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

let api: http.Server | undefined;
afterAll(async () => {
  if (api) await new Promise((resolve) => api?.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

const ENV_PATH = "/v1/organizations/acme/projects/web/environments/development";

/** The fake Varlatch server of a run: one Secret, one agent, a Capability for api.example.com:443. */
function answerApi(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    const json = (status: number, payload?: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(payload === undefined ? "" : JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { serverVersion: "0.22.0", capabilities: ["capabilities.targets"] });
    if (url.startsWith(`${ENV_PATH}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_1",
        items: [{ name: "API_KEY", sensitive: true, source: "self", value: null }],
        manifest: { manifestVersion: 1, projectId: "prj_1", environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null }, contract: null, items: [] },
      });
    }
    if (url === "/v1/organizations/acme/identities") return json(200, { items: [{ id: "idn_agent", kind: "agent", name: "coder" }] });
    if (url === `${ENV_PATH}/capabilities` && req.method === "POST") {
      return json(201, { id: "cap_1", secret: "capsecret", destinations: ["api.example.com:443"], targets: { API_KEY: ["header:authorization"] }, expiresAt: "2100-01-01T00:00:00.000Z" });
    }
    if (req.method === "DELETE") return json(204);
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: url, requestId: "r" } });
  });
}

/** The Agent: hands back the Broker's port and per-run credential, then waits to be ended. */
const AGENT = `const p = new URL(process.env.HTTPS_PROXY);
process.stdout.write(JSON.stringify({ port: Number(p.port), token: decodeURIComponent(p.password) }) + "\\n");
setInterval(() => {}, 1000);
process.on("SIGTERM", () => process.exit(0));
`;

async function startRun(mode: "default" | "strict"): Promise<Child> {
  if (!api) {
    api = http.createServer(answerApi);
    await new Promise<void>((resolve) => api?.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
    mkdirSync(join(dir, "repo"), { recursive: true });
    writeFileSync(join(dir, "repo", "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
    writeFileSync(join(dir, "agent.cjs"), AGENT);
  }
  const args = [
    "run", "--agent-safe", "--agent", "coder", "--allow-host", "api.example.com", "--target", "API_KEY=header:authorization",
    ...(mode === "strict" ? ["--agent-network", "strict"] : []),
    "--", process.execPath, join(dir, "agent.cjs"),
  ];
  const env = { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_cli_operatorFAKE", VARLATCH_BROKER_CREDENTIAL: "vlt_brk_fakeBROKER", VARLATCH_ASSISTED: "0" };
  return new Promise((resolve, reject) => {
    const child = spawn(...cliCommand(join(dir, "unused.cjs"), args), { cwd: join(dir, "repo"), env, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.stdout.once("data", (d: Buffer) => {
      const { port, token } = JSON.parse(d.toString()) as { port: number; token: string };
      resolve({ process: child, port, token, stderr: () => stderr });
    });
    child.on("error", reject);
    child.on("close", (code) => reject(new Error(`the run ended (${code}) before its Agent started:\n${stderr}`)));
  });
}

function startChild(mode: "default" | "strict"): Promise<Child> {
  if (process.env.VARLATCH_TEST_CLI) return startRun(mode);
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
