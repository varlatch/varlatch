// SPDX-License-Identifier: Apache-2.0
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, afterEach, describe, expect, it } from "vitest";
import { buildAgentEnv, BROKER_CREDENTIAL_ENV } from "../src/agentRun.js";
import {
  containsPlaceholder,
  generatePlaceholder,
  isTextualContentType,
  matchesSelectors,
  parseSelectors,
  startBroker,
  substituteExact,
  type RunningBroker,
} from "../src/broker.js";

describe("placeholders", () => {
  it("are opaque, random, and self-identifying", () => {
    const a = generatePlaceholder();
    const b = generatePlaceholder();
    expect(a).toMatch(/^vlch_ph_v1_[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain("STRIPE"); // no item metadata encoded
    expect(containsPlaceholder(`Bearer ${a}`)).toBe(true);
    expect(containsPlaceholder("vlch_ph_v1_short")).toBe(false);
  });

  it("substitution replaces exact tokens only", () => {
    const token = generatePlaceholder();
    const values = new Map([[token, "sk_live_1"]]);
    expect(substituteExact(`Bearer ${token}`, values)).toBe("Bearer sk_live_1");
    // A truncated token is not a token.
    expect(substituteExact(token.slice(0, -1), values)).toBe(token.slice(0, -1));
    // Unknown tokens stay put rather than vanishing.
    const other = generatePlaceholder();
    expect(substituteExact(other, values)).toBe(other);
  });
});

describe("selector matching (canonical strings from issuance)", () => {
  const sel = parseSelectors(["api.stripe.com:443", "*.example.com:443", "127.0.0.1:9000"]);
  it("matches exact host+port and wildcard subdomains, never the apex", () => {
    expect(matchesSelectors(sel, "api.stripe.com", 443)).toBe(true);
    expect(matchesSelectors(sel, "API.stripe.com.", 443)).toBe(true);
    expect(matchesSelectors(sel, "a.b.example.com", 443)).toBe(true);
    expect(matchesSelectors(sel, "example.com", 443)).toBe(false);
    expect(matchesSelectors(sel, "api.stripe.com", 8443)).toBe(false);
    expect(matchesSelectors(sel, "evil.example", 443)).toBe(false);
    expect(matchesSelectors(sel, "127.0.0.1", 9000)).toBe(true);
  });
});

describe("body substitution policy", () => {
  it("allows only inspectable text types", () => {
    expect(isTextualContentType("application/json; charset=utf-8")).toBe(true);
    expect(isTextualContentType("application/x-www-form-urlencoded")).toBe(true);
    expect(isTextualContentType("text/plain")).toBe(true);
    expect(isTextualContentType("application/octet-stream")).toBe(false);
    expect(isTextualContentType("application/gzip")).toBe(false);
    expect(isTextualContentType(undefined)).toBe(false);
  });
});

describe("agent child environment", () => {
  it("contains placeholders and proxy config, never plaintext or broker credential", () => {
    const placeholder = generatePlaceholder();
    const env = buildAgentEnv(
      { PATH: "/bin", [BROKER_CREDENTIAL_ENV]: "vlt_svc_broker" },
      {
        environmentId: "env_1",
        items: [
          { name: "PLAIN", sensitive: false, source: "self", versionId: "v1", value: "hello" },
          { name: "STRIPE_KEY", sensitive: true, source: "self", versionId: "v2", value: null },
        ],
      },
      new Map([["STRIPE_KEY", placeholder]]),
      "http://vlt:tok@127.0.0.1:1234",
    );
    expect(env.PLAIN).toBe("hello");
    expect(env.STRIPE_KEY).toBe(placeholder);
    expect(env[BROKER_CREDENTIAL_ENV]).toBeUndefined();
    expect(env.HTTPS_PROXY).toBe("http://vlt:tok@127.0.0.1:1234");
    expect(JSON.stringify(env)).not.toContain("vlt_svc_broker");
  });

  it("strips the parent's own bearer (VARLATCH_TOKEN) from the child env", () => {
    const env = buildAgentEnv(
      { PATH: "/bin", VARLATCH_TOKEN: "vlt_cli_parent" },
      { environmentId: "env_1", items: [] },
      new Map(),
      "http://vlt:tok@127.0.0.1:1234",
    );
    expect(env.VARLATCH_TOKEN).toBeUndefined();
  });

  it("metadata-credential mode injects the short-lived agent token instead (ADR-0023)", () => {
    const env = buildAgentEnv(
      { PATH: "/bin", VARLATCH_TOKEN: "vlt_cli_parent" },
      { environmentId: "env_1", items: [] },
      new Map(),
      "http://vlt:tok@127.0.0.1:1234",
      { server: "https://varlatch.example", token: "vlt_agr_child" },
    );
    expect(env.VARLATCH_TOKEN).toBe("vlt_agr_child");
    expect(env.VARLATCH_SERVER).toBe("https://varlatch.example");
    expect(JSON.stringify(env)).not.toContain("vlt_cli_parent");
  });
});

// ---------------------------------------------------------------------------
// Live loopback broker against local upstreams.

let tlsOptions: { key: Buffer; cert: Buffer };
let certDir: string;
const originalCa = https.globalAgent.options.ca;
beforeAll(() => {
  certDir = mkdtempSync(join(tmpdir(), "varlatch-broker-test-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", join(certDir, "key"), "-out", join(certDir, "cert"),
    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
  tlsOptions = { key: readFileSync(join(certDir, "key")), cert: readFileSync(join(certDir, "cert")) };
  https.globalAgent.options.ca = tlsOptions.cert;
});
afterAll(() => {
  https.globalAgent.options.ca = originalCa;
  rmSync(certDir, { recursive: true, force: true });
});

type Received = { headers: http.IncomingHttpHeaders; body: string; url: string | undefined };

function upstream(handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void, tls = true) {
  return new Promise<{ port: number; received: Received[]; close: () => void }>((resolve) => {
    const received: Received[] = [];
    const listener = (req: http.IncomingMessage, res: http.ServerResponse) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        received.push({ headers: req.headers, body, url: req.url });
        if (handler) handler(req, res);
        else res.writeHead(200, { "Content-Type": "application/json" }).end('{"ok":true}');
      });
    };
    const server = tls ? https.createServer(tlsOptions, listener) : http.createServer(listener);
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        received,
        close: () => server.close(),
      });
    });
  });
}

const cleanups: (() => unknown)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

async function liveBroker(
  destinations: string[],
  opts: { strict?: boolean; itemValue?: string | undefined; onExercise?: () => void } = {},
) {
  const placeholder = generatePlaceholder();
  const broker = await startBroker({
    placeholders: new Map([[placeholder, "STRIPE_KEY"]]),
    destinations,
    strict: opts.strict ?? false,
    exercise: async () => {
      opts.onExercise?.();
      return new Map(opts.itemValue === undefined ? [["STRIPE_KEY", "sk_live_1"]] : [["STRIPE_KEY", opts.itemValue]]);
    },
  });
  cleanups.push(broker.close);
  return { broker, placeholder };
}

function proxyRequest(
  broker: RunningBroker,
  target: string,
  init: { method?: string; headers?: Record<string, string>; body?: string; auth?: boolean } = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...init.headers };
    if (init.auth !== false) {
      headers["Proxy-Authorization"] = `Basic ${Buffer.from(`vlt:${broker.token}`).toString("base64")}`;
    }
    const req = http.request(
      { host: "127.0.0.1", port: broker.port, method: init.method ?? "GET", path: target, headers },
      (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
      },
    );
    req.on("error", reject);
    req.end(init.body);
  });
}

describe("broker proxy", () => {
  it("requires the per-run proxy token", async () => {
    const { broker } = await liveBroker(["api.example.com:443"]);
    const res = await proxyRequest(broker, "http://api.example.com/", { auth: false });
    expect(res.status).toBe(407);
  });

  it("substitutes placeholders in headers and JSON bodies for allowlisted hosts", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`]);
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/charge`, {
      method: "POST",
      headers: { Host: "wrong.example", Authorization: `Bearer ${placeholder}`, "Content-Type": "application/json" },
      body: JSON.stringify({ key: placeholder }),
    });
    expect(res.status).toBe(200);
    expect(up.received[0]!.headers.host).toBe(`127.0.0.1:${up.port}`);
    expect(up.received[0]!.headers.authorization).toBe("Bearer sk_live_1");
    expect(JSON.parse(up.received[0]!.body)).toEqual({ key: "sk_live_1" });
    expect(up.received[0]!.headers["content-length"]).toBe(String(up.received[0]!.body.length));
    expect(up.received[0]!.headers["proxy-authorization"]).toBeUndefined();
  });

  it("refuses HTTP substitution before exercising, including in strict mode", async () => {
    const up = await upstream(undefined, false);
    cleanups.push(up.close);
    let exercised = false;
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`], {
      strict: true, onExercise: () => { exercised = true; },
    });
    const res = await proxyRequest(broker, `http://127.0.0.1:${up.port}/`, {
      headers: { Authorization: placeholder },
    });
    expect(res.status).toBe(502);
    expect(exercised).toBe(false);
    expect(up.received).toHaveLength(0);
  });

  it("rejects an untrusted TLS certificate without sending secret material", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`]);
    https.globalAgent.options.ca = [];
    try {
      const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/`, {
        headers: { Authorization: placeholder },
      });
      expect(res.status).toBe(502);
      expect(up.received).toHaveLength(0);
    } finally { https.globalAgent.options.ca = tlsOptions.cert; }
  });

  it("passes non-allowlisted traffic through unchanged — placeholders intact", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    let exercised = false;
    const { broker, placeholder } = await liveBroker(["api.example.com:443"], {
      onExercise: () => (exercised = true),
    });
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/collect`, {
      headers: { Authorization: `Bearer ${placeholder}` },
    });
    expect(res.status).toBe(200);
    expect(exercised).toBe(false);
    expect(up.received[0]!.headers.authorization).toBe(`Bearer ${placeholder}`);
  });

  it("strict mode blocks non-allowlisted traffic instead", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker } = await liveBroker(["api.example.com:443"], { strict: true });
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/x`);
    expect(res.status).toBe(403);
    expect(up.received).toHaveLength(0);
  });

  it("refuses substitution into non-textual bodies, never partial", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`]);
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/bin`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: `prefix ${placeholder} suffix`,
    });
    expect(res.status).toBe(502);
    expect(up.received).toHaveLength(0);
  });

  it("fails loudly when a placeholder cannot be resolved", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const broker = await startBroker({
      placeholders: new Map([[generatePlaceholder(), "STRIPE_KEY"]]),
      destinations: [`127.0.0.1:${up.port}`],
      exercise: async () => new Map(), // withheld by the server
    });
    cleanups.push(broker.close);
    const foreign = generatePlaceholder();
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/x`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: foreign }),
    });
    expect(res.status).toBe(502);
    expect(up.received).toHaveLength(0);
  });

  it("answers 503 with Retry-After while the installation is in maintenance (ADR-0036 D6)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const placeholder = generatePlaceholder();
    const broker = await startBroker({
      placeholders: new Map([[placeholder, "STRIPE_KEY"]]),
      destinations: [`127.0.0.1:${up.port}`],
      exercise: async () => {
        throw Object.assign(new Error("Installation maintenance; retry later"), { code: "MAINTENANCE" });
      },
    });
    cleanups.push(broker.close);
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/charge`, {
      headers: { Authorization: `Bearer ${placeholder}` },
    });
    expect(res.status).toBe(503);
    expect(res.headers["retry-after"]).toBe("15");
    expect(res.body).toContain("maintenance");
    expect(up.received).toHaveLength(0);
  });

  it("relays redirects to the agent instead of following them", async () => {
    const up = await upstream((_req, res) => {
      res.writeHead(302, { Location: "http://evil.example/collect" }).end();
    });
    cleanups.push(up.close);
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`]);
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/r`, {
      headers: { Authorization: `Bearer ${placeholder}` },
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("http://evil.example/collect");
    // Only the original request went out; nothing was sent to evil.example.
    expect(up.received).toHaveLength(1);
  });

  it("refuses CONNECT to secret-using destinations with the diagnostic", async () => {
    const { broker } = await liveBroker(["api.stripe.com:443"]);
    const result = await new Promise<string>((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port: broker.port,
        method: "CONNECT",
        path: "api.stripe.com:443",
        headers: { "Proxy-Authorization": `Basic ${Buffer.from(`vlt:${broker.token}`).toString("base64")}` },
      });
      // Node emits "connect" for every response to a CONNECT request; the
      // status code distinguishes an established tunnel from a refusal.
      req.on("connect", (res, socket, head) => {
        socket.destroy();
        resolve(`${res.statusCode}:${head.toString()}`);
      });
      req.on("response", (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c.toString()));
        res.on("end", () => resolve(`${res.statusCode}:${body}`));
      });
      req.on("error", reject);
      req.end();
    });
    expect(result).toContain("502");
    expect(result).toContain("intentionally does not MITM");
  });

  it("rejects origin-form requests with guidance", async () => {
    const { broker } = await liveBroker(["api.example.com:443"]);
    const res = await proxyRequest(broker, "/not-absolute");
    expect(res.status).toBe(400);
    expect(res.body).toContain("absolute-URI");
  });
});
