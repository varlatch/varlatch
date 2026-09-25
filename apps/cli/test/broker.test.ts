// SPDX-License-Identifier: Apache-2.0
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net, { type AddressInfo } from "node:net";
import { afterAll, beforeAll, afterEach, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import type { ResolvedContext } from "@varlatch/context";
import {
  buildAgentEnv,
  BROKER_CREDENTIAL_ENV,
  checkTargetFlags,
  contractSecrets,
  issueWithTargets,
  requireTargetsServer,
} from "../src/agentRun.js";
import {
  generatePlaceholder,
  matchesSelectors,
  parseSelectors,
  sameTargets,
  startBroker,
  type BrokerEvent,
  type Exercised,
  type RunningBroker,
} from "../src/broker.js";
import type { Placement } from "../src/placement.js";

describe("placeholders", () => {
  it("are opaque, random, and self-identifying", () => {
    const a = generatePlaceholder();
    const b = generatePlaceholder();
    expect(a).toMatch(/^vlch_ph_v1_[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain("STRIPE"); // no item metadata encoded
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
    expect(env.NODE_USE_ENV_PROXY).toBe("1");
    expect(env.NO_PROXY).toBe("127.0.0.1:1234");
    expect(env.no_proxy).toBe("127.0.0.1:1234");
    expect(JSON.stringify(env)).not.toContain("vlt_svc_broker");
  });

  it("strips stored and Contract Secrets inherited from the shell; unknown names pass (test 8)", () => {
    const placeholder = generatePlaceholder();
    const env = buildAgentEnv(
      { PATH: "/bin", STRIPE_KEY: "sk_shell", OMITTED: "shell_omitted", CONTRACT_ONLY: "shell_contract", UNKNOWN: "shell_unknown" },
      {
        environmentId: "env_1",
        items: [
          { name: "STRIPE_KEY", sensitive: true, source: "self", versionId: "v1", value: "sk_operator_can_read" },
          { name: "OMITTED", sensitive: true, source: "self", versionId: "v2", value: "operator_plaintext" },
        ],
      },
      new Map([["STRIPE_KEY", placeholder]]),
      "http://vlt:tok@127.0.0.1:1234",
      undefined,
      ["STRIPE_KEY", "OMITTED", "CONTRACT_ONLY"],
    );
    expect(env.STRIPE_KEY).toBe(placeholder);
    // An omitted Secret never reaches the Agent, neither the shell's copy nor the operator's.
    expect(env.OMITTED).toBeUndefined();
    expect(env.CONTRACT_ONLY).toBeUndefined();
    expect(env.UNKNOWN).toBe("shell_unknown"); // the stated limit
    expect(JSON.stringify(env)).not.toMatch(/sk_shell|shell_omitted|shell_contract|operator_plaintext|sk_operator_can_read/);
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

describe("targets on the command line (tests 3 and 4)", () => {
  it("every stored Secret needs a target or an omit, naming the item and the flags", () => {
    expect(() => checkTargetFlags(["API_KEY", "DB_PASSWORD"], { targets: { DB_PASSWORD: ["json:/password"] }, omit: [] })).toThrow(
      "API_KEY has no substitution target: add --target API_KEY=header:authorization\n" +
        "          (or query:, json:, form:), or --omit API_KEY to leave it out of this run",
    );
  });

  it("--omit leaves the Secret off the Capability", () => {
    expect(checkTargetFlags(["API_KEY", "DB_PASSWORD"], { targets: { API_KEY: ["header:authorization"] }, omit: ["DB_PASSWORD"] })).toEqual({
      mediated: ["API_KEY"],
      targets: { API_KEY: ["header:authorization"] },
    });
  });

  it("names that are not stored Secrets, or both targeted and omitted, are errors", () => {
    expect(() => checkTargetFlags(["API_KEY"], { targets: { API_KEY: ["header:x"], TYPO: ["header:y"] }, omit: [] })).toThrow(
      "not stored here: TYPO",
    );
    expect(() => checkTargetFlags(["API_KEY"], { targets: { API_KEY: ["header:x"] }, omit: ["API_KEY"] })).toThrow("both targeted and omitted");
  });
});

// Stand-ins for the parts of the SDK client the run's checks use.
function stubClient(parts: Partial<Record<keyof VarlatchClient, unknown>>): VarlatchClient {
  return parts as unknown as VarlatchClient;
}
const ctx = { organization: "o", project: "p", environment: "e", server: "https://v.example" } as ResolvedContext;

describe("the server's side of targets (tests 2, 6, and 9)", () => {
  it("a server without capabilities.targets is refused, naming the minimum version", async () => {
    const api = stubClient({ meta: async () => ({ apiMajor: 1, serverVersion: "0.10.0", capabilities: ["capabilities.broker"] }) });
    await expect(requireTargetsServer(api)).rejects.toThrow("Varlatch 0.11.0 or later on the server");
    const current = stubClient({ meta: async () => ({ apiMajor: 1, serverVersion: "0.11.0", capabilities: ["capabilities.targets"] }) });
    await expect(requireTargetsServer(current)).resolves.toBeUndefined();
  });

  it("issuance must record exactly the requested targets, or the run does not start", async () => {
    const input = {
      agentIdentityId: "id_a",
      items: ["API_KEY"],
      destinations: ["api.example.com:443"],
      targets: { API_KEY: ["header:authorization"] },
      ttlSeconds: 60,
    };
    for (const returned of [undefined, { API_KEY: ["header:x-api-key"] }, { API_KEY: ["header:authorization", "query:k"] }]) {
      const revoked: string[] = [];
      const api = stubClient({
        issueCapability: async () => ({ id: "cap_1", secret: "s", destinations: [], targets: returned }),
        revokeCapability: async (_o: string, _p: string, _e: string, id: string) => revoked.push(id),
      });
      await expect(issueWithTargets(api, ctx, input)).rejects.toThrow("different substitution targets");
      expect(revoked).toEqual(["cap_1"]);
    }
    const ok = stubClient({ issueCapability: async () => ({ id: "cap_1", secret: "s", destinations: [], targets: input.targets }) });
    await expect(issueWithTargets(ok, ctx, input)).resolves.toMatchObject({ id: "cap_1" });
  });

  it("the Broker re-checks the targets it is given and refuses a transport-owned header", async () => {
    await expect(
      startBroker({ placeholders: new Map(), destinations: [], targets: { A: ["header:host"] }, exercise: async () => ({ values: new Map(), targets: {} }) }),
    ).rejects.toThrow("transport-owned");
    expect(sameTargets({ A: ["query:a", "header:b"] }, { A: ["header:b", "query:a"] })).toBe(true);
    expect(sameTargets({ A: ["header:b"] }, { A: ["header:b"], B: ["header:b"] })).toBe(false);
  });

  it("an active Contract needs contract.read; without a Contract nothing is fetched", async () => {
    const effective = (contract: boolean) =>
      ({ environmentId: "e", items: [], manifest: { contract: contract ? { revisionId: "r" } : null } }) as unknown as EffectiveConfiguration;
    const denied = stubClient({
      getActiveContract: async () => {
        throw new VarlatchApiError(404, "RESOURCE_NOT_FOUND", "No active Contract revision");
      },
    });
    await expect(contractSecrets(denied, ctx, effective(true))).rejects.toThrow("needs contract.read");
    await expect(contractSecrets(denied, ctx, effective(false))).resolves.toEqual([]);
    const readable = stubClient({
      getActiveContract: async () => ({ contract: { items: [{ name: "A", sensitive: true }, { name: "B", sensitive: false }] } }),
    });
    await expect(contractSecrets(readable, ctx, effective(true))).resolves.toEqual(["A"]);
    // A server that reports no manifest cannot say whether a Contract is active.
    await expect(contractSecrets(readable, ctx, { environmentId: "e", items: [] })).rejects.toThrow("0.11.0 or later");
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

type Received = { headers: http.IncomingHttpHeaders; rawHeaders: string[]; body: string; url: string | undefined };

/** A fake upstream that records every request and every TCP connection. */
function upstream(handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void, tls = true) {
  return new Promise<{ port: number; received: Received[]; connections: () => number; close: () => void }>((resolve) => {
    const received: Received[] = [];
    let connections = 0;
    const listener = (req: http.IncomingMessage, res: http.ServerResponse) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        received.push({ headers: req.headers, rawHeaders: req.rawHeaders, body, url: req.url });
        if (handler) handler(req, res);
        else res.writeHead(200, { "Content-Type": "application/json" }).end('{"ok":true}');
      });
    };
    const server = tls ? https.createServer(tlsOptions, listener) : http.createServer(listener);
    server.on("connection", () => connections++);
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        received,
        connections: () => connections,
        close: () => server.close(),
      });
    });
  });
}

const cleanups: (() => unknown)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

const DEFAULT_TARGETS = { STRIPE_KEY: ["header:authorization", "json:/key"] };

async function liveBroker(
  destinations: string[],
  opts: {
    strict?: boolean;
    itemValue?: string;
    targets?: Record<string, string[]>;
    onExercise?: (placements: Placement[]) => void;
    respond?: (placements: Placement[]) => Exercised;
  } = {},
) {
  const placeholder = generatePlaceholder();
  const events: BrokerEvent[] = [];
  const exercises: Placement[][] = [];
  const targets = opts.targets ?? DEFAULT_TARGETS;
  const broker = await startBroker({
    placeholders: new Map([[placeholder, "STRIPE_KEY"]]),
    destinations,
    targets,
    strict: opts.strict ?? false,
    report: (event) => events.push(event),
    exercise: async (_destination, placements) => {
      exercises.push(placements);
      opts.onExercise?.(placements);
      if (opts.respond) return opts.respond(placements);
      return { values: new Map([["STRIPE_KEY", opts.itemValue ?? "sk_live_1"]]), targets };
    },
  });
  cleanups.push(broker.close);
  return { broker, placeholder, events, exercises };
}

function proxyRequest(
  broker: RunningBroker,
  target: string,
  init: { method?: string; headers?: Record<string, string> | string[]; body?: string | Buffer; auth?: boolean } = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const auth = `Basic ${Buffer.from(`vlt:${broker.token}`).toString("base64")}`;
    let headers: Record<string, string> | string[];
    if (Array.isArray(init.headers)) {
      headers = [...init.headers, ...(init.auth !== false ? ["Proxy-Authorization", auth] : [])];
    } else {
      headers = { ...init.headers };
      if (init.auth !== false) headers["Proxy-Authorization"] = auth;
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

  it("substitutes only at the targets, and changes nothing but the transport it owns (test 11)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder, exercises } = await liveBroker([`127.0.0.1:${up.port}`], {
      targets: { STRIPE_KEY: ["header:authorization", "json:/key", "query:k"] },
      itemValue: "sk live/1",
    });
    const body = `{"key": "${placeholder}",  "n": 1.50}`;
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/charge?a=%7e1&k=${placeholder}&b=x+y`, {
      method: "POST",
      headers: ["Host", "wrong.example", "Authorization", `Bearer ${placeholder}`, "X-Dup", "1", "x-dup", "2", "Content-Type", "application/json"],
      body,
    });
    expect(res.status).toBe(200);
    const got = up.received[0]!;
    expect(got.url).toBe("/charge?a=%7e1&k=sk%20live%2F1&b=x+y");
    expect(got.headers.host).toBe(`127.0.0.1:${up.port}`);
    expect(got.body).toBe(`{"key": "sk live/1",  "n": 1.50}`);
    expect(got.headers["content-length"]).toBe(String(Buffer.byteLength(got.body)));
    expect(got.headers["proxy-authorization"]).toBeUndefined();
    // Every other header arrives as sent: order, case, and repeats.
    const pairs: string[] = [];
    for (let i = 0; i < got.rawHeaders.length; i += 2) {
      if (!["host", "content-length", "connection"].includes(got.rawHeaders[i]!.toLowerCase())) pairs.push(got.rawHeaders[i]!, got.rawHeaders[i + 1]!);
    }
    expect(pairs).toEqual(["Authorization", "Bearer sk live/1", "X-Dup", "1", "x-dup", "2", "Content-Type", "application/json"]);
    // The exercise named exactly the placements.
    expect(exercises).toEqual([
      [
        { item: "STRIPE_KEY", target: "header:authorization" },
        { item: "STRIPE_KEY", target: "query:k" },
        { item: "STRIPE_KEY", target: "json:/key" },
      ],
    ]);
    expect(broker.heldValues()).toBe(0);
  });

  it("the Agent cannot add or widen a target from its request (test 1)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder, exercises } = await liveBroker([`127.0.0.1:${up.port}`]);
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/x?target=header:x-api-key`, {
      headers: { "X-Varlatch-Target": "STRIPE_KEY=header:x-api-key", "X-Api-Key": placeholder, Authorization: placeholder },
    });
    expect(res.status).toBe(403);
    expect(res.body).toContain('STRIPE_KEY: placeholder at header "x-api-key", which is not a target');
    expect(exercises).toHaveLength(0);
    expect(up.connections()).toBe(0);
  });

  it("forwards a stray in an untargeted surface unchanged and reports it (test 13)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder, events } = await liveBroker([`127.0.0.1:${up.port}`], {
      targets: { STRIPE_KEY: ["header:authorization"] },
    });
    const res = await proxyRequest(broker, `https://127.0.0.1:${up.port}/log`, {
      method: "POST",
      headers: { Authorization: `Bearer ${placeholder}`, "Content-Type": "application/octet-stream" },
      body: `prefix ${placeholder} suffix`,
    });
    expect(res.status).toBe(200);
    expect(up.received[0]!.headers.authorization).toBe("Bearer sk_live_1");
    expect(up.received[0]!.body).toBe(`prefix ${placeholder} suffix`);
    expect(events).toEqual([{ kind: "stray", item: "STRIPE_KEY", surface: "body" }]);
  });

  it("blocks before exercise with no call to varlatchd and zero upstream connections (tests 12, 14, 15, 16)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder: p, exercises, events } = await liveBroker([`127.0.0.1:${up.port}`], {
      targets: { STRIPE_KEY: ["header:authorization", "json:/key", "query:k"] },
    });
    const url = `https://127.0.0.1:${up.port}/x`;
    const json = { "Content-Type": "application/json" };
    const cases: [string, Parameters<typeof proxyRequest>[2], string][] = [
      [url, { headers: { Authorization: p, "X-Debug": p } }, "outside-target"],
      [url, { headers: { Authorization: `${p} ${p}` } }, "second-occurrence"],
      [url, { method: "POST", headers: json, body: `{"key":"${p}","key":"x"}` }, "duplicate-key"],
      [url, { headers: ["Host", "127.0.0.1", "Authorization", p, "authorization", "x"] }, "repeated-header"],
      [`${url}?k=${p}&%6b=x`, {}, "repeated-name"],
      [`${url}?k=${p};x=1`, {}, "separator"],
      [`${url}?k=${p.replace("_", "%5F")}`, {}, "encoded-placeholder"],
      [url, { method: "POST", headers: { "Content-Type": "text/plain" }, body: `{"key":"${p}"}` }, "content-type"],
      [url, { method: "POST", headers: { "Content-Type": "application/json; charset=latin1" }, body: `{"key":"${p}"}` }, "content-type"],
      [url, { method: "POST", headers: { ...json, "Content-Encoding": "gzip" }, body: `{"key":"${p}"}` }, "content-encoding"],
    ];
    for (const [target, init, rule] of cases) {
      const res = await proxyRequest(broker, target, init);
      expect(res.status, rule).toBe(403);
      expect(res.body).not.toContain(p);
      expect(events.at(-1)).toMatchObject({ kind: "blocked", rule });
    }
    const over = await proxyRequest(broker, url, { method: "POST", headers: json, body: Buffer.alloc(2 * 1024 * 1024 + 1, 0x20) });
    expect(over.status).toBe(413);
    expect(exercises).toHaveLength(0);
    expect(up.connections()).toBe(0);
  });

  it("drops the request after exercise with zero upstream connections, holding no plaintext (test 17)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const targets = { STRIPE_KEY: ["header:authorization", "json:/key"] };
    const url = `https://127.0.0.1:${up.port}/x`;
    const scenarios: [string, (p: string) => Parameters<typeof proxyRequest>[2], (placements: Placement[]) => Exercised][] = [
      ["unsafe-header-value", (p) => ({ headers: { Authorization: p } }), () => ({ values: new Map([["STRIPE_KEY", "a\r\nX-Injected: 1"]]), targets })],
      [
        "body-limit",
        (p) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: `{"key":"${p}","f":"${"x".repeat(2 * 1024 * 1024 - 100)}"}` }),
        () => ({ values: new Map([["STRIPE_KEY", "v".repeat(500)]]), targets }),
      ],
      ["exercise-mismatch", (p) => ({ headers: { Authorization: p } }), () => ({ values: new Map([["STRIPE_KEY", "v"]]), targets: { STRIPE_KEY: ["header:x"] } })],
      [
        "exercise-mismatch",
        (p) => ({ headers: { Authorization: p } }),
        () => ({ values: new Map([["STRIPE_KEY", "v"], ["OTHER", "w"]]), targets }),
      ],
      ["missing-value", (p) => ({ headers: { Authorization: p } }), () => ({ values: new Map(), targets, withheld: ["STRIPE_KEY"] })],
    ];
    for (const [rule, init, respond] of scenarios) {
      const { broker, placeholder, exercises, events } = await liveBroker([`127.0.0.1:${up.port}`], { targets, respond });
      const res = await proxyRequest(broker, url, init(placeholder));
      expect(res.status, rule).toBe(502);
      expect(res.body).not.toMatch(/sk_live|X-Injected|vvvv/);
      expect(exercises).toHaveLength(1);
      expect(events.at(-1)).toMatchObject({ kind: "failed", rule });
      expect(broker.heldValues()).toBe(0);
    }
    expect(up.connections()).toBe(0);
  });

  it("answers 413 to a declared length over the limit before reading the body (test 18, B-P6)", async () => {
    const { broker } = await liveBroker(["api.example.com:443"]);
    const reply = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(broker.port, "127.0.0.1", () => {
        socket.write(
          `POST https://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n` +
            `Proxy-Authorization: Basic ${Buffer.from(`vlt:${broker.token}`).toString("base64")}\r\n` +
            `Content-Length: ${3 * 1024 * 1024}\r\n\r\nonly a little`,
        );
      });
      let data = "";
      socket.on("data", (c: Buffer) => {
        data += c.toString();
        if (data.includes("\r\n\r\n")) {
          socket.destroy();
          resolve(data);
        }
      });
      socket.on("error", reject);
    });
    expect(reply).toMatch(/^HTTP\/1\.1 413/);
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
    expect(up.connections()).toBe(0);
  });

  it("rejects an untrusted TLS certificate without sending secret material (test 18, B-P7)", async () => {
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

  it("matches a trailing-dot host to its canonical selector (test 18, B-P2)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, exercises } = await liveBroker([`localhost:${up.port}`]);
    const res = await proxyRequest(broker, `http://localhost.:${up.port}/`, { headers: { Authorization: "none" } });
    // Allowlisted, so with no Placeholder the request is relayed as is.
    expect(exercises).toHaveLength(0);
    expect(res.status).not.toBe(403);
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

  it("answers 503 with Retry-After while the installation is in maintenance (ADR-0036 D6)", async () => {
    const up = await upstream();
    cleanups.push(up.close);
    const placeholder = generatePlaceholder();
    const broker = await startBroker({
      placeholders: new Map([[placeholder, "STRIPE_KEY"]]),
      destinations: [`127.0.0.1:${up.port}`],
      targets: DEFAULT_TARGETS,
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

  it("Node's fetch reaches the Broker with NODE_USE_ENV_PROXY=1, and absolute-URI requests still substitute (test 10)", async () => {
    const decoy = await upstream(undefined, false);
    cleanups.push(decoy.close);
    const up = await upstream();
    cleanups.push(up.close);
    const { broker, placeholder } = await liveBroker([`127.0.0.1:${up.port}`, "api.example.com:443"], { strict: true });
    const env = buildAgentEnv(
      { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: join(certDir, "cert"), NO_PROXY: "internal.example" },
      { environmentId: "e", items: [] },
      new Map(),
      broker.proxyUrl,
    );
    expect(env.NO_PROXY).toBe(`internal.example,127.0.0.1:${broker.port}`);
    // Plain HTTP fetch goes through the Broker (strict mode answers it);
    // HTTPS fetch to an allowlisted destination is tunnelled with CONNECT,
    // which the Broker refuses rather than letting it bypass; the
    // absolute-URI form a Node Agent uses for substitution keeps working.
    const script = `
      import http from "node:http";
      const r = await fetch("http://127.0.0.1:${decoy.port}/direct", { headers: { authorization: "${placeholder}" } });
      console.log("http", r.status, (await r.text()).trim());
      try { await fetch("https://api.example.com/x"); console.log("https reached"); }
      catch { console.log("https refused"); }
      const proxy = new URL(process.env.HTTPS_PROXY);
      const auth = "Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64");
      const status = await new Promise((resolve, reject) => {
        const req = http.request({ host: proxy.hostname, port: proxy.port, path: "https://127.0.0.1:${up.port}/manual",
          headers: { "Proxy-Authorization": auth, Authorization: "Bearer ${placeholder}" } },
          (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
        req.on("error", reject);
        req.end();
      });
      console.log("manual", status);
    `;
    const out = await new Promise<string>((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], { env, stdio: ["ignore", "pipe", "pipe"] });
      let text = "";
      child.stdout.on("data", (c: Buffer) => (text += c.toString()));
      child.stderr.on("data", (c: Buffer) => (text += c.toString()));
      child.on("exit", () => resolve(text));
    });
    expect(out).toContain("http 403 varlatch-broker: destination 127.0.0.1");
    expect(out).toContain("https refused");
    expect(out).toContain("manual 200");
    expect(decoy.connections()).toBe(0);
    expect(up.received.map((r) => [r.url, r.headers.authorization])).toEqual([["/manual", "Bearer sk_live_1"]]);
  });
});
