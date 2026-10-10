// SPDX-License-Identifier: AGPL-3.0-or-later
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import type { ServerType } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { decodePair, NodeCertificate } from "../src/tailnet/cert.js";
import { serveTailnetHttps, tailnetResolver } from "../src/tailnet/listener.js";
import { localApiGet } from "../src/tailnet/localapi.js";
import { selfNodeResolver } from "../src/tailnet/whois.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The tailnet browser endpoint (ADR-0046) on a real TLS socket, with the
 * production resolver wiring and a fake LocalAPI that knows a device only
 * by the test client's own local port: what the endpoint checks is the
 * socket peer, never anything the request says.
 */

const HOST = "varlatch.example.ts.net";
const ORIGIN = "https://varlatch.example.com";
const ENV_PATH = "/v1/organizations/acme/projects/api/environments/production";

type Pair = { key: string; cert: string };

/** A self-signed pair for `names`, valid from now for `days`. */
function makePair(names: string[], days = 30): Pair {
  const dir = mkdtempSync(join(tmpdir(), "tailnet-cert-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", String(days),
    "-subj", `/CN=${names[0]}`, "-addext", `subjectAltName=${names.map((n) => `DNS:${n}`).join(",")}`,
  ], { stdio: "ignore" });
  return { key: readFileSync(join(dir, "key.pem"), "utf8"), cert: readFileSync(join(dir, "cert.pem"), "utf8") };
}

interface Device {
  StableID: string;
  Name: string;
  Tags?: string[];
  Sharer?: number;
}

describe("tailnet browser endpoint", () => {
  let pair: Pair;
  let localApi: http.Server;
  let socketPath: string;
  /** WhoIs answers, by the exact addr:port the endpoint asked about. */
  let devices: Map<string, Device>;
  let whoisAsked: string[];
  let whoisDown: boolean;
  let certAnswer: { status: number; body: string };
  let certQueries: string[];

  let ctx: AppCtx & { close: () => Promise<void> };
  let adminToken: string;
  let certificate: NodeCertificate;
  let server: ServerType;
  let port: number;

  beforeAll(() => {
    pair = makePair([HOST]);
  });

  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    devices = new Map();
    whoisAsked = [];
    whoisDown = false;
    certAnswer = { status: 200, body: pair.key + pair.cert };
    certQueries = [];
    localApi = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://local-tailscaled.sock");
      if (url.pathname === "/localapi/v0/status") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ Self: { ID: "nSELF" } }));
      }
      if (url.pathname === "/localapi/v0/whois") {
        const addr = url.searchParams.get("addr") ?? "";
        whoisAsked.push(addr);
        if (whoisDown) return res.writeHead(500).end("down");
        const device = devices.get(addr);
        if (!device) return res.writeHead(404).end("no match");
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ Node: { Tags: [], ...device }, UserProfile: { LoginName: "jeremy@example.com" } }));
      }
      if (url.pathname.startsWith("/localapi/v0/cert/")) {
        certQueries.push(url.pathname + url.search);
        return res.writeHead(certAnswer.status).end(certAnswer.body);
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((r) => localApi.listen(socketPath, r));

    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
    adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;

    // Through the ordinary listener: a production Environment whose values
    // need a device tagged tag:prod.
    const ordinary = buildApp(ctx);
    const send = (method: string, path: string, body: unknown) =>
      ordinary.request(path, { method, headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    await send("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
    await send("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" });
    await send("POST", "/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" });
    await send("PUT", `${ENV_PATH}/values/SECRET_A`, { value: "s3cr3t" });
    const required = await send("POST", "/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    expect(required.status).toBe(201);

    certificate = new NodeCertificate({ socketPath, host: HOST });
    expect(await certificate.refresh()).toBe(true);
    // The production wiring, as serveCommand builds it.
    let app: ReturnType<typeof buildApp> | null = null;
    server = serveTailnetHttps({ fetch: (req, env) => app!.fetch(req, env), host: HOST, port: 0, certificate });
    await once(server, "listening");
    port = (server.address() as net.AddressInfo).port;
    app = buildApp(ctx, {
      clientAddress: (c) => getConnInfo(c).remote.address ?? "unknown",
      resolveTailnetContext: tailnetResolver({ socketPath, expectedTailnet: "example.ts.net", selfNodeId: selfNodeResolver(socketPath) }),
      tailnetBrowser: { host: HOST, port, origins: [ORIGIN] },
      browserEndpoint: `https://${HOST}:${port}`,
    });
  });

  afterEach(async () => {
    certificate.stop();
    await new Promise((r) => server.close(r));
    await new Promise((r) => localApi.close(r));
    await ctx.close();
  });

  /** A TLS connection to the endpoint; `device` is what WhoIs answers for its local port. */
  async function connect(opts: { device?: Device; servername?: string; anyCertificate?: boolean } = {}): Promise<tls.TLSSocket> {
    const socket = tls.connect({
      host: "127.0.0.1",
      port,
      servername: opts.servername ?? HOST,
      ...(opts.anyCertificate ? { rejectUnauthorized: false } : { ca: pair.cert }),
    });
    await once(socket, "secureConnect");
    if (opts.device) devices.set(`127.0.0.1:${socket.localPort}`, opts.device);
    return socket;
  }

  type Answer = { status: number; headers: http.IncomingHttpHeaders; body: any };

  function send(
    socket: tls.TLSSocket,
    opts: { method?: string; path: string; headers?: Record<string, string>; body?: unknown; keepAlive?: boolean },
  ): Promise<Answer> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          createConnection: () => socket,
          method: opts.method ?? "GET",
          path: opts.path,
          headers: {
            Host: `${HOST}:${port}`,
            Connection: opts.keepAlive ? "keep-alive" : "close",
            ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
            ...opts.headers,
          },
        },
        (res) => {
          let text = "";
          res.on("data", (d: Buffer) => (text += d.toString("utf8")));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: text ? JSON.parse(text) : null }));
        },
      );
      req.on("error", reject);
      if (opts.body !== undefined) req.write(JSON.stringify(opts.body));
      req.end();
    });
  }

  const call = async (opts: Parameters<typeof send>[1] & { device?: Device }) => send(await connect({ device: opts.device }), opts);

  const bearer = () => ({ Authorization: `Bearer ${adminToken}` });
  const approved: Device = { StableID: "nLAPTOP", Name: "laptop.example.ts.net.", Tags: ["tag:prod"] };
  const latestAudit = async (eventType: string) =>
    (await ctx.db.query("SELECT listener, tailnet FROM audit_events WHERE event_type = $1 ORDER BY event_order DESC LIMIT 1", [eventType]))
      .rows[0] as { listener: string | null; tailnet: unknown } | undefined;
  const count = async (eventType: string) =>
    Number((await ctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = $1", [eventType])).rows[0]!.n);
  const json = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);

  it("lets an allowlisted origin read protected values from an approved device, checked on the socket peer", async () => {
    const preflight = await call({
      method: "OPTIONS",
      path: `${ENV_PATH}/disclosures`,
      headers: { Origin: ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type" },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(preflight.headers["access-control-allow-methods"]).toBe("GET, POST");
    expect(preflight.headers["access-control-allow-headers"]).toBe("Authorization, Content-Type");
    expect(preflight.headers["access-control-allow-credentials"]).toBeUndefined();
    expect(preflight.headers["vary"]).toContain("Origin");
    // A preflight costs no WhoIs lookup.
    expect(whoisAsked).toEqual([]);

    const socket = await connect({ device: approved });
    const disclosed = await send(socket, {
      method: "POST",
      path: `${ENV_PATH}/disclosures`,
      headers: { ...bearer(), Origin: ORIGIN },
      body: { scope: "all-authorized-secrets" },
    });
    expect(disclosed.status).toBe(200);
    expect(disclosed.body.items[0]).toMatchObject({ name: "SECRET_A", value: "s3cr3t" });
    expect(disclosed.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(disclosed.headers["access-control-allow-credentials"]).toBeUndefined();
    // WhoIs was asked about exactly this connection's own local port.
    expect(whoisAsked).toEqual([`127.0.0.1:${socket.localPort}`]);
    const audit = await latestAudit("secret.disclosed");
    expect(audit?.listener).toBe("tailnet");
    expect(json(audit?.tailnet)).toEqual({ tailnet: "example.ts.net", nodeId: "nLAPTOP", nodeName: "laptop", tags: ["tag:prod"] });

    const values = await call({ path: `${ENV_PATH}/effective-configuration?include=values`, headers: { ...bearer(), Origin: ORIGIN }, device: approved });
    expect(values.status).toBe(200);
    expect(values.headers["access-control-allow-origin"]).toBe(ORIGIN);

    const device = await call({ path: "/v1/tailnet/context", headers: { ...bearer(), Origin: ORIGIN }, device: approved });
    expect(device.status).toBe(200);
    expect(device.body).toEqual({ recognized: true, tailnet: "example.ts.net", nodeId: "nLAPTOP", nodeName: "laptop", tags: ["tag:prod"] });
  });

  it("denies a device that does not match, an unknown connection, and a shared device, with errors the page can read", async () => {
    const other: Device = { StableID: "nDESK", Name: "desk.example.ts.net.", Tags: ["tag:dev"] };
    const mismatch = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), Origin: ORIGIN }, body: { scope: "all-authorized-secrets" }, device: other });
    expect(mismatch.status).toBe(403);
    expect(mismatch.body.error.code).toBe("TAILNET_CONTEXT_UNAVAILABLE");
    expect(mismatch.headers["access-control-allow-origin"]).toBe(ORIGIN);

    const unknown = await call({ path: `${ENV_PATH}/effective-configuration?include=values`, headers: { ...bearer(), Origin: ORIGIN } });
    expect(unknown.status).toBe(403);
    expect(unknown.body.error.code).toBe("TAILNET_CONTEXT_REQUIRED");
    expect(unknown.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(await call({ path: "/v1/tailnet/context", headers: { ...bearer(), Origin: ORIGIN } })).toMatchObject({
      status: 200,
      body: { recognized: false, reason: "unrecognized" },
    });

    const shared: Device = { ...approved, StableID: "nSHARED", Sharer: 42 };
    expect((await call({ path: "/v1/tailnet/context", headers: { ...bearer(), Origin: ORIGIN }, device: shared })).body).toEqual({
      recognized: false,
      reason: "shared",
    });
    const sharedRead = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), Origin: ORIGIN }, body: { scope: "all-authorized-secrets" }, device: shared });
    expect(sharedRead.body.error.code).toBe("TAILNET_CONTEXT_REQUIRED");
    expect(json((await latestAudit("authorization.denied"))?.tailnet)).toEqual({ refused: "shared" });
    expect(await count("secret.disclosed")).toBe(0);
  });

  it("refuses other origins, null, and every other route before the device check and authentication, without CORS headers", async () => {
    const refused = async (opts: Parameters<typeof send>[1]) => {
      const res = await call({ ...opts, device: approved });
      expect(res.status, `${opts.method ?? "GET"} ${opts.path} from ${opts.headers?.Origin}`).toBe(403);
      expect(res.body.error.code).toBe("PERMISSION_DENIED");
      expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    };
    const disclosure = { method: "POST", path: `${ENV_PATH}/disclosures`, body: { scope: "all-authorized-secrets" } };
    await refused({ ...disclosure, headers: { ...bearer(), Origin: "https://evil.example.com" } });
    await refused({ ...disclosure, headers: { ...bearer(), Origin: "null" } });
    await refused({ ...disclosure, headers: { ...bearer(), Origin: `${ORIGIN}.evil.example.com` } });
    await refused({ ...disclosure, headers: { ...bearer(), Origin: "http://varlatch.example.com" } });
    await refused({ method: "OPTIONS", path: disclosure.path, headers: { Origin: "https://evil.example.com", "Access-Control-Request-Method": "POST" } });
    // An allowlisted origin, but not a browser read route.
    await refused({ method: "PUT", path: `${ENV_PATH}/values/SECRET_A`, headers: { ...bearer(), Origin: ORIGIN }, body: { value: "x" } });
    await refused({ method: "OPTIONS", path: `${ENV_PATH}/values/SECRET_A`, headers: { Origin: ORIGIN, "Access-Control-Request-Method": "PUT" } });
    await refused({ method: "POST", path: "/v1/tokens/convex", headers: { ...bearer(), Origin: ORIGIN }, body: {} });
    await refused({ path: "/v1/organizations", headers: { ...bearer(), Origin: ORIGIN } });
    await refused({ path: `${ENV_PATH}/effective-configuration/extra`, headers: { ...bearer(), Origin: ORIGIN } });
    await refused({ method: "GET", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), Origin: ORIGIN } });
    // None of them reached the device check, authentication, or a disclosure.
    expect(whoisAsked).toEqual([]);
    expect(await count("secret.disclosed")).toBe(0);
    expect(await count("authentication.failed")).toBe(0);
  });

  it("leaves requests without Origin (the CLI, scripts) as the tailnet listener answers them", async () => {
    const res = await call({ path: "/v1/organizations", headers: bearer(), device: approved });
    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    const disclosed = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: bearer(), body: { scope: "all-authorized-secrets" }, device: approved });
    expect(disclosed.status).toBe(200);
  });

  it("answers a missing or invalid bearer with 401 the page can read; cookies never authenticate", async () => {
    const none = await call({ path: "/v1/tailnet/context", headers: { Origin: ORIGIN }, device: approved });
    expect(none.status).toBe(401);
    expect(none.headers["access-control-allow-origin"]).toBe(ORIGIN);
    const cookie = await call({ path: `${ENV_PATH}/effective-configuration?include=values`, headers: { Origin: ORIGIN, Cookie: "better-auth.session_token=anything" }, device: approved });
    expect(cookie.status).toBe(401);
    const invalid = await call({ path: "/v1/tailnet/context", headers: { Origin: ORIGIN, Authorization: "Bearer vl_not-a-credential" }, device: approved });
    expect(invalid.status).toBe(401);
    expect(invalid.headers["access-control-allow-origin"]).toBe(ORIGIN);
  });

  it("answers only as the node's own name", async () => {
    const wrongHost = await send(await connect({ device: approved }), { path: "/v1/tailnet/context", headers: { ...bearer(), Host: "evil.example.com" } });
    expect(wrongHost.status).toBe(403);
    expect(whoisAsked).toEqual([]);
    // Bare name (port 443 in front of it) is the same host.
    expect((await send(await connect({ device: approved }), { path: "/v1/tailnet/context", headers: { ...bearer(), Host: HOST } })).status).toBe(200);
    // Another name, or none at all, gets no handshake: the server refuses,
    // even for a client that would accept any certificate.
    await expect(connect({ servername: "other.example.ts.net", anyCertificate: true })).rejects.toThrow();
    await expect(connect({ servername: "", anyCertificate: true })).rejects.toThrow();
    (await connect({ anyCertificate: true })).destroy();
  });

  it("changes nothing for spoofed identity: forwarding headers, Tailscale headers, a PROXY preamble", async () => {
    const spoof = {
      "X-Forwarded-For": "100.64.0.7",
      Forwarded: "for=100.64.0.7",
      "X-Real-IP": "100.64.0.7",
      "Tailscale-User-Login": "admin@example.com",
      "Tailscale-User-Name": "Admin",
      "Tailscale-App-Capabilities": JSON.stringify({ "example.com/cap/varlatch": [{}] }),
    };
    const denied = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), ...spoof, Origin: ORIGIN }, body: { scope: "all-authorized-secrets" } });
    expect(denied.body.error.code).toBe("TAILNET_CONTEXT_REQUIRED");
    const allowed = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), ...spoof, Origin: ORIGIN }, body: { scope: "all-authorized-secrets" }, device: approved });
    expect(allowed.status).toBe(200);
    expect(json((await latestAudit("secret.disclosed"))?.tailnet)).toMatchObject({ nodeId: "nLAPTOP" });

    // A PROXY protocol preamble is not TLS: the connection ends with no HTTP answer.
    const raw = net.connect(port, "127.0.0.1");
    await once(raw, "connect");
    raw.write("PROXY TCP4 100.64.0.7 127.0.0.1 51000 8688\r\nGET /v1/tailnet/context HTTP/1.1\r\nHost: x\r\n\r\n");
    let received = "";
    raw.on("data", (d: Buffer) => (received += d.toString("latin1")));
    raw.on("error", () => {});
    await once(raw, "close");
    expect(received).not.toContain("HTTP/1.1");
  });

  it("fails closed when the LocalAPI cannot answer, while unconstrained reads still work", async () => {
    whoisDown = true;
    const denied = await call({ method: "POST", path: `${ENV_PATH}/disclosures`, headers: { ...bearer(), Origin: ORIGIN }, body: { scope: "all-authorized-secrets" }, device: approved });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe("TAILNET_CONTEXT_REQUIRED");
    expect(json((await latestAudit("authorization.denied"))?.tailnet)).toEqual({ refused: "resolver-unavailable" });
    const metadata = await call({ path: `${ENV_PATH}/effective-configuration`, headers: { ...bearer(), Origin: ORIGIN }, device: approved });
    expect(metadata.status).toBe(200);
    expect(metadata.headers["access-control-allow-origin"]).toBe(ORIGIN);
  });

  it("keeps open connections across a certificate swap, and new connections get the new one", async () => {
    const before = await connect({ device: approved });
    const firstSerial = before.getPeerCertificate().serialNumber;
    pair = makePair([HOST]);
    certAnswer = { status: 200, body: pair.key + pair.cert };
    expect(await certificate.refresh()).toBe(true);
    const old = await send(before, { path: "/v1/tailnet/context", headers: bearer() });
    expect(old.status).toBe(200);
    const after = await connect({ device: approved });
    expect(after.getPeerCertificate().serialNumber).not.toBe(firstSerial);
    after.destroy();
  });

  it("refuses every handshake while no valid certificate is loaded", async () => {
    const cold = new NodeCertificate({ socketPath, host: HOST });
    certAnswer = { status: 403, body: "cert access denied" };
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(await cold.refresh()).toBe(false);
    expect(cold.context()).toBeNull();
    expect(cold.status()).toMatchObject({
      notAfter: null,
      lastError: "tailscaled refused (403): varlatchd's user needs certificate permission (TS_PERMIT_CERT_UID)",
    });
    const coldServer = serveTailnetHttps({ fetch: () => new Response("never"), host: HOST, port: 0, certificate: cold });
    await once(coldServer, "listening");
    const coldPort = (coldServer.address() as net.AddressInfo).port;
    const attempt = tls.connect({ host: "127.0.0.1", port: coldPort, servername: HOST, rejectUnauthorized: false });
    await expect(once(attempt, "secureConnect")).rejects.toThrow();
    await new Promise((r) => coldServer.close(r));
    warn.mockRestore();
  });

  it("stops serving a certificate once it expires", async () => {
    let now = Date.now();
    const clocked = new NodeCertificate({ socketPath, host: HOST, now: () => now });
    expect(await clocked.refresh()).toBe(true);
    expect(clocked.context()).not.toBeNull();
    now += 31 * 86_400_000;
    expect(clocked.context()).toBeNull();
  });
});

describe("node certificate", () => {
  let localApi: http.Server;
  let socketPath: string;
  let answer: { status: number; body: string };
  let queries: string[];

  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    queries = [];
    localApi = http.createServer((req, res) => {
      queries.push(req.url ?? "");
      res.writeHead(answer.status).end(answer.body);
    });
    await new Promise<void>((r) => localApi.listen(socketPath, r));
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await new Promise((r) => localApi.close(r));
  });

  it("uses only a pair that names the host, is valid now, and whose key matches", () => {
    const good = makePair([HOST]);
    const now = Date.now();
    expect(typeof decodePair(good.key + good.cert, HOST, now)).toBe("object");
    expect(decodePair(good.key + good.cert, "other.example.ts.net", now)).toBe("the certificate does not name other.example.ts.net");
    expect(decodePair(good.key + good.cert, HOST, now + 40 * 86_400_000)).toBe("the certificate is not valid now");
    expect(decodePair(makePair([HOST]).key + good.cert, HOST, now)).toBe("the key does not match the certificate");
    expect(decodePair(good.cert, HOST, now)).toBe("the answer is not one key with a certificate");
    expect(decodePair("not pem", HOST, now)).toBe("the answer is not one key with a certificate");
    // Tailscale issues node certificates for the exact name; a wildcard is not this node's.
    const wildcard = makePair(["*.example.ts.net"]);
    expect(decodePair(wildcard.key + wildcard.cert, HOST, now)).toBe(`the certificate does not name ${HOST}`);
  });

  it("says when a different certificate is swapped in, so its observer checks at once (real-tailnet finding)", async () => {
    const pair = makePair([HOST]);
    answer = { status: 200, body: pair.key + pair.cert };
    vi.spyOn(console, "log").mockImplementation(() => {});
    let changes = 0;
    const cert = new NodeCertificate({ socketPath, host: HOST, onChange: () => changes++ });
    expect(await cert.refresh()).toBe(true);
    expect(await cert.refresh()).toBe(true);
    expect(changes).toBe(1);
    const next = makePair([HOST], 60);
    answer = { status: 200, body: next.key + next.cert };
    expect(await cert.refresh()).toBe(true);
    expect(changes).toBe(2);
    answer = { status: 500, body: "" };
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(await cert.refresh()).toBe(false);
    expect(changes).toBe(2);
  });

  it("asks for early renewal only once it knows the lifetime, and never for more than a fresh certificate gives", async () => {
    const pair = makePair([HOST], 90);
    answer = { status: 200, body: pair.key + pair.cert };
    const cert = new NodeCertificate({ socketPath, host: HOST });
    vi.spyOn(console, "log").mockImplementation(() => {});
    expect(await cert.refresh()).toBe(true);
    expect(await cert.refresh()).toBe(true);
    expect(queries).toEqual([
      `/localapi/v0/cert/${HOST}?type=pair`,
      // A third of 90 days is 30 days; at most a week is asked.
      `/localapi/v0/cert/${HOST}?type=pair&min_validity=168h`,
    ]);
    const short = makePair([HOST], 6);
    answer = { status: 200, body: short.key + short.cert };
    expect(await cert.refresh()).toBe(true);
    expect(await cert.refresh()).toBe(true);
    // A six-day certificate: a third of its lifetime, 48 hours.
    expect(queries.at(-1)).toBe(`/localapi/v0/cert/${HOST}?type=pair&min_validity=48h`);
  });

  it("keeps the last valid certificate when renewal fails, logs each reason once, and never logs key material", async () => {
    const pair = makePair([HOST]);
    answer = { status: 200, body: pair.key + pair.cert };
    const logged: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void logged.push(a.join(" ")));
    vi.spyOn(console, "warn").mockImplementation((...a: unknown[]) => void logged.push(a.join(" ")));
    const cert = new NodeCertificate({ socketPath, host: HOST });
    expect(await cert.refresh()).toBe(true);
    answer = { status: 500, body: "acme: rate limited" };
    expect(await cert.refresh()).toBe(false);
    expect(await cert.refresh()).toBe(false);
    expect(cert.context()).not.toBeNull();
    expect(cert.status().lastError).toBe("tailscaled answered 500");
    answer = { status: 200, body: makePair(["other.example.ts.net"]).key + pair.cert };
    expect(await cert.refresh()).toBe(false);
    expect(logged.filter((l) => l.includes("answered 500"))).toHaveLength(1);
    expect(logged.join("\n")).not.toMatch(/PRIVATE KEY|BEGIN/);
  });
});

describe("browser endpoint review regressions", () => {
  let localApi: http.Server;
  let socketPath: string;
  let handler: http.RequestListener;
  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    localApi = http.createServer((req, res) => handler(req, res));
    await new Promise<void>((r) => localApi.listen(socketPath, r));
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    localApi.closeAllConnections();
    await new Promise((r) => localApi.close(r));
  });

  for (const version of ["TLSv1.2", "TLSv1.3"] as const) {
    it(`never resumes a ${version} session, so an expired certificate refuses every connection (review regression)`, async () => {
      const pair = makePair([HOST]);
      handler = (_req, res) => res.writeHead(200).end(pair.key + pair.cert);
      vi.spyOn(console, "log").mockImplementation(() => {});
      let now = Date.now();
      const certificate = new NodeCertificate({ socketPath, host: HOST, now: () => now });
      expect(await certificate.refresh()).toBe(true);
      const server = serveTailnetHttps({ fetch: () => new Response("ok"), host: HOST, port: 0, certificate });
      await once(server, "listening");
      const port = (server.address() as net.AddressInfo).port;
      const sockets: tls.TLSSocket[] = [];
      // One request on a connection that offers `session`; what it saved, and whether it resumed.
      const visit = async (session?: Buffer) => {
        const socket = tls.connect({ host: "127.0.0.1", port, servername: HOST, rejectUnauthorized: false, minVersion: version, maxVersion: version, session });
        sockets.push(socket);
        const saved: Buffer[] = [];
        socket.on("session", (s: Buffer) => saved.push(s));
        await once(socket, "secureConnect");
        const reused = socket.isSessionReused();
        socket.write(`GET / HTTP/1.1\r\nHost: ${HOST}:${port}\r\nConnection: close\r\n\r\n`);
        let text = "";
        socket.on("data", (d: Buffer) => (text += d.toString("latin1")));
        await once(socket, "close");
        expect(text).toContain("200 OK");
        return { saved: saved.at(-1) ?? socket.getSession(), reused };
      };
      try {
        const first = await visit();
        expect(first.saved).toBeDefined();
        const second = await visit(first.saved);
        expect(second.reused).toBe(false);
        now += 31 * 86_400_000;
        expect(certificate.context()).toBeNull();
        await expect(visit(second.saved ?? first.saved)).rejects.toThrow();
      } finally {
        for (const socket of sockets) socket.destroy();
        await new Promise((r) => server.close(r));
      }
    });
  }

  it("settles a LocalAPI answer that ends early or never finishes, and a later certificate refresh succeeds (review regression)", async () => {
    const pair = makePair([HOST]);
    let mode: "truncate" | "trickle" | "whole" = "truncate";
    handler = (_req, res) => {
      if (mode === "whole") return res.writeHead(200).end(pair.key + pair.cert);
      res.writeHead(200, { "Content-Length": "100000" });
      res.write(pair.key.slice(0, 20));
      // Ends mid-body, or keeps the connection busy past any deadline.
      if (mode === "truncate") setTimeout(() => res.destroy(), 10);
      else {
        const drip = setInterval(() => res.write("."), 20);
        res.on("close", () => clearInterval(drip));
      }
    };
    await expect(localApiGet(socketPath, "/localapi/v0/cert/x", 1_000)).rejects.toThrow("ended early");
    mode = "trickle";
    const started = Date.now();
    await expect(localApiGet(socketPath, "/localapi/v0/cert/x", 200)).rejects.toThrow("timeout");
    expect(Date.now() - started).toBeLessThan(1_000);

    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    mode = "truncate";
    const certificate = new NodeCertificate({ socketPath, host: HOST });
    expect(await certificate.refresh()).toBe(false);
    expect(certificate.status().lastError).toContain("ended early");
    mode = "whole";
    expect(await certificate.refresh()).toBe(true);
    expect(certificate.context()).not.toBeNull();
  });

  it("never repeats a refusal's body, key material included, in the log or status (review regression)", async () => {
    const pair = makePair([HOST]);
    const logged: string[] = [];
    vi.spyOn(console, "warn").mockImplementation((...a: unknown[]) => void logged.push(a.join(" ")));
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void logged.push(a.join(" ")));
    const certificate = new NodeCertificate({ socketPath, host: HOST });
    for (const status of [500, 403, 404, 502]) {
      handler = (_req, res) => res.writeHead(status).end(`failed: ${pair.key}${pair.cert}`);
      expect(await certificate.refresh()).toBe(false);
      expect(certificate.status().lastError).not.toMatch(/BEGIN|PRIVATE|failed:/);
    }
    expect(logged.join("\n")).not.toMatch(/BEGIN|PRIVATE|failed:/);
    expect(logged).toHaveLength(4);
  });
});

describe("listeners without the browser endpoint", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let token: string;
  beforeAll(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
    token = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  });
  afterAll(async () => {
    await ctx.close();
  });

  it("change nothing: no CORS, no device route, on the ordinary listener or the plain tailnet listener", async () => {
    const ordinary = buildApp(ctx);
    const plainTailnet = buildApp(ctx, { resolveTailnetContext: async () => ({ tailnet: "example.ts.net", nodeId: "nX", tags: [] }) });
    for (const app of [ordinary, plainTailnet]) {
      const preflight = await app.request(`${ENV_PATH}/disclosures`, {
        method: "OPTIONS",
        headers: { Origin: ORIGIN, "Access-Control-Request-Method": "POST" },
      });
      expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
      const read = await app.request("/v1/organizations", { headers: { Authorization: `Bearer ${token}`, Origin: ORIGIN } });
      expect(read.status).toBe(200);
      expect(read.headers.get("access-control-allow-origin")).toBeNull();
      expect((await app.request("/v1/tailnet/context", { headers: { Authorization: `Bearer ${token}` } })).status).toBe(404);
    }
  });

  it("say where the endpoint is only when it is configured, and never in the unauthenticated meta", async () => {
    const off = buildApp(ctx);
    expect(await (await off.request("/v1/tailnet/endpoint", { headers: { Authorization: `Bearer ${token}` } })).json()).toEqual({ browserEndpoint: null });
    expect((await (await off.request("/v1/meta")).json()).capabilities).not.toContain("tailnet.browser-reads");
    expect((await off.request("/v1/tailnet/endpoint")).status).toBe(401);

    const on = buildApp(ctx, { browserEndpoint: `https://${HOST}:8688` });
    expect(await (await on.request("/v1/tailnet/endpoint", { headers: { Authorization: `Bearer ${token}` } })).json()).toEqual({
      browserEndpoint: `https://${HOST}:8688`,
    });
    const meta = await (await on.request("/v1/meta")).text();
    expect(JSON.parse(meta).capabilities).toContain("tailnet.browser-reads");
    expect(meta).not.toContain(HOST);
  });

  it("give each recognized device its own request window instead of sharing the forwarded 127.0.0.1", async () => {
    const app = buildApp(ctx, {
      clientAddress: () => "127.0.0.1",
      // Test-only: the device named by a header; production uses the socket peer.
      resolveTailnetContext: async (c) => ({ tailnet: "example.ts.net", nodeId: c.req.header("X-Test-Node") ?? "nA", tags: [] }),
    });
    for (let i = 0; i < 600; i++) expect((await app.request("/v1/meta", { headers: { "X-Test-Node": "nBUSY" } })).status).toBe(200);
    expect((await app.request("/v1/meta", { headers: { "X-Test-Node": "nBUSY" } })).status).toBe(429);
    expect((await app.request("/v1/meta", { headers: { "X-Test-Node": "nQUIET" } })).status).toBe(200);
  });
});
