// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { checkTailnet, type ServerDoctorInput } from "../src/doctor.js";
import { buildApp } from "../src/http/app.js";
import type { NodeCertificate } from "../src/tailnet/cert.js";
import { LISTENERS_STATUS_FILE, readListenerReport, TailnetObserver, type TailnetListenerReport } from "../src/tailnet/observe.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * What varlatchd reports about its tailnet listeners (ADR-0046, Listener
 * metadata): configuration, and what it observed with the time, never
 * reachability; to Installation Admins over the API and to `admin doctor`
 * through the state volume.
 */

const HOST = "varlatch.example.ts.net";

describe("tailnet listener observer", () => {
  let server: http.Server;
  let socketPath: string;
  let status: { code: number; body: unknown };

  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.` } } };
    server = http.createServer((_req, res) => {
      res.writeHead(status.code, { "Content-Type": "application/json" });
      res.end(JSON.stringify(status.body));
    });
    await new Promise<void>((r) => server.listen(socketPath, r));
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await new Promise((r) => server.close(r));
  });

  const certificate = (valid: boolean) =>
    ({
      context: () => (valid ? ({} as object) : null),
      status: () => ({ notAfter: valid ? "2027-01-05T00:00:00.000Z" : null, lastError: null, checkedAt: null }),
    }) as unknown as NodeCertificate;
  const observer = (opts: { browser?: boolean; valid?: boolean; stateDir?: string | null; now?: () => number } = {}) =>
    new TailnetObserver({
      socketPath,
      expectedTailnet: "example.ts.net",
      listenerPort: 8687,
      browser: opts.browser === false ? null : { host: HOST, port: 8688 },
      certificate: opts.browser === false ? null : certificate(opts.valid ?? true),
      stateDir: opts.stateDir ?? null,
      ...(opts.now ? { now: opts.now } : {}),
    });

  it("says unknown before the first check, then what it observed, and never reachability", async () => {
    const o = observer();
    expect(o.report()).toEqual({
      configured: { tailnet: "example.ts.net", listenerPort: 8687, browserEndpoint: `https://${HOST}:8688` },
      observed: {
        checkedAt: null,
        checks: {
          listener: { status: "unknown", reason: "NOT_CHECKED" },
          browserTls: { status: "unknown", reason: "NOT_CHECKED" },
          localApi: { status: "unknown", reason: "NOT_CHECKED" },
          node: { status: "unknown", reason: "NOT_CHECKED" },
        },
      },
    });
    o.listening("plain", true);
    o.listening("browser", true);
    const report = await o.check();
    expect(report.observed.checks).toEqual({
      listener: { status: "pass" },
      browserTls: { status: "pass", certificateNotAfter: "2027-01-05T00:00:00.000Z" },
      localApi: { status: "pass" },
      node: { status: "pass" },
    });
    expect(report.observed.checkedAt).not.toBeNull();
    expect(JSON.stringify(report)).not.toMatch(/reachab/i);
  });

  it("names each failure with a fixed reason", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const o = observer({ valid: false });
    o.listening("plain", true);
    o.listening("browser", false);
    let r = await o.check();
    expect(r.observed.checks.listener).toEqual({ status: "fail", reason: "NOT_LISTENING" });
    expect(r.observed.checks.browserTls).toEqual({ status: "fail", reason: "NO_CERTIFICATE" });

    status = { code: 200, body: { BackendState: "NeedsLogin", MagicDNSSuffix: "example.ts.net", Self: { DNSName: `${HOST}.` } } };
    expect((await o.check()).observed.checks.node).toEqual({ status: "fail", reason: "NOT_RUNNING" });
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "other.ts.net", Self: { DNSName: "varlatch.other.ts.net." } } };
    expect((await o.check()).observed.checks.node).toEqual({ status: "fail", reason: "OTHER_TAILNET" });
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { DNSName: "varlatch-1.example.ts.net." } } };
    expect((await o.check()).observed.checks.node).toEqual({ status: "fail", reason: "NAME_CHANGED" });
    status = { code: 500, body: "boom" };
    r = await o.check();
    expect(r.observed.checks.localApi).toEqual({ status: "fail", reason: "LOCALAPI_UNAVAILABLE" });
    // The node cannot be judged without the LocalAPI.
    expect(r.observed.checks.node).toEqual({ status: "unknown", reason: "NOT_CHECKED" });
  });

  it("review: a delayed startup check cannot replace a bound listener with its older snapshot", async () => {
    server.removeAllListeners("request");
    let first: http.ServerResponse | undefined;
    let count = 0;
    server.on("request", (_req, res) => {
      if (++count === 1) { first = res; return; }
      res.writeHead(status.code, { "Content-Type": "application/json" });
      res.end(JSON.stringify(status.body));
    });
    const o = observer({ browser: false });
    const older = o.check();
    await vi.waitFor(() => expect(first).toBeDefined());
    o.listening("plain", true);
    await o.check();
    expect(o.report().observed.checks.listener).toEqual({ status: "pass" });
    first!.writeHead(status.code, { "Content-Type": "application/json" });
    first!.end(JSON.stringify(status.body));
    await older;
    expect(o.report().observed.checks.listener).toEqual({ status: "pass" });
  });

  it("reports the node as it read it, under observed, with the shared checkedAt", async () => {
    status = {
      code: 200,
      body: {
        BackendState: "Running",
        MagicDNSSuffix: "Example.ts.net",
        Self: { ID: "nExampleNode1CNTRL", DNSName: `Varlatch.Example.ts.net.`, Tags: ["tag:server", "tag:varlatch"], TailscaleIPs: ["fd7a:115c:a1e0::7", "100.64.0.7"] },
      },
    };
    const o = observer({ browser: false });
    expect(o.report().observed).not.toHaveProperty("node");
    const r = await o.check();
    expect(r.observed.node).toEqual({
      name: "varlatch",
      dnsName: "varlatch.example.ts.net",
      tailnet: "example.ts.net",
      tags: ["tag:server", "tag:varlatch"],
      addresses: ["100.64.0.7", "fd7a:115c:a1e0::7"],
      nodeId: "nExampleNode1CNTRL",
    });
    // One time for the whole report: the node has none of its own.
    expect(Object.keys(r.observed).sort()).toEqual(["checkedAt", "checks", "node"]);
  });

  it("omits what is absent or malformed, and a list with any bad entry, instead of guessing", async () => {
    status = {
      code: 200,
      body: { BackendState: "Running", MagicDNSSuffix: 7, Self: { ID: "bad id!", DNSName: "not a name.", Tags: ["tag:ok", 5], TailscaleIPs: ["100.64.0.7", "nope"] } },
    };
    const o = observer({ browser: false });
    expect((await o.check()).observed).not.toHaveProperty("node");
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { DNSName: `${HOST}.`, Tags: null, TailscaleIPs: [] } } };
    expect((await o.check()).observed.node).toEqual({ name: "varlatch", dnsName: HOST, tailnet: "example.ts.net" });
  });

  it("review: validates tags as Tailscale does, a letter first, and drops the whole list for one bad tag", async () => {
    const o = observer({ browser: false });
    const withTags = (Tags: unknown) => ({ code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.`, Tags } } });
    // tailcfg.CheckTag: the name must start with a letter, so one such tag drops the whole list.
    status = withTags(["tag:server", "tag:123"]);
    expect((await o.check()).observed.node).not.toHaveProperty("tags");
    for (const bad of [["tag:"], ["tag:-x"], ["server"], ["tag:a_b"], ["tag:é"]]) {
      status = withTags(bad);
      expect((await o.check()).observed.node, JSON.stringify(bad)).not.toHaveProperty("tags");
    }
  });

  it("review: keeps a long valid tag: Tailscale sets no length limit", async () => {
    const o = observer({ browser: false });
    const long = `tag:a${"b1-".repeat(100)}`;
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.`, Tags: ["tag:server", long, "tag:A9"] } } };
    expect((await o.check()).observed.node?.tags).toEqual(["tag:server", long, "tag:A9"]);
  });

  it("clears the node after a failed read: stale details never sit next to a failing check", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const o = observer({ browser: false });
    expect((await o.check()).observed.node?.nodeId).toBe("nSELF");
    status = { code: 500, body: "boom" };
    const failed = await o.check();
    expect(failed.observed.checks.localApi).toEqual({ status: "fail", reason: "LOCALAPI_UNAVAILABLE" });
    expect(failed.observed).not.toHaveProperty("node");
  });

  it("an older check that ends late cannot replace newer node details", async () => {
    server.removeAllListeners("request");
    let held: { res: http.ServerResponse; body: unknown } | undefined;
    let count = 0;
    server.on("request", (_req, res) => {
      if (++count === 1) { held = { res, body: status.body }; return; }
      res.writeHead(status.code, { "Content-Type": "application/json" });
      res.end(JSON.stringify(status.body));
    });
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.`, Tags: ["tag:old"] } } };
    const o = observer({ browser: false });
    const older = o.check();
    await vi.waitFor(() => expect(held).toBeDefined());
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.`, Tags: ["tag:new"] } } };
    expect((await o.check()).observed.node?.tags).toEqual(["tag:new"]);
    held!.res.writeHead(200, { "Content-Type": "application/json" });
    held!.res.end(JSON.stringify(held!.body));
    await older;
    expect(o.report().observed.node?.tags).toEqual(["tag:new"]);
  });

  it("rewrites the file for `admin doctor` when only the node changes", async () => {
    const write = vi.fn();
    const o = new TailnetObserver({ socketPath, expectedTailnet: "example.ts.net", listenerPort: 8687, browser: null, certificate: null, stateDir: mkdtempSync(join(tmpdir(), "varlatch-state-")), write });
    o.listening("plain", true);
    await o.check();
    expect(write).toHaveBeenCalledOnce();
    status = { code: 200, body: { BackendState: "Running", MagicDNSSuffix: "example.ts.net", Self: { ID: "nSELF", DNSName: `${HOST}.`, Tags: ["tag:server"] } } };
    await o.check();
    expect(write).toHaveBeenCalledTimes(2);
    expect((write.mock.calls[1]![1] as TailnetListenerReport).observed.node?.tags).toEqual(["tag:server"]);
  });

  it("checks again as soon as a listener binds, not at the next minute (real-tailnet finding)", async () => {
    const o = observer({ browser: false });
    o.start();
    try {
      await vi.waitFor(() => expect(o.report().observed.checks.localApi.status).toBe("pass"));
      // Started before the listener bound, as varlatchd does: unknown until it binds.
      expect(o.report().observed.checks.listener).toEqual({ status: "unknown", reason: "NOT_CHECKED" });
      o.listening("plain", true);
      await vi.waitFor(() => expect(o.report().observed.checks.listener).toEqual({ status: "pass" }));
    } finally {
      o.stop();
    }
  });

  it("has no browserTls check, and no endpoint, while the browser endpoint is off", async () => {
    const o = observer({ browser: false });
    o.listening("plain", true);
    const r = await o.check();
    expect(r.configured.browserEndpoint).toBeNull();
    expect(r.observed.checks).not.toHaveProperty("browserTls");
    expect(r.observed.checks.listener).toEqual({ status: "pass" });
  });

  it("writes the report for `admin doctor` on change, and at least every five minutes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-state-"));
    let now = Date.parse("2026-10-09T10:00:00Z");
    const write = vi.fn();
    const o = new TailnetObserver({
      socketPath,
      expectedTailnet: "example.ts.net",
      listenerPort: 8687,
      browser: null,
      certificate: null,
      stateDir: dir,
      write,
      now: () => now,
    });
    o.listening("plain", true);
    await o.check();
    await o.check();
    expect(write).toHaveBeenCalledOnce();
    expect(write.mock.calls[0]![0]).toBe(join(dir, LISTENERS_STATUS_FILE));
    now += 6 * 60_000;
    await o.check();
    expect(write).toHaveBeenCalledTimes(2);
    status = { code: 200, body: { BackendState: "Stopped", MagicDNSSuffix: "example.ts.net", Self: {} } };
    await o.check();
    expect(write).toHaveBeenCalledTimes(3);
    // The real writer, read back.
    const real = new TailnetObserver({ socketPath, expectedTailnet: "example.ts.net", listenerPort: 8687, browser: null, certificate: null, stateDir: dir });
    await real.check();
    expect(readListenerReport(dir)?.configured.listenerPort).toBe(8687);
  });
});

describe("GET /v1/installation/listeners", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let adminToken: string;
  let memberToken: string;
  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
    adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
    await ctx.db.query("INSERT INTO identities(id, kind, name, installation_admin) VALUES ('id_member','human','Member',false)");
    memberToken = (await issueCredential(ctx.db, { identityId: "id_member", kind: "cli" })).token;
  });
  afterEach(async () => {
    await ctx.close();
  });

  const report: TailnetListenerReport = {
    configured: { tailnet: "example.ts.net", listenerPort: 8687, browserEndpoint: `https://${HOST}:8688` },
    observed: { checkedAt: "2026-10-09T10:15:00.000Z", checks: { listener: { status: "pass" }, localApi: { status: "pass" }, node: { status: "fail", reason: "NOT_RUNNING" } } },
  };

  it("gives Installation Admins configuration and observations, and refuses everyone else", async () => {
    const app = buildApp(ctx, { tailnetListeners: () => report });
    const res = await app.request("/v1/installation/listeners", { headers: { Authorization: `Bearer ${adminToken}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ tailnet: report });
    expect((await app.request("/v1/installation/listeners")).status).toBe(401);
    expect((await app.request("/v1/installation/listeners", { headers: { Authorization: `Bearer ${memberToken}` } })).status).toBe(403);
  });

  it("says null without a tailnet listener", async () => {
    const res = await buildApp(ctx).request("/v1/installation/listeners", { headers: { Authorization: `Bearer ${adminToken}` } });
    expect(await res.json()).toEqual({ tailnet: null });
  });
});

describe("admin doctor: tailnet checks", () => {
  const now = Date.parse("2026-10-09T10:20:00Z");
  const base = { ctx: null, db: {} as ServerDoctorInput["db"], stateDir: "/nonexistent", publicUrl: undefined, convexUrl: undefined, now: () => now };
  const fresh = (checks: TailnetListenerReport["observed"]["checks"], endpoint: string | null = `https://${HOST}:8688`): TailnetListenerReport => ({
    configured: { tailnet: "example.ts.net", listenerPort: 8687, browserEndpoint: endpoint },
    observed: { checkedAt: "2026-10-09T10:19:00.000Z", checks },
  });
  const pass = { status: "pass" as const };

  it("checks nothing without Tailscale", () => {
    expect(checkTailnet({ ...base, tailnet: null })).toEqual([]);
  });

  it("is unknown, never pass, without a recent report", () => {
    for (const read of [() => null, () => ({ ...fresh({ listener: pass, localApi: pass, node: pass }), observed: { checkedAt: "2026-10-09T10:00:00.000Z", checks: { listener: pass, localApi: pass, node: pass } } })]) {
      const checks = checkTailnet({ ...base, tailnet: { browserEndpoint: `https://${HOST}:8688` }, readListeners: read });
      expect(checks.map((c) => [c.id, c.status])).toEqual([
        ["tailnet.listener", "unknown"],
        ["tailnet.browser-endpoint", "unknown"],
      ]);
    }
  });

  it("passes what varlatchd observed, and leaves browser reachability unknown", () => {
    const checks = checkTailnet({
      ...base,
      tailnet: { browserEndpoint: `https://${HOST}:8688` },
      readListeners: () => fresh({ listener: pass, browserTls: { status: "pass", certificateNotAfter: "2027-01-05T00:00:00.000Z" }, localApi: pass, node: pass }),
    });
    expect(checks.map((c) => [c.id, c.status, c.class])).toEqual([
      ["tailnet.listener", "pass", "advisory"],
      ["tailnet.browser-endpoint", "pass", "advisory"],
      ["tailnet.browser-reachability", "unknown", "advisory"],
    ]);
    expect(checks[1]!.detail).toContain("2027-01-05");
  });

  it("names failures with a remedy; a missing certificate points at setup", () => {
    const checks = checkTailnet({
      ...base,
      tailnet: { browserEndpoint: `https://${HOST}:8688` },
      readListeners: () => fresh({ listener: pass, browserTls: { status: "fail", reason: "NO_CERTIFICATE" }, localApi: pass, node: { status: "fail", reason: "NAME_CHANGED" } }),
    });
    expect(checks[0]).toMatchObject({ id: "tailnet.listener", status: "fail" });
    expect(checks[0]!.detail).toContain("no longer the browser endpoint's host");
    expect(checks[1]).toMatchObject({ id: "tailnet.browser-endpoint", status: "fail" });
    expect(checks[1]!.remedy).toContain("varlatch setup --tailnet-endpoint");
  });

  it("reports only the listener while the browser endpoint is off", () => {
    const checks = checkTailnet({ ...base, tailnet: { browserEndpoint: null }, readListeners: () => fresh({ listener: pass, localApi: pass, node: pass }, null) });
    expect(checks.map((c) => c.id)).toEqual(["tailnet.listener"]);
  });
});
