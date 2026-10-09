// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveWhois, selfNodeResolver, whois, type WhoisResult } from "../src/tailnet/whois.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

describe("whois client", () => {
  let server: http.Server;
  let socketPath: string;
  let response: { status: number; body: unknown };
  let status: { status: number; body: unknown };
  let lastAddr: string | null;

  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    status = { status: 200, body: { Self: { ID: "nSELF" } } };
    lastAddr = null;
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://local-tailscaled.sock");
      const answer = url.pathname === "/localapi/v0/status" ? status : response;
      if (url.pathname === "/localapi/v0/whois") lastAddr = url.searchParams.get("addr");
      expect(["/localapi/v0/whois", "/localapi/v0/status"]).toContain(url.pathname);
      res.writeHead(answer.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(answer.body));
    });
    await new Promise<void>((r) => server.listen(socketPath, r));
  });
  afterEach(async () => {
    await new Promise((r) => server.close(r));
  });

  const config = () => ({ socketPath, expectedTailnet: "example.ts.net", selfNodeId: selfNodeResolver(socketPath) });
  const node = (extra: Record<string, unknown>) => ({ status: 200, body: { Node: { StableID: "nPEER", Name: "laptop.example.ts.net.", Tags: [], ...extra }, UserProfile: { LoginName: "jeremy@example.com" } } });

  it("maps a tagged node to tag-set identity with no user login", async () => {
    response = {
      status: 200,
      body: {
        Node: { StableID: "nSTABLE1", Name: "ci-runner.example.ts.net.", Tags: ["tag:ci"] },
        UserProfile: { LoginName: "tagged-devices" },
      },
    };
    const ctx = await whois(config(), "127.0.0.1", 51234);
    expect(ctx).toEqual({ tailnet: "example.ts.net", nodeId: "nSTABLE1", tags: ["tag:ci"] });
  });

  it("surfaces the user for untagged human devices", async () => {
    response = node({ StableID: "nSTABLE2" });
    const ctx = await whois(config(), "127.0.0.1", 1);
    expect(ctx).toMatchObject({ nodeId: "nSTABLE2", userLogin: "jeremy@example.com" });
  });

  it("says why a peer has no context, and every reason fails closed", async () => {
    response = node({ Name: "peer.other.ts.net" });
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "other-tailnet" });
    response = { status: 404, body: {} };
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "unrecognized" });
    response = { status: 200, body: { Node: { Name: "x.example.ts.net" } } };
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "unrecognized" });
    response = { status: 500, body: {} };
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "resolver-unavailable" });
    expect(
      await resolveWhois({ socketPath: "/nonexistent/sock", expectedTailnet: "example.ts.net", selfNodeId: selfNodeResolver("/nonexistent/sock") }, "127.0.0.1", 1),
    ).toEqual({ ok: false, reason: "resolver-unavailable" });
    expect(await whois(config(), "127.0.0.1", 1)).toBeNull();
  });

  it("refuses a device shared into the tailnet, whatever its name and tags", async () => {
    // This tailnet's name and a tag a Requirement might select: still refused.
    response = node({ Name: "visitor.example.ts.net.", Tags: ["tag:prod"], Sharer: 4242 });
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "shared" });
  });

  it("refuses the Varlatch node itself, and refuses everyone while its own ID is unknown", async () => {
    response = node({ StableID: "nSELF", Name: "varlatch.example.ts.net." });
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "self" });
    status = { status: 500, body: {} };
    response = node({ StableID: "nPEER" });
    expect(await resolveWhois(config(), "127.0.0.1", 1)).toEqual({ ok: false, reason: "resolver-unavailable" });
  });

  it("brackets IPv6 peers in the WhoIs address", async () => {
    response = node({});
    await resolveWhois(config(), "fd7a:115c:a1e0::1", 443);
    expect(lastAddr).toBe("[fd7a:115c:a1e0::1]:443");
  });
});

describe("tailnet requirements end to end", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let adminToken: string;

  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
    adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  });
  afterEach(async () => {
    await ctx.close();
  });

  it("constrains production reveal to the tailnet listener with matching identity", async () => {
    const ordinary = buildApp(ctx);
    // Test-only resolver: production wiring uses socket peer + WhoIs; the
    // ordinary listener never gets a resolver at all.
    const tailnetApp = (tags: string[], tailnet = "example.ts.net") =>
      buildApp(ctx, {
        resolveTailnetContext: async () => ({ tailnet, nodeId: "nT", tags }),
      });

    const auth = { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" };
    const post = (app: ReturnType<typeof buildApp>, path: string, body: unknown) =>
      app.request(path, { method: "POST", headers: auth, body: JSON.stringify(body) });

    await post(ordinary, "/v1/organizations", { name: "Acme", slug: "acme" });
    await post(ordinary, "/v1/organizations/acme/projects", {
      name: "API",
      slug: "api",
      contractAuthority: "managed",
    });
    await post(ordinary, "/v1/organizations/acme/projects/api/environments", {
      name: "production",
      tier: "production",
    });
    await ordinary.request(
      "/v1/organizations/acme/projects/api/environments/production/values/SECRET_A",
      { method: "PUT", headers: auth, body: JSON.stringify({ value: "s3cr3t" }) },
    );

    const created = await post(ordinary, "/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    expect(created.status).toBe(201);

    const path =
      "/v1/organizations/acme/projects/api/environments/production/effective-configuration?include=values";

    // Ordinary listener: no Tailnet Context can exist -> fail closed, diagnosable.
    const denied = await ordinary.request(path, { headers: auth });
    expect(denied.status).toBe(403);
    expect((await denied.json()).error.code).toBe("TAILNET_CONTEXT_REQUIRED");

    // Tailnet listener, wrong tag -> distinct unavailable/selector error.
    const wrongTag = await tailnetApp(["tag:dev"]).request(path, { headers: auth });
    expect((await wrongTag.json()).error.code).toBe("TAILNET_CONTEXT_UNAVAILABLE");

    // Foreign tailnet never satisfies even with the right tag.
    const foreign = await tailnetApp(["tag:prod"], "other.ts.net").request(path, { headers: auth });
    expect((await foreign.json()).error.code).toBe("TAILNET_CONTEXT_UNAVAILABLE");

    // Matching tag from the pinned tailnet -> the explicit disclosure works.
    const ok = await tailnetApp(["tag:prod"]).request(
      "/v1/organizations/acme/projects/api/environments/production/disclosures",
      { method: "POST", headers: auth, body: JSON.stringify({ scope: "all-authorized-secrets" }) },
    );
    expect(ok.status).toBe(200);
    expect((await ok.json()).items[0]).toMatchObject({ name: "SECRET_A", value: "s3cr3t" });

    // Metadata on the ordinary listener stays unaffected (ADR-0014 §5).
    const metadata = await ordinary.request(
      "/v1/organizations/acme/projects/api/environments/production/effective-configuration",
      { headers: auth },
    );
    expect(metadata.status).toBe(200);

    // Revoking the requirement restores ordinary retrieval.
    const reqId = (await created.json()).id;
    await ordinary.request(`/v1/organizations/acme/requirements/${reqId}`, {
      method: "DELETE",
      headers: auth,
    });
    const after = await ordinary.request(path, { headers: auth });
    expect(after.status).toBe(200);
  });

  it("records the listener and the tailnet resolution in the audit log, refusals included", async () => {
    const ordinary = buildApp(ctx);
    const tailnetApp = (result: WhoisResult) => buildApp(ctx, { resolveTailnetContext: async () => result });
    const auth = { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" };
    const post = (app: ReturnType<typeof buildApp>, path: string, body: unknown) =>
      app.request(path, { method: "POST", headers: auth, body: JSON.stringify(body) });
    await post(ordinary, "/v1/organizations", { name: "Acme", slug: "acme" });
    await post(ordinary, "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" });
    await post(ordinary, "/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" });
    await ordinary.request("/v1/organizations/acme/projects/api/environments/production/values/SECRET_A", {
      method: "PUT",
      headers: auth,
      body: JSON.stringify({ value: "s3cr3t-value" }),
    });
    await post(ordinary, "/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    const disclose = (app: ReturnType<typeof buildApp>) =>
      post(app, "/v1/organizations/acme/projects/api/environments/production/disclosures", { scope: "all-authorized-secrets" });
    const latest = async (eventType: string) =>
      (await ctx.db.query("SELECT listener, tailnet FROM audit_events WHERE event_type = $1 ORDER BY event_order DESC LIMIT 1", [eventType])).rows[0] as {
        listener: string | null;
        tailnet: unknown;
      };
    const json = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);

    // A device shared into the tailnet: refused, denied, and the denial says why.
    const shared = await disclose(tailnetApp({ ok: false, reason: "shared" }));
    expect(shared.status).toBe(403);
    expect((await shared.json()).error.code).toBe("TAILNET_CONTEXT_REQUIRED");
    const denied = await latest("authorization.denied");
    expect(denied.listener).toBe("tailnet");
    expect(json(denied.tailnet)).toEqual({ refused: "shared" });

    // An approved device: the disclosure names the listener and the device.
    const ok = await disclose(tailnetApp({ ok: true, context: { tailnet: "example.ts.net", nodeId: "nDEVICE", tags: ["tag:prod"] } }));
    expect(ok.status).toBe(200);
    const disclosed = await latest("secret.disclosed");
    expect(disclosed.listener).toBe("tailnet");
    expect(json(disclosed.tailnet)).toEqual({ tailnet: "example.ts.net", nodeId: "nDEVICE", tags: ["tag:prod"] });

    // The ordinary listener: no tailnet resolution at all.
    expect((await disclose(ordinary)).status).toBe(403);
    const ordinaryDenied = await latest("authorization.denied");
    expect(ordinaryDenied.listener).toBe("ordinary");
    expect(ordinaryDenied.tailnet).toBeNull();
  });
});
