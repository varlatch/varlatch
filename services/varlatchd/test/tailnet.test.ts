// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { whois } from "../src/tailnet/whois.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

describe("whois client", () => {
  let server: http.Server;
  let socketPath: string;
  let response: { status: number; body: unknown };

  beforeEach(async () => {
    socketPath = join(mkdtempSync(join(tmpdir(), "ts-sock-")), "tailscaled.sock");
    server = http.createServer((req, res) => {
      expect(req.url).toContain("/localapi/v0/whois?addr=");
      res.writeHead(response.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response.body));
    });
    await new Promise<void>((r) => server.listen(socketPath, r));
  });
  afterEach(async () => {
    await new Promise((r) => server.close(r));
  });

  const config = { socketPath: "", expectedTailnet: "example.ts.net" };

  it("maps a tagged node to tag-set identity with no user login", async () => {
    response = {
      status: 200,
      body: {
        Node: { StableID: "nSTABLE1", Name: "ci-runner.example.ts.net.", Tags: ["tag:ci"] },
        UserProfile: { LoginName: "tagged-devices" },
      },
    };
    const ctx = await whois({ ...config, socketPath }, "100.64.0.7", 51234);
    expect(ctx).toEqual({ tailnet: "example.ts.net", nodeId: "nSTABLE1", tags: ["tag:ci"] });
  });

  it("surfaces the user for untagged human devices", async () => {
    response = {
      status: 200,
      body: {
        Node: { StableID: "nSTABLE2", Name: "laptop.example.ts.net", Tags: [] },
        UserProfile: { LoginName: "jeremy@example.com" },
      },
    };
    const ctx = await whois({ ...config, socketPath }, "100.64.0.8", 1);
    expect(ctx).toMatchObject({ nodeId: "nSTABLE2", userLogin: "jeremy@example.com" });
  });

  it("pins the tailnet: foreign/shared peers yield no context", async () => {
    response = {
      status: 200,
      body: { Node: { StableID: "nX", Name: "peer.other.ts.net", Tags: [] } },
    };
    expect(await whois({ ...config, socketPath }, "100.64.0.9", 1)).toBeNull();
  });

  it("unknown peers (404) and unavailable LocalAPI yield no context", async () => {
    response = { status: 404, body: {} };
    expect(await whois({ ...config, socketPath }, "1.2.3.4", 1)).toBeNull();
    expect(
      await whois({ socketPath: "/nonexistent/sock", expectedTailnet: "example.ts.net" }, "1.2.3.4", 1),
    ).toBeNull();
  });
});

describe("tailnet requirements end to end", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let adminToken: string;

  beforeEach(async () => {
    const db = await testDb();
    await runMigrations(db);
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
});
