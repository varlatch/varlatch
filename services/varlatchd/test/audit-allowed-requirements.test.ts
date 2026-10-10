// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Allowed events for tailnet-constrained actions record which Requirement
 * each was allowed under, and by what (ADR-0046 Decision 8, issue #22), in
 * the shape denials record them: on every path that reads values, so the
 * audit log says not only from which device a protected value was read
 * but which network requirement that device met.
 */

const P = "/v1/organizations/acme/projects/api";
const PROD = `${P}/environments/production`;
const DEVICE = { tailnet: "example.ts.net", nodeId: "nLAPTOP", tags: ["tag:prod"] };

let ctx: AppCtx & { close: () => Promise<void> };
let token: string;
let ordinary: ReturnType<typeof buildApp>;
let tailnet: ReturnType<typeof buildApp>;
let envId: string;

async function call(app: ReturnType<typeof buildApp>, method: string, path: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : null) as Record<string, any> };
}

/** The newest allowed event of each type since `after`, with what it recorded as authz. */
async function allowedSince(after: number) {
  const res = await ctx.db.query(
    "SELECT event_type, action, authz FROM audit_events WHERE event_order > $1 AND decision = 'allow' AND event_type IN ('value.disclosed','secret.disclosed','value.validated','secret.validated') ORDER BY event_order",
    [after],
  );
  return (res.rows as { event_type: string; action: string; authz: unknown }[]).map((r) => ({
    eventType: r.event_type,
    action: r.action,
    authz: (typeof r.authz === "string" ? JSON.parse(r.authz) : r.authz) as { grantIds: string[]; requirements: unknown[] } | null,
  }));
}
const position = async () => Number((await ctx.db.query("SELECT coalesce(max(event_order),0)::int AS n FROM audit_events")).rows[0]!.n);

/** Every value path: values, disclosure, validation, strict retrieval. */
async function readEverything(app: ReturnType<typeof buildApp>) {
  for (const [method, path, body] of [
    ["GET", `${PROD}/effective-configuration?include=values`, undefined],
    ["POST", `${PROD}/disclosures`, { scope: "all-authorized-secrets" }],
    ["POST", `${PROD}/validate`, {}],
    ["POST", `${PROD}/retrievals`, { mode: "strict" }],
  ] as const) {
    const res = await call(app, method, path, body);
    expect(res.status, `${method} ${path}: ${JSON.stringify(res.body).slice(0, 200)}`).toBe(200);
  }
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  token = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  ordinary = buildApp(ctx);
  tailnet = buildApp(ctx, { resolveTailnetContext: async () => DEVICE });
  await call(ordinary, "POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  await call(ordinary, "POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" });
  envId = (await call(ordinary, "POST", `${P}/environments`, { name: "production", tier: "production" })).body.id;
  const revision = await call(ordinary, "POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      semanticsVersion: 2,
      items: [
        { name: "PORT", required: { kind: "never" }, sensitive: false, type: "string" },
        { name: "SECRET_A", required: { kind: "never" }, sensitive: true, type: "string" },
      ],
    },
  });
  expect(revision.status).toBe(201);
  await call(ordinary, "POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  await call(ordinary, "PUT", `${PROD}/values/PORT`, { value: "8080" });
  await call(ordinary, "PUT", `${PROD}/values/SECRET_A`, { value: "s3cr3t-value" });
});
afterEach(async () => {
  await ctx.close();
});

const requirement = async (target: unknown, selector: Record<string, unknown>) => {
  const res = await call(ordinary, "POST", "/v1/organizations/acme/requirements", { kind: "tailnet", target, selector: { tailnet: "example.ts.net", ...selector } });
  expect(res.status).toBe(201);
  return res.body.id as string;
};

describe("allowed reads record the Requirement outcomes (issue #22)", () => {
  it("one Requirement: every value path records it as satisfied, and by what", async () => {
    const byNode = await requirement({ kind: "tier", tier: "production" }, { nodes: ["nLAPTOP"] });
    const before = await position();
    await readEverything(tailnet);
    const events = await allowedSince(before);
    // Values, disclosure, validation of both classes, strict retrieval of both classes.
    expect(new Set(events.map((e) => `${e.eventType}:${e.action}`))).toEqual(
      new Set([
        "value.disclosed:config.value.read",
        "secret.disclosed:secret.reveal",
        "value.validated:config.value.read",
        "secret.validated:secret.reveal",
      ]),
    );
    for (const e of events) {
      expect(e.authz, `${e.eventType} via ${e.action}`).toMatchObject({
        grantIds: expect.any(Array),
        requirements: [{ requirementId: byNode, satisfied: true, by: "node:nLAPTOP" }],
      });
    }
  });

  it("two overlapping Requirements: both outcomes, each with what satisfied it", async () => {
    const byNode = await requirement({ kind: "tier", tier: "production" }, { nodes: ["nLAPTOP"] });
    const byTag = await requirement({ kind: "environments", environmentIds: [envId] }, { tags: ["tag:prod"] });
    const before = await position();
    await readEverything(tailnet);
    const events = await allowedSince(before);
    expect(events.length).toBeGreaterThanOrEqual(4);
    for (const e of events) {
      const outcomes = (e.authz?.requirements ?? []) as { requirementId: string; satisfied: boolean; by: string }[];
      expect(outcomes, `${e.eventType} via ${e.action}`).toHaveLength(2);
      expect(outcomes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ requirementId: byNode, satisfied: true, by: "node:nLAPTOP" }),
          expect.objectContaining({ requirementId: byTag, satisfied: true, by: "tag:prod" }),
        ]),
      );
    }
  });

  it("the ordinary listener, where no Requirement applies: the grants, and no outcomes", async () => {
    const before = await position();
    await readEverything(ordinary);
    const events = await allowedSince(before);
    expect(events.length).toBeGreaterThanOrEqual(4);
    for (const e of events) {
      expect(e.authz, `${e.eventType} via ${e.action}`).toEqual(expect.objectContaining({ grantIds: expect.any(Array), requirements: [] }));
    }
  });

  it("records outcomes in the same shape a denial does", async () => {
    await requirement({ kind: "tier", tier: "production" }, { nodes: ["nSOMEONEELSE"] });
    const before = await position();
    expect((await call(tailnet, "POST", `${PROD}/disclosures`, { scope: "all-authorized-secrets" })).status).toBe(403);
    const denied = (await ctx.db.query("SELECT authz FROM audit_events WHERE event_order > $1 AND event_type = 'authorization.denied' ORDER BY event_order DESC LIMIT 1", [before])).rows[0] as { authz: unknown };
    const deniedAuthz = (typeof denied.authz === "string" ? JSON.parse(denied.authz) : denied.authz) as { requirements: Record<string, unknown>[] };
    await ctx.db.query("UPDATE requirements SET revoked_at = now()");
    const byNode = await requirement({ kind: "tier", tier: "production" }, { nodes: ["nLAPTOP"] });
    const after = await position();
    expect((await call(tailnet, "POST", `${PROD}/disclosures`, { scope: "all-authorized-secrets" })).status).toBe(200);
    const [allowed] = await allowedSince(after);
    const outcome = (allowed!.authz!.requirements as Record<string, unknown>[])[0]!;
    // Same keys apart from what differs between a pass and a failure.
    expect(Object.keys(deniedAuthz.requirements[0]!).filter((k) => k !== "reason").sort()).toEqual(
      Object.keys(outcome).filter((k) => k !== "by").sort(),
    );
    expect(outcome.requirementId).toBe(byNode);
  });
});
