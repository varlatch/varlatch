// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { resolveOrganization } from "../src/http/organization.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * One place where a request's principal enters an Organization (ADR-0054
 * Decision 7): resolveOrganization in http/organization.ts. The
 * per-request Organization checks will run there, so a route that finds
 * its Organization any other way would skip them. Two checks keep that
 * from happening:
 *
 * - At runtime, every route registered under /v1/organizations/:org, on
 *   every listener, is called once and must have called the resolver
 *   exactly once for that request. This catches a route that never
 *   resolves the Organization itself (for example one passing the raw
 *   route parameter to a domain function) and one that resolves it twice.
 * - Statically, no file in src/http/ looks an Organization up except the
 *   resolver, apart from the documented exceptions below. This catches a
 *   new direct lookup before it has a route, and lookups outside
 *   /v1/organizations/:org.
 */

vi.mock("../src/http/organization.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/http/organization.js")>();
  return { ...actual, resolveOrganization: vi.fn(actual.resolveOrganization) };
});
const resolver = vi.mocked(resolveOrganization);

const HOST = "varlatch.example.ts.net";
const LISTENERS: { name: string; options: BuildAppOptions; headers: Record<string, string> }[] = [
  { name: "ordinary", options: {}, headers: {} },
  { name: "tailnet", options: { resolveTailnetContext: async () => null }, headers: {} },
  {
    name: "tailnet browser endpoint",
    options: {
      resolveTailnetContext: async () => null,
      tailnetBrowser: { host: HOST, port: 8688, origins: ["https://varlatch.example.com"] },
    },
    headers: { Host: HOST },
  },
];

const ORG_ROUTES = "/v1/organizations/:org";

/**
 * Routes that name Organizations but do not enter one through :org. Each
 * needs a reason; a new one fails the test until it is listed here or goes
 * through the resolver.
 */
const NOT_ENTERING = new Set([
  // The caller's own memberships (user-scoped), and creating a new one.
  "GET /v1/organizations",
  "POST /v1/organizations",
  // A deleted Organization's audit tombstone: no live Organization to
  // enter; its own readers check (ADR-0051 Decision 8).
  "GET /v1/deleted-organizations/:organization/audit-events",
  "GET /v1/deleted-organizations/:organization/audit-events/export",
  // Installation Admin views of deleted Organizations' tombstones.
  "GET /v1/installation/deleted-organizations",
  "DELETE /v1/installation/deleted-organizations/:organization/readers/:identity",
]);

/**
 * Organization lookups in src/http/ other than the resolver's, by file and
 * the exact line, one entry per occurrence. Each needs a reason, and an
 * entry that no longer matches fails too, so the list cannot go stale.
 * Background work (backup metadata, the Mirror publisher, deletion
 * sweeps) is outside src/http/ and serves no request.
 */
const LOOKUP_EXCEPTIONS: { file: string; line: string; reason: string }[] = [
  {
    file: "organization.ts",
    line: "const org = await getOrganization(ctx, routeParam(c, \"org\"));",
    reason: "the resolver itself",
  },
  {
    file: "app.ts",
    line: "const orgs = await listOrganizationsFor(ctx, principal.identity.id);",
    reason:
      "POST /v1/tokens/convex names the caller's own memberships in an Application Plane token, which this " +
      "API never accepts back (ADR-0018 §6)",
  },
  {
    file: "app.ts",
    line: "const orgs = await listOrganizationsFor(ctx, principal.identity.id);",
    reason: "GET /v1/organizations lists the caller's own memberships (user-scoped)",
  },
  {
    file: "app.ts",
    line: "const res = await ctx.db.query(\"SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL\", [",
    reason: "GET /v1/me describes a machine caller's own Organization; whoami exercises no authority (ADR-0016)",
  },
  {
    file: "app.ts",
    line: "`SELECT 1 FROM audit_tombstone_readers r JOIN organizations o ON o.id = r.organization_id",
    reason: "deleted Organizations' audit tombstone readers (ADR-0051 Decision 8)",
  },
  {
    file: "app.ts",
    line:
      "await ctx.db.query(\"SELECT id, slug, name, deleted_at FROM organizations WHERE deleted_at IS NOT NULL " +
      "ORDER BY deleted_at DESC, id\")",
    reason: "Installation Admin list of deleted Organizations' tombstones",
  },
];

const LOOKUP = /\bgetOrganization\b|\blistOrganizationsFor\b|\b(?:FROM|JOIN)\s+organizations\b/;

describe("Organization lookups in src/http/", () => {
  it("go through the resolver, except the listed ones", () => {
    const dir = fileURLToPath(new URL("../src/http/", import.meta.url));
    const found: string[] = [];
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".ts")).sort()) {
      for (const raw of readFileSync(`${dir}${file}`, "utf8").split("\n")) {
        const line = raw.trim();
        // Imports and comments are not lookups.
        if (!LOOKUP.test(line) || /^(?:import\b|\/\/|\*|\/\*\*)/.test(line) || /^[\w\s,]+,$/.test(line)) continue;
        found.push(`${file}: ${line}`);
      }
    }
    expect(found.sort()).toEqual(LOOKUP_EXCEPTIONS.map((e) => `${e.file}: ${e.line}`).sort());
  });

  it("import getOrganization only in the resolver", () => {
    const dir = fileURLToPath(new URL("../src/http/", import.meta.url));
    const importers = readdirSync(dir)
      .filter((f) => f.endsWith(".ts"))
      .filter((f) => /\bgetOrganization\b/.test(readFileSync(`${dir}${f}`, "utf8")));
    expect(importers).toEqual(["organization.ts"]);
  });
});

let ctx: AppCtx & { close: () => Promise<void> };
let token: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  token = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  const app = buildApp(ctx);
  for (const [path, body] of [
    ["/v1/organizations", { name: "Acme", slug: "acme" }],
    ["/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" }],
    ["/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" }],
  ] as const) {
    const res = await app.request(path, { method: "POST", headers: headers(), body: JSON.stringify(body) });
    expect(res.status).toBe(201);
  }
  resolver.mockClear();
});
afterEach(async () => {
  await ctx.close();
});

function headers(extra: Record<string, string> = {}): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...extra };
}

/**
 * The resolver's calls during one request: the slug of the Organization
 * each returned, or "(not found)" for one that threw.
 */
async function orgsResolvedBy(run: () => Promise<Response>): Promise<{ status: number; slugs: string[] }> {
  resolver.mockClear();
  const res = await run();
  const slugs = resolver.mock.settledResults.map((r) =>
    r.type === "fulfilled" ? (r.value as { slug: string }).slug : "(not found)",
  );
  return { status: res.status, slugs };
}

describe("every /v1/organizations/:org route", () => {
  for (const listener of LISTENERS) {
    it(`resolves its Organization through the resolver, once (${listener.name} listener)`, async () => {
      const app = buildApp(ctx, listener.options);
      const routes = app.routes.filter((r) => r.method !== "ALL" && r.path.startsWith("/v1/"));
      const entering = routes.filter((r) => r.path === ORG_ROUTES || r.path.startsWith(`${ORG_ROUTES}/`));
      // Anything else naming an Organization is a listed exception.
      const others = routes
        .filter((r) => !entering.includes(r) && /organization/.test(r.path))
        .map((r) => `${r.method} ${r.path}`);
      expect(new Set(others)).toEqual(NOT_ENTERING);
      expect(entering.length).toBeGreaterThan(100);

      const skipped: string[] = [];
      for (const route of entering) {
        // Only :org is real: the resolver runs before anything below it
        // is looked up, so the other parameters need not exist.
        const path = route.path.replace(":org", "acme").replace(/:[a-z]+/gi, "x");
        const { slugs } = await orgsResolvedBy(() =>
          app.request(path, {
            method: route.method,
            headers: headers(listener.headers),
            ...(route.method === "GET" ? {} : { body: "{}" }),
          }),
        );
        if (slugs.length !== 1 || slugs[0] !== "acme") skipped.push(`${route.method} ${route.path}: ${slugs.join(", ")}`);
      }
      expect(skipped).toEqual([]);
    });
  }

  it("includes a project-only route, an environment route and a retrieval", async () => {
    const app = buildApp(ctx);
    const send = (method: string, path: string, body?: unknown) =>
      orgsResolvedBy(() =>
        app.request(path, { method, headers: headers(), ...(body === undefined ? {} : { body: JSON.stringify(body) }) }),
      );
    const P = "/v1/organizations/acme/projects/api";
    // projectScope: a project rename.
    expect(await send("PATCH", P, { name: "API gateway" })).toEqual({ status: 200, slugs: ["acme"] });
    // envScope: an Environment read.
    expect(await send("GET", `${P}/environments/development`)).toEqual({ status: 200, slugs: ["acme"] });
    // envScope inside a retrieval snapshot.
    expect(await send("POST", `${P}/environments/development/retrievals`, { mode: "strict" })).toEqual({
      status: 200,
      slugs: ["acme"],
    });
    // Unknown Organizations are still not found, before any check could run.
    expect(await send("GET", "/v1/organizations/nope/projects")).toEqual({ status: 404, slugs: ["(not found)"] });
  });
});
