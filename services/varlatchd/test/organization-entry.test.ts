// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { freezeOrganization } from "../src/domain/freeze.js";
import type { FreezeException } from "../src/domain/liveness.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { resolveOrganization } from "../src/http/organization.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { ROUTE_ACCESS } from "./helpers/route-access.js";

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

/**
 * Every /v1/organizations/:org route and the exception it runs under while
 * the Organization is frozen for an incident (ADR-0055 Decisions 3 and 4);
 * null: refused for the Organization's members and machines. A route
 * missing here, or naming another exception when it resolves its
 * Organization, fails.
 */
const DURING_FREEZE: Record<string, FreezeException | null> = {
  "GET /v1/organizations/:org": "inspection",
  "GET /v1/organizations/:org/me/permissions": "inspection",
  "PATCH /v1/organizations/:org": null,
  "GET /v1/organizations/:org/deletion": "inspection",
  "POST /v1/organizations/:org/deletion": null,
  "POST /v1/organizations/:org/deletion/:deletion/approve": null,
  "POST /v1/organizations/:org/deletion/:deletion/cancel": "recovery",
  "GET /v1/organizations/:org/incident-freeze": "inspection",
  "POST /v1/organizations/:org/incident-freeze": "freeze",
  "POST /v1/organizations/:org/incident-freeze/:freeze/lift": "freeze",
  "GET /v1/organizations/:org/config-items": null,
  "GET /v1/organizations/:org/projects": "inspection",
  "POST /v1/organizations/:org/projects": null,
  "GET /v1/organizations/:org/projects/:project": "inspection",
  "PATCH /v1/organizations/:org/projects/:project": null,
  "DELETE /v1/organizations/:org/projects/:project": null,
  "GET /v1/organizations/:org/projects/:project/environments": "inspection",
  "POST /v1/organizations/:org/projects/:project/environments": null,
  "GET /v1/organizations/:org/projects/:project/environments/:environment": "inspection",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/validate": null,
  "PUT /v1/organizations/:org/projects/:project/environments/:environment/values/:item": null,
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/values/:item": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations/complete": null,
  "GET /v1/organizations/:org/projects/:project/environments/:environment/effective-configuration": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/disclosures": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/retrievals": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities": null,
  "GET /v1/organizations/:org/projects/:project/environments/:environment/capabilities": "inspection",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability": "recovery",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability/exercises": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/changes": null,
  "GET /v1/organizations/:org/projects/:project/contract": null,
  "POST /v1/organizations/:org/projects/:project/contract/revisions": null,
  "GET /v1/organizations/:org/projects/:project/contract/revisions/:revision": null,
  "POST /v1/organizations/:org/projects/:project/contract/revisions/:revision/activate": null,
  "GET /v1/organizations/:org/identities": "inspection",
  "POST /v1/organizations/:org/identities": null,
  "POST /v1/organizations/:org/identities/:identity/credentials": null,
  "DELETE /v1/organizations/:org/identities/:identity/credentials/:credential": "recovery",
  "GET /v1/organizations/:org/identities/:identity/credentials": "inspection",
  "GET /v1/organizations/:org/security/credential-review": "inspection",
  "POST /v1/organizations/:org/identities/:identity/retire": "recovery",
  "POST /v1/organizations/:org/identities/:identity/reactivate": null,
  "GET /v1/organizations/:org/security/controls": "inspection",
  "GET /v1/organizations/:org/security/control-report": "inspection",
  "GET /v1/organizations/:org/security/approval-keys": "inspection",
  "GET /v1/organizations/:org/security/refused-destinations": "inspection",
  "PATCH /v1/organizations/:org/security/controls/:control": "recovery",
  "GET /v1/organizations/:org/identities/:identity/reach": "inspection",
  "PATCH /v1/organizations/:org/identities/:identity": null,
  "POST /v1/organizations/:org/identities/:identity/oidc-bindings": null,
  "GET /v1/organizations/:org/identities/:identity/oidc-bindings": "inspection",
  "DELETE /v1/organizations/:org/identities/:identity/oidc-bindings/:binding": "recovery",
  "GET /v1/organizations/:org/members/:member/review": "inspection",
  "DELETE /v1/organizations/:org/members/:member": "recovery",
  "PATCH /v1/organizations/:org/members/:member": "recovery",
  "GET /v1/organizations/:org/members/:member/exposure": "inspection",
  "POST /v1/organizations/:org/members/:member/exposure/confirmations": null,
  "POST /v1/organizations/:org/invitations": null,
  "GET /v1/organizations/:org/invitations": "inspection",
  "DELETE /v1/organizations/:org/invitations/:invitation": "recovery",
  "GET /v1/organizations/:org/grants": "inspection",
  "POST /v1/organizations/:org/grants": null,
  "DELETE /v1/organizations/:org/grants/:grant": "recovery",
  "POST /v1/organizations/:org/grants/:grant/replace": null,
  "GET /v1/organizations/:org/roles": "inspection",
  "POST /v1/organizations/:org/roles": null,
  "PATCH /v1/organizations/:org/roles/:role": null,
  "DELETE /v1/organizations/:org/roles/:role": null,
  "GET /v1/organizations/:org/groups": "inspection",
  "POST /v1/organizations/:org/groups": null,
  "PATCH /v1/organizations/:org/groups/:group": null,
  "DELETE /v1/organizations/:org/groups/:group": null,
  "GET /v1/organizations/:org/groups/:group/members": "inspection",
  "POST /v1/organizations/:org/groups/:group/members": null,
  "DELETE /v1/organizations/:org/groups/:group/members/:identity": null,
  "GET /v1/organizations/:org/teams": "inspection",
  "POST /v1/organizations/:org/teams": null,
  "PATCH /v1/organizations/:org/teams/:team": null,
  "DELETE /v1/organizations/:org/teams/:team": null,
  "GET /v1/organizations/:org/teams/:team/members": "inspection",
  "POST /v1/organizations/:org/teams/:team/members": null,
  "DELETE /v1/organizations/:org/teams/:team/members/:identity": null,
  "GET /v1/organizations/:org/teams/:team/projects": "inspection",
  "POST /v1/organizations/:org/teams/:team/projects": null,
  "DELETE /v1/organizations/:org/teams/:team/projects/:project": null,
  "GET /v1/organizations/:org/requirements": "inspection",
  "POST /v1/organizations/:org/requirements": "recovery",
  "PATCH /v1/organizations/:org/requirements/:requirement": null,
  "DELETE /v1/organizations/:org/requirements/:requirement": null,
  "POST /v1/organizations/:org/webhooks": null,
  "GET /v1/organizations/:org/webhooks": "inspection",
  "PATCH /v1/organizations/:org/webhooks/:webhook": null,
  "DELETE /v1/organizations/:org/webhooks/:webhook": null,
  "GET /v1/organizations/:org/platform-connections": "inspection",
  "POST /v1/organizations/:org/platform-connections": null,
  "POST /v1/organizations/:org/platform-connections/check": null,
  "POST /v1/organizations/:org/platform-connections/destinations": null,
  "GET /v1/organizations/:org/platform-connections/:connection": null,
  "POST /v1/organizations/:org/platform-connections/:connection/credential": null,
  "DELETE /v1/organizations/:org/platform-connections/:connection": "recovery",
  "GET /v1/organizations/:org/github-app": null,
  "POST /v1/organizations/:org/github-app/registrations": null,
  "POST /v1/organizations/:org/github-app/registrations/complete": null,
  "POST /v1/organizations/:org/github-app/import": null,
  "POST /v1/organizations/:org/github-app/key": null,
  "DELETE /v1/organizations/:org/github-app": null,
  "GET /v1/organizations/:org/github-app/installations": null,
  "GET /v1/organizations/:org/sync-targets": "inspection",
  "GET /v1/organizations/:org/projects/:project/environments/:environment/sync-targets": "inspection",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets": null,
  "GET /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": null,
  "PATCH /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/push": null,
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/pause": "recovery",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/resume": null,
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": null,
  "GET /v1/organizations/:org/audit-events": "audit",
  "GET /v1/organizations/:org/audit-events/export": "audit",
};

const LOOKUP = /\bgetOrganization\b|\blistOrganizationsFor\b|\b(?:FROM|JOIN)\s+organizations\b/;

/**
 * passkey-verification's decision points (ADR-0054 Decision 7,
 * src/domain/requestaccess.ts) outside the routes' own checkpoints: every
 * explicit lock of an Organization row in src/, by file, each with how a
 * request writing under it is decided, or why none is. A new direct lock
 * fails until it is classified here. lockLiveScope and lockScope
 * (liveness.ts) capture the outcome under their lock for every writer that
 * uses them.
 */
const ORGANIZATION_LOCKS: { file: string; count: number; reason: string }[] = [
  { file: "domain/liveness.ts", count: 2, reason: "lockLiveScope and lockScope capture under the lock (withExternalEffect builds on lockLiveScope)" },
  { file: "domain/approvals.ts", count: 1, reason: "createApproval: decides under the lock before an approval intent is created" },
  { file: "domain/orgdeletion.ts", count: 1, reason: "the deletion worker's claim: background work, outside any request" },
  { file: "domain/securityreport.ts", count: 2, reason: "report counters: the access-count worker outside any request, and a protected write's count after its checkpoint" },
  { file: "domain/exposure.ts", count: 1, reason: "the exposure backfill worker: background work, outside any request" },
];

/**
 * The protected effects that must come after a request's checkpoint, each
 * guarded where it happens (assertOrganizationAccessChecked notes a gap,
 * which fails the test, and decides then): a disclosure audit and
 * decryption, and an outbound call for an Organization.
 */
const EFFECT_GUARDS: { file: string; line: string }[] = [
  { file: "domain/retrieval.ts", line: "await assertOrganizationAccessChecked(ctx.db, state.org.id, \"a disclosure audit and decryption\");" },
  { file: "net/outbound.ts", line: "if (audit) await assertOrganizationAccessChecked(audit.db, audit.organizationId, `an outbound ${purpose} call`, { underLock: true });" },
];

/**
 * Requests outside /v1/organizations/:org that reach an Organization, and
 * how passkey-verification applies to each.
 */
const OUTSIDE_ORG_ROUTES: Record<string, string> = {
  "POST /v1/tokens/convex": "decides per Organization when the token is minted, leaving a blocked one out",
  "DELETE /v1/me/credentials/:credential": "a machine's own credential: its Organization's writer protocol (exempt by kind, checked like any writer)",
  "POST /v1/oidc/token": "the OIDC exchange: unauthenticated, mints a machine credential (exempt by kind)",
  "GET /v1/organizations": "the person's own memberships, no Organization's contents",
  "POST /v1/organizations": "creates a new Organization the person then administers",
  "/v1/me/approvals/:approval/*": "the person's own approval ceremony with a fresh passkey assertion; the operation it approves decides itself",
  "/v1/deleted-organizations/* and /v1/installation/deleted-organizations/*": "no live Organization to enforce anything (ADR-0051 Decision 8)",
};

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

  it("lock an Organization row only where passkey-verification is decided, or outside any request", () => {
    const root = fileURLToPath(new URL("../src/", import.meta.url));
    const counts = new Map<string, number>();
    const walk = (dir: string) => {
      for (const entry of readdirSync(`${root}${dir}`, { withFileTypes: true })) {
        const rel = dir ? `${dir}/${entry.name}` : entry.name;
        if (entry.isDirectory()) walk(rel);
        else if (rel.endsWith(".ts")) {
          const n = readFileSync(`${root}${rel}`, "utf8").split("\n").filter((l) => /table: "organizations"|\(table: "organizations" \|/.test(l)).length;
          if (n > 0) counts.set(rel, n);
        }
      }
    };
    walk("");
    expect(Object.fromEntries([...counts].sort())).toEqual(Object.fromEntries(ORGANIZATION_LOCKS.map((l) => [l.file, l.count]).sort()));
    for (const guard of EFFECT_GUARDS) {
      expect(readFileSync(`${root}${guard.file}`, "utf8"), guard.file).toContain(guard.line);
    }
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

      expect(new Set(entering.map((r) => `${r.method} ${r.path}`))).toEqual(new Set(Object.keys(DURING_FREEZE)));
      // And where each decides passkey-verification (ADR-0054 Decision 7).
      expect(new Set(entering.map((r) => `${r.method} ${r.path}`))).toEqual(new Set(Object.keys(ROUTE_ACCESS)));
      // The listed requests outside /v1/organizations/:org exist.
      const all = routes.map((r) => `${r.method} ${r.path}`);
      for (const k of Object.keys(OUTSIDE_ORG_ROUTES).filter((k) => /^(?:GET|POST|PUT|PATCH|DELETE) /.test(k))) expect(all).toContain(k);
      // An effect-free read decided at its answer is a GET.
      expect(Object.entries(ROUTE_ACCESS).filter(([k, v]) => v === "read" && !k.startsWith("GET ")).map(([k]) => k)).toEqual([]);
      const skipped: string[] = [];
      const misnamed: string[] = [];
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
        const named = (resolver.mock.calls[0]?.[2] as { duringIncidentFreeze?: FreezeException } | undefined)?.duringIncidentFreeze ?? null;
        if (named !== DURING_FREEZE[`${route.method} ${route.path}`]) misnamed.push(`${route.method} ${route.path}: ${named}`);
      }
      expect(skipped).toEqual([]);
      expect(misnamed).toEqual([]);
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

describe("every /v1/organizations/:org route while the Organization is frozen (ADR-0055)", () => {
  /** The status and error code of every entering route for one token. */
  async function answers(app: ReturnType<typeof buildApp>, bearer: string) {
    const out = new Map<string, { status: number; code: string | null }>();
    for (const route of app.routes.filter((r) => r.method !== "ALL" && (r.path === ORG_ROUTES || r.path.startsWith(`${ORG_ROUTES}/`)))) {
      const path = route.path.replace(":org", "acme").replace(/:[a-z]+/gi, "x");
      const res = await app.request(path, {
        method: route.method,
        headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
        ...(route.method === "GET" ? {} : { body: "{}" }),
      });
      const body = (await res.json().catch(() => null)) as { error?: { code: string } } | null;
      out.set(`${route.method} ${route.path}`, { status: res.status, code: body?.error?.code ?? null });
    }
    return out;
  }

  it("refuses a member and a machine of the Organization on each route without an exception, allows each exempt one; an outsider gets the usual answer", async () => {
    const app = buildApp(ctx);
    const send = (path: string, body: unknown, bearer = token) =>
      app.request(path, { method: "POST", headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const bot = (await (await send("/v1/organizations/acme/identities", { name: "bot", kind: "service" })).json()) as { id: string; credential: string };
    expect((await send("/v1/organizations/acme/grants", { subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["organization.read", "config.metadata.read"] })).status).toBe(201);
    const other = (await (await send("/v1/organizations", { name: "Beta", slug: "beta" })).json()) as { id: string };
    const adminId = ((await ctx.db.query("SELECT identity_id FROM credentials WHERE kind = 'cli'")).rows[0] as { identity_id: string }).identity_id;
    const outsiderId = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: other.id, role: "member", name: "Outsider" }, adminId)).token, {})).identityId;
    const outsider = (await issueCredential(ctx.db, { identityId: outsiderId, kind: "cli" })).token;
    const acme = ((await ctx.db.query("SELECT id FROM organizations WHERE slug = 'acme'")).rows[0] as { id: string }).id;

    const outsiderBefore = await answers(app, outsider);
    await freezeOrganization(ctx, {
      organizationId: acme, actor: { id: adminId, kind: "human" }, credentialKind: "cli", reason: "drill", requestId: "req_test", authorizeIn: async () => undefined,
    });

    for (const [who, bearer] of [["member", token], ["machine", bot.credential]] as const) {
      const wrong: string[] = [];
      for (const [route, answer] of await answers(app, bearer)) {
        const frozenAnswer = answer.code === "ORGANIZATION_FROZEN";
        if (frozenAnswer !== (DURING_FREEZE[route] === null)) wrong.push(`${route}: ${answer.status} ${answer.code}`);
      }
      expect(wrong, who).toEqual([]);
    }
    const outsiderDuring = await answers(app, outsider);
    expect([...outsiderDuring].filter(([route, a]) => a.status !== outsiderBefore.get(route)?.status || a.code !== outsiderBefore.get(route)?.code)).toEqual([]);
    expect([...outsiderDuring.values()].some((a) => a.code === "ORGANIZATION_FROZEN")).toBe(false);
    // Four passes over every route, each request's transactions checked
    // by the lock trace: about 6 s on PGlite, over the 5 s default.
  }, 30_000);
});
