// SPDX-License-Identifier: AGPL-3.0-or-later
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { expect, inject } from "vitest";
import { issueCredential } from "../../src/auth/credentials.js";
import { encryptGitHubAppKey } from "../../src/crypto/hierarchy.js";
import { getOrganization, orgKekOf } from "../../src/domain/orgs.js";
import { setOutboundResolverForTests } from "../../src/net/outbound.js";
import type { AppCtx } from "../../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../../src/domain/bootstrap.js";
import { accessCountsSettled } from "../../src/domain/securityreport.js";
import { buildApp } from "../../src/http/app.js";
import { PUBLIC_URL, RP } from "./device-sign-in.js";
import { lockOrderMode, lockTraced } from "./lock-trace.js";
import { asQuerier } from "./pglite-snapshots.js";
import { TEST_PUBLIC_ADDRESS } from "./outbound-resolver.js";
import { registerSoftPasskey } from "./soft-authenticator.js";

/**
 * An existing GitHub App of the Organization, written as registration
 * leaves it (its private key wrapped under the Organization's KEK), with no
 * call to GitHub.
 */
export async function insertGitHubApp(ctx: AppCtx, organization: string, createdBy: string): Promise<string> {
  const org = await getOrganization(ctx, organization);
  const id = `gha_${randomUUID().replaceAll("-", "").slice(0, 26)}`;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
  const envelope = encryptGitHubAppKey(orgKekOf(ctx, org), org.id, id, pem);
  await ctx.db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
     VALUES ($1,$2,4242,'acme-varlatch','Iv1.fixture','acme',4243,'organization',$3,$4)`,
    [id, org.id, JSON.stringify(envelope), createdBy],
  );
  return id;
}

/** The pending GitHub App registration the attach and discard routes find (fixture id). */
export const PENDING_REGISTRATION = "ghr_sweeppendingregistration01";

/**
 * A GitHub App registration of the admin, converted and waiting to be
 * attached (ADR-0054 amendment D), its key wrapped under the Organization
 * KEK and bound to the registration id, with no call to GitHub. Written
 * only for the routes on a registration (`prepare`), so every other
 * variant runs on exactly the fixtures main's baseline was recorded on.
 */
export async function insertPendingRegistration(ctx: AppCtx, organization: string, startedBy: string): Promise<void> {
  const org = await getOrganization(ctx, organization);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
  const envelope = encryptGitHubAppKey(orgKekOf(ctx, org), org.id, PENDING_REGISTRATION, pem);
  await ctx.db.query(
    `INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, expires_at, consumed_at,
       converted_at, pending_expires_at, pending_github_app_id, pending_slug, pending_client_id, pending_owner_login, pending_owner_id,
       pending_owner_type, pending_key_envelope)
     VALUES ($1, 'sweep-pending', $2, $3, 'acme', 'organization', now() + interval '1 hour', now(),
       now(), now() + interval '1 hour', 4245, 'acme-pending', 'Iv1.pending', 'acme', 4243, 'organization', $4)
     ON CONFLICT DO NOTHING`,
    [PENDING_REGISTRATION, org.id, startedBy, JSON.stringify(envelope)],
  );
}

/** Routes on a pending registration: their fixture is written per variant (Sweeper.prepare). */
const ON_REGISTRATION = new Set([
  "POST /v1/organizations/:org/github-app/registrations/:registration/attach",
  "DELETE /v1/organizations/:org/github-app/registrations/:registration",
]);

/**
 * The test resolver with api.github.com on a private address, which the
 * outbound policy refuses: a call to GitHub is refused, and recorded,
 * without the network. `restore` puts the setup file's resolver back.
 */
export function githubOnPrivateAddress(): { restore: () => void } {
  setOutboundResolverForTests(async (name) => {
    if (name === "api.github.com") return [{ address: "10.20.30.40", family: 4 }];
    if (name === "localhost") return [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }];
    return [{ address: TEST_PUBLIC_ADDRESS, family: 4 }];
  });
  return {
    restore: () =>
      setOutboundResolverForTests(async (name) =>
        name === "localhost" ? [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }] : [{ address: TEST_PUBLIC_ADDRESS, family: 4 }],
      ),
  };
}

/**
 * Every /v1/organizations/:org route with existing fixtures, then with each
 * path parameter missing in turn, then (for an environment's routes) an
 * environment a Tailnet Requirement covers: the route sweep of
 * test/passkey-verification.test.ts, and the recorder of its off-mode
 * baseline (test/passkey-verification-baseline.test.ts), which runs the
 * same sweep on another checkout. It uses only APIs that main had before
 * the passkey-verification boundary fix, so it runs there unchanged.
 */

export type Fixtures = Record<string, string>;

export async function fixtureDb(data?: Blob) {
  const pg = new PGlite(data ? { loadDataDir: data } : { loadDataDir: new Blob([await readFile(inject("pgliteSnapshots").traced)]) });
  await pg.waitReady;
  const raw = asQuerier(pg);
  const mode = lockOrderMode();
  return { pg, db: mode === "off" ? raw : lockTraced(raw, mode) };
}

export async function buildFixtures(rootKek: Buffer): Promise<{ data: Blob; f: Fixtures; tokens: { admin: string; verified: string }; admin: string }> {
  const { pg, db } = await fixtureDb();
  const fctx: AppCtx = { db, rootKek };
  await ensureInstallation(fctx);
  const adminIdentity = (await consumeSetupGrant(fctx, (await issueBootstrapGrant(fctx)).token, { adminName: "Admin" })).identityId;
  const adminToken = (await issueCredential(db, { identityId: adminIdentity, kind: "cli" })).token;
  const key = await registerSoftPasskey(db, adminIdentity, { ...RP, trust: "trusted" });
  await db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT 'ses_sweep', now() + interval '1 day', 'ses_sweep', better_auth_user_id FROM auth_user_links WHERE identity_id = $1`,
    [adminIdentity],
  );
  await db.query("INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ('ses_sweep', 'sign-in', true, $1)", [key.passkeyId]);
  const verifiedToken = (await issueCredential(db, { identityId: adminIdentity, kind: "browser", expiresAt: new Date(Date.now() + 3600_000).toISOString(), authSessionId: "ses_sweep" })).token;
  const a = buildApp(fctx, { publicUrl: PUBLIC_URL });
  const post = async (method: string, path: string, body?: unknown) => {
    const res = await a.request(path, {
      method,
      headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    expect(res.status, `${method} ${path}: ${text}`).toBeLessThan(300);
    return text ? JSON.parse(text) : null;
  };
  const o = "/v1/organizations/acme";
  const org = await post("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  const project = await post("POST", `${o}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
  await post("POST", `${o}/projects/api/environments`, { name: "production", tier: "production" });
  const revision = await post("POST", `${o}/projects/api/contract/revisions`, {
    contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await post("POST", `${o}/projects/api/contract/revisions/${revision.id}/activate`, {});
  await post("PUT", `${o}/projects/api/environments/production/values/DB_PASS`, { value: "hunter2-hunter2" });
  // A staging environment that the Tailnet Requirement below covers: its
  // values need verified Tailnet Context, which the sweep never has.
  await post("POST", `${o}/projects/api/environments`, { name: "staging", tier: "staging" });
  await post("PUT", `${o}/projects/api/environments/staging/values/DB_PASS`, { value: "staging-staging" });
  const bob = (await consumeSetupGrant(fctx, (await issueInviteGrant(fctx, { organizationId: org.id, role: "member", name: "Bob" }, adminIdentity)).token, {})).identityId;
  const bot = await post("POST", `${o}/identities`, { name: "bot", kind: "service" });
  const botCredential = ((await db.query("SELECT id FROM credentials WHERE identity_id = $1", [bot.id])).rows[0] as { id: string }).id;
  const grant = await post("POST", `${o}/grants`, { subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["organization.read"] });
  const role = await post("POST", `${o}/roles`, { name: "Reader", actions: ["organization.read"] });
  const group = await post("POST", `${o}/groups`, { name: "Ops" });
  await post("POST", `${o}/groups/${group.id}/members`, { identityId: bob });
  const team = await post("POST", `${o}/teams`, { name: "Core" });
  await post("POST", `${o}/teams/${team.id}/members`, { identityId: bob });
  await post("POST", `${o}/teams/${team.id}/projects`, { projectId: project.id });
  const requirement = await post("POST", `${o}/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:ci"] } });
  const webhook = await post("POST", `${o}/webhooks`, { url: "https://hooks.example.com/varlatch" });
  const invitation = await post("POST", `${o}/invitations`, { name: "Eve", role: "member" });
  const binding = await post("POST", `${o}/identities/${bot.id}/oidc-bindings`, { issuer: "https://token.example.com", audience: "varlatch", subject: "repo:acme/api" });
  // An existing GitHub App: its routes and App Connections reach GitHub,
  // which the sweep's resolver puts on a refused address.
  const githubApp = await insertGitHubApp(fctx, "acme", adminIdentity);
  const data = await pg.dumpDataDir("none");
  await pg.close();
  return {
    data,
    tokens: { admin: adminToken, verified: verifiedToken },
    admin: adminIdentity,
    f: {
      org: "acme", project: "api", environment: "production", item: "DB_PASS", revision: revision.id,
      identity: bot.id, credential: botCredential, member: bob, invitation: invitation.id, grant: grant.id,
      role: role.id, group: group.id, team: team.id, requirement: requirement.id, webhook: webhook.id,
      binding: binding.id, control: "requirement-protection", projectId: project.id, githubApp,
      registration: PENDING_REGISTRATION,
    },
  };
}

/** Query strings that make a route read more (values, not only metadata). */
export const QUERIES: Record<string, string> = {
  "GET /v1/organizations/:org/projects/:project/environments/:environment/effective-configuration": "?include=values",
};

/** A body each write route accepts with the fixtures (the rest get {}). */
export function bodyOf(route: string, f: Fixtures): unknown {
  const R = "/v1/organizations/:org";
  const E = `${R}/projects/:project/environments/:environment`;
  const bodies: Record<string, unknown> = {
    [`PATCH ${R}`]: { name: "Acme 2" },
    [`POST ${R}/deletion`]: { afterDays: 1 },
    [`POST ${R}/incident-freeze`]: { reason: "drill" },
    [`POST ${R}/projects`]: { name: "Web", slug: "web", contractAuthority: "git" },
    [`PATCH ${R}/projects/:project`]: { name: "API 2" },
    [`POST ${R}/projects/:project/environments`]: { name: "staging", tier: "staging" },
    [`PUT ${E}/values/:item`]: { value: "changed-changed" },
    [`POST ${E}/values/:item/rotations`]: { value: "rotated-rotated" },
    [`POST ${E}/changes`]: { changes: [{ op: "set", item: "DB_PASS", value: "set-set-set" }] },
    [`POST ${E}/disclosures`]: { scope: "all-authorized-secrets" },
    [`POST ${E}/retrievals`]: { mode: "strict" },
    [`POST ${R}/projects/:project/contract/revisions`]: { contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }, { name: "PORT", required: { kind: "never" }, sensitive: false, type: "string" }] } },
    [`POST ${R}/identities`]: { name: "bot2", kind: "service" },
    [`POST ${R}/identities/:identity/credentials`]: { name: "second" },
    [`PATCH ${R}/identities/:identity`]: { name: "bot-renamed" },
    [`POST ${R}/identities/:identity/oidc-bindings`]: { issuer: "https://token2.example.com", audience: "varlatch", subject: "repo:acme/web" },
    [`PATCH ${R}/members/:member`]: { role: "admin" },
    [`POST ${R}/invitations`]: { name: "Mallory", role: "member" },
    [`POST ${R}/grants`]: { subjectIdentityId: f.identity, scope: { kind: "organization" }, actions: ["config.metadata.read"] },
    [`POST ${R}/grants/:grant/replace`]: { subjectIdentityId: f.identity, scope: { kind: "organization" }, actions: ["config.metadata.read"] },
    [`POST ${R}/roles`]: { name: "Viewer", actions: ["organization.read"] },
    [`PATCH ${R}/roles/:role`]: { expectedVersion: 1, name: "Reader 2" },
    [`POST ${R}/groups`]: { name: "Ops 2" },
    [`PATCH ${R}/groups/:group`]: { expectedVersion: 1, name: "Ops 3" },
    [`POST ${R}/groups/:group/members`]: { identityId: f.identity },
    [`POST ${R}/teams`]: { name: "Core 2" },
    [`PATCH ${R}/teams/:team`]: { expectedVersion: 1, name: "Core 3" },
    [`POST ${R}/teams/:team/members`]: { identityId: f.identity },
    [`POST ${R}/teams/:team/projects`]: { projectId: f.projectId },
    [`POST ${R}/requirements`]: { kind: "tailnet", target: { kind: "tier", tier: "development" }, selector: { tailnet: "example.ts.net", tags: ["tag:dev"] } },
    [`PATCH ${R}/requirements/:requirement`]: { expectedVersion: 1, selector: { tailnet: "example.ts.net", tags: ["tag:other"] } },
    [`POST ${R}/webhooks`]: { url: "https://hooks.example.com/second" },
    [`PATCH ${R}/webhooks/:webhook`]: { expectedVersion: 1, eventTypes: null },
    [`PATCH ${R}/security/controls/:control`]: { mode: "report", expectedVersion: 0 },
    // An App Connection: GitHub is asked for the installation, and refused.
    [`POST ${R}/platform-connections`]: { credentialKind: "github-app", installationId: 4244, name: "Actions" },
  };
  return bodies[route] ?? {};
}

/** Each table's state, apart from refusals' audit events and the control flipped between runs. */
export async function fingerprint(db: AppCtx["db"]): Promise<Map<string, string>> {
  const tables = ((await db.query(
    `SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname`,
  )).rows as { name: string }[]).map((r) => r.name);
  const SPECIAL: Record<string, string> = {
    // Changed by every request (last use); what counts is issuance and revocation.
    credentials: "SELECT count(*)::text || '/' || count(revoked_at)::text FROM credentials",
    // last_seen_at: stamped with a credential's last use, at most once a minute.
    identities: "SELECT md5(coalesce(string_agg((to_jsonb(x) - 'last_seen_at')::text, ',' ORDER BY x.id), '')) FROM identities x",
    audit_events: "SELECT count(*)::text FROM audit_events WHERE event_type <> 'authorization.denied'",
    // Flipped between the runs; nothing a request changes.
    security_controls: "SELECT count(*)::text || '/' || string_agg(control || ':' || mode, ',' ORDER BY control) FROM security_controls WHERE control <> 'passkey-verification'",
    organizations: "SELECT string_agg(id || ':' || name || ':' || coalesce(deleted_at::text, ''), ',' ORDER BY id) FROM organizations",
  };
  const SKIP = new Set(["audit_position", "varlatch_migrations", "security_control_counters"]);
  const parts = tables.filter((t) => !SKIP.has(t)).map((t) =>
    `SELECT '${t}' AS t, (${SPECIAL[t] ?? `SELECT md5(coalesce(string_agg(x::text, ',' ORDER BY x::text), '')) FROM "${t}" x`}) AS v`,
  );
  const rows = (await db.query(parts.join(" UNION ALL "))).rows as { t: string; v: string | null }[];
  return new Map(rows.map((r) => [r.t, r.v ?? ""]));
}

/** The tables whose state differs. */
export function changedTables(before: Map<string, string>, after: Map<string, string>): string[] {
  return [...new Set([...before.keys(), ...after.keys()])].filter((t) => before.get(t) !== after.get(t)).sort();
}

/**
 * A JSON body's shape: object keys and value types. Order never matters:
 * an array is the sorted set of its elements' distinct shapes, and the
 * entries of a map keyed by ids (credentials by id, say) collapse into one
 * "<id>" key with the same set, since ids differ from run to run.
 */
export function shapeOf(value: unknown): unknown {
  const set = (items: unknown[]) => [...new Set(items.map((i) => JSON.stringify(shapeOf(i))))].sort().map((j) => JSON.parse(j) as unknown);
  if (Array.isArray(value)) return set(value);
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const isId = (k: string) => /^[a-z]+_[a-z0-9]{16,}$/.test(k);
    const ids = entries.filter(([k]) => isId(k)).map(([, v]) => v);
    const named = entries.filter(([k]) => !isId(k)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return Object.fromEntries([...named.map(([k, v]) => [k, shapeOf(v)]), ...(ids.length > 0 ? [["<id>", set(ids)]] : [])]);
  }
  return value === null ? "null" : typeof value;
}

export interface Answer { status: number; code: string | null; shape: unknown }

export interface Variant { key: string; label: string; method: string; path: string; body: unknown; variant: string }

export interface Sweeper {
  variants(): Variant[];
  setMode(mode: "off" | "enforce"): Promise<void>;
  /**
   * What the variant's route needs beyond the fixtures, written before its
   * state is taken (a pending registration for the routes on one). Nothing
   * for every other route.
   */
  prepare(v: Variant): Promise<void>;
  send(v: Variant): Promise<Answer>;
  state(): Promise<Map<string, string>>;
  denials(): Promise<number>;
  /** Back to the fixtures, for the next variant. */
  fresh(): Promise<void>;
  close(): Promise<void>;
}

const R = "/v1/organizations/:org";

/** The sweep over a fixture database: one route variant at a time, the blocked admin's requests. */
export async function sweeper(rootKek: Buffer): Promise<Sweeper> {
  const resolver = githubOnPrivateAddress();
  const { data, f, tokens, admin } = await buildFixtures(rootKek);
  let current = await fixtureDb(data);
  let sctx: AppCtx = { db: current.db, rootKek };
  let sapp = buildApp(sctx, { publicUrl: PUBLIC_URL });
  return {
    variants: () =>
      sapp.routes
        .filter((r) => r.method !== "ALL" && (r.path === R || r.path.startsWith(`${R}/`)))
        .flatMap((route) => {
          const key = `${route.method} ${route.path}`;
          const params = [...route.path.matchAll(/:([a-z]+)/gi)].map((m) => m[1]!);
          const variants: [string, Record<string, string>][] = [
            ["fixtures", {}],
            ...params.map((p) => [`missing ${p}`, { [p]: `missing_${p}` }] as [string, Record<string, string>]),
            ...(params.includes("environment") ? [["tailnet environment", { environment: "staging" }] as [string, Record<string, string>]] : []),
          ];
          return variants.map(([variant, override]) => ({
            key,
            variant,
            label: `${key} (${variant})`,
            method: route.method,
            path: route.path.replace(/:([a-z]+)/gi, (_, p: string) => encodeURIComponent(override[p] ?? f[p] ?? "x")) + (QUERIES[key] ?? ""),
            body: bodyOf(key, f),
          }));
        }),
    setMode: async (mode) => {
      await sctx.db.query(
        `INSERT INTO security_controls (organization_id, control, mode, version)
         SELECT id, 'passkey-verification', $1, 1 FROM organizations WHERE slug = 'acme'
         ON CONFLICT (organization_id, control) DO UPDATE SET mode = EXCLUDED.mode, version = security_controls.version + 1`,
        [mode],
      );
    },
    send: async (v) => {
      const res = await sapp.request(v.path, {
        method: v.method,
        headers: { Authorization: `Bearer ${tokens.admin}`, "Content-Type": "application/json" },
        ...(v.method === "GET" || v.method === "DELETE" ? {} : { body: JSON.stringify(v.body) }),
      });
      const parsed = (await res.json().catch(() => null)) as { error?: { code: string } } | null;
      await accessCountsSettled();
      return { status: res.status, code: parsed?.error?.code ?? null, shape: shapeOf(parsed) };
    },
    prepare: async (v) => {
      if (ON_REGISTRATION.has(v.key)) await insertPendingRegistration(sctx, "acme", admin);
    },
    state: () => fingerprint(sctx.db),
    denials: async () =>
      ((await sctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE metadata::jsonb->>'reason' = 'passkey_verification_required'")).rows[0] as { n: number }).n,
    fresh: async () => {
      await current.pg.close();
      current = await fixtureDb(data);
      sctx = { db: current.db, rootKek };
      sapp = buildApp(sctx, { publicUrl: PUBLIC_URL });
    },
    close: async () => {
      resolver.restore();
      await current.pg.close();
    },
  };
}

/** One variant's off-mode answer and effects: what the baseline records. */
export interface OffRecord { status: number; code: string | null; shape: unknown; tables: string[] }

/**
 * One variant with the control off, on the fixtures exactly (each variant
 * starts from them: any earlier change was undone by `fresh`): its answer
 * and the tables it changed. The baseline and the sweep both take it this
 * way, so they compare like with like.
 */
export async function offRun(s: Sweeper, v: Variant): Promise<{ answer: Answer; record: OffRecord }> {
  await s.setMode("off");
  await s.prepare(v);
  const before = await s.state();
  const answer = await s.send(v);
  const tables = changedTables(before, await s.state());
  if (tables.length > 0) await s.fresh();
  return { answer, record: { status: answer.status, code: answer.code, shape: answer.shape, tables } };
}

/** The off-mode baseline: every variant, the blocked admin, the control off. */
export async function recordOff(rootKek: Buffer): Promise<Record<string, OffRecord>> {
  const s = await sweeper(rootKek);
  const out: Record<string, OffRecord> = {};
  for (const v of s.variants()) out[v.label] = (await offRun(s, v)).record;
  await s.close();
  return out;
}
