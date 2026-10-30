// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { Querier } from "../src/db/migrate.js";
import { SerializationRetriesExhausted, withSerializableTx, withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { loadGrants } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Removing a person from an Organization, leaving, and role changes
 * (ADR-0052 Decisions 1 to 5).
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: { id: string; token: string };
let orgId: string;
let projectId: string;
let devId: string;
let prodId: string;

async function call(method: string, path: string, body?: unknown, token = admin.token) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function addHuman(name: string, role: "admin" | "member") {
  const invite = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, invite.token, {});
  const token = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  return { id: identityId, token };
}

async function grant(subjectIdentityId: string, scope: Record<string, unknown>, actions: string[]) {
  const res = await call("POST", `${ORG}/grants`, { subjectIdentityId, scope, actions });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.id as string;
}

async function events(eventType: string) {
  const res = await ctx.db.query(
    "SELECT actor_identity_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order",
    [eventType],
  );
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, unknown>;
  return (res.rows as { actor_identity_id: string; resource: unknown; metadata: unknown }[]).map((r) => ({
    actor: r.actor_identity_id,
    resource: parse(r.resource),
    metadata: parse(r.metadata),
  }));
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  admin = { id: identityId, token: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  app = buildApp(ctx);
  orgId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  projectId = (await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
  devId = (await call("POST", `${P}/environments`, { name: "development", tier: "development" })).body.id;
  prodId = (await call("POST", `${P}/environments`, { name: "production", tier: "production" })).body.id;
});
afterEach(async () => {
  await ctx.close();
});

describe("removing a member", () => {
  it("is advertised in /v1/meta", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("members.lifecycle");
  });

  it("ends their access from the next request, and cleans up what removal owns", async () => {
    const bob = await addHuman("Bob", "member");
    const reveal = await grant(bob.id, { kind: "environments", projectId, selector: { kind: "environments", environmentIds: [prodId] } }, ["secret.reveal"]);
    await grant(bob.id, { kind: "organization" }, ["identity.manage"]);
    const group = (await call("POST", `${ORG}/groups`, { name: "ops" })).body.id as string;
    expect((await call("POST", `${ORG}/groups/${group}/members`, { identityId: bob.id })).status).toBe(204);
    const invitation = await call("POST", `${ORG}/invitations`, { name: "Carol", role: "member" }, bob.token);
    expect(invitation.status).toBe(201);
    expect((await call("GET", ORG, undefined, bob.token)).status).toBe(200);

    const removed = await call("DELETE", `${ORG}/members/${bob.id}`);
    expect(removed.status, JSON.stringify(removed.body)).toBe(200);
    expect(removed.body).toMatchObject({
      identityId: bob.id,
      role: "member",
      left: false,
      grantsRevoked: 2,
      groupsLeft: 1,
      invitationsRevoked: 1,
    });

    // Their sign-in still works; the Organization is gone for them.
    expect((await call("GET", "/v1/me", undefined, bob.token)).status).toBe(200);
    expect((await call("GET", ORG, undefined, bob.token)).status).toBe(404);
    expect((await call("GET", "/v1/organizations", undefined, bob.token)).body.items).toEqual([]);
    expect((await call("GET", `${P}/environments`, undefined, bob.token)).status).toBe(404);

    // Former members stay listed, without a role.
    const listed = (await call("GET", `${ORG}/identities`)).body.items.find((i: { id: string }) => i.id === bob.id);
    expect(listed).toMatchObject({ orgRole: null });
    expect(listed.removedAt).toEqual(expect.any(String));

    const grants = (await call("GET", `${ORG}/grants`)).body.items as { id: string }[];
    expect(grants.map((g) => g.id)).not.toContain(reveal);
    expect((await call("GET", `${ORG}/groups/${group}/members`)).body.items).toEqual([]);
    const invitations = (await call("GET", `${ORG}/invitations?status=all`)).body.items;
    expect(invitations.find((i: { id: string }) => i.id === invitation.body.id)).toMatchObject({ status: "revoked" });

    expect(await events("membership.removed")).toEqual([
      {
        actor: admin.id,
        resource: { identityId: bob.id, removalId: removed.body.removalId },
        metadata: { role: "member", left: false, grantsRevoked: 2, groupsLeft: 1, invitationsRevoked: 1 },
      },
    ]);

    // Nothing more to remove; nothing can be given to them again.
    expect((await call("DELETE", `${ORG}/members/${bob.id}`)).status).toBe(404);
    expect((await call("POST", `${ORG}/grants`, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["audit.read"] })).status).toBe(404);
    expect((await call("POST", `${ORG}/groups/${group}/members`, { identityId: bob.id })).status).toBe(404);
  });

  it("a Grant row left behind gives a removed person nothing", async () => {
    const bob = await addHuman("Bob", "member");
    expect((await call("DELETE", `${ORG}/members/${bob.id}`)).status).toBe(200);
    await ctx.db.query(
      `INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions) VALUES ('grt_left', $1, $2, '{"kind":"organization"}', $3)`,
      [orgId, bob.id, ["organization.read", "secret.reveal"]],
    );
    expect(await loadGrants(ctx, orgId, bob.id)).toEqual([]);
    expect((await call("GET", ORG, undefined, bob.token)).status).toBe(404);
  });

  it("machine Grants keep working", async () => {
    const bob = await addHuman("Bob", "member");
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service" })).body;
    await grant(svc.id, { kind: "project", projectId }, ["environment.read"]);
    expect((await call("DELETE", `${ORG}/members/${bob.id}`)).status).toBe(200);
    expect((await call("GET", `${P}/environments/development`, undefined, svc.credential)).status).toBe(200);
    // Grants for machines of another Organization are refused.
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    const foreign = (await call("POST", "/v1/organizations/other/identities", { name: "x", kind: "service" })).body;
    expect((await call("POST", `${ORG}/grants`, { subjectIdentityId: foreign.id, scope: { kind: "organization" }, actions: ["audit.read"] })).status).toBe(404);
  });

  it("needs a live built-in admin; an explicit Grant does not substitute", async () => {
    const bob = await addHuman("Bob", "member");
    const carol = await addHuman("Carol", "member");
    await grant(bob.id, { kind: "organization" }, ["organization.manage", "identity.manage", "policy.manage"]);
    for (const res of [
      await call("DELETE", `${ORG}/members/${carol.id}`, undefined, bob.token),
      await call("PATCH", `${ORG}/members/${carol.id}`, { role: "admin" }, bob.token),
      await call("PATCH", `${ORG}/members/${bob.id}`, { role: "admin" }, bob.token),
      await call("GET", `${ORG}/members/${carol.id}/review`, undefined, bob.token),
    ]) {
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe("PERMISSION_DENIED");
    }
    expect(await events("membership.removed")).toEqual([]);
    const denials = await events("authorization.denied");
    expect(denials).toHaveLength(4);
    expect(denials[0]).toMatchObject({
      actor: bob.id,
      resource: { identityId: carol.id },
      metadata: { operation: "DELETE members", reason: "not-admin" },
    });
    // Someone who cannot see the Organization learns nothing about it.
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    expect((await call("DELETE", `/v1/organizations/other/members/${admin.id}`, undefined, bob.token)).status).toBe(404);
  });

  it("a removed admin is denied at once", async () => {
    const bob = await addHuman("Bob", "admin");
    expect((await call("DELETE", `${ORG}/members/${bob.id}`)).status).toBe(200);
    expect((await call("DELETE", `${ORG}/members/${admin.id}`, undefined, bob.token)).status).toBe(404);
    expect((await call("POST", `${ORG}/invitations`, { name: "Eve", role: "admin" }, bob.token)).status).toBe(404);
  });

  it("a member can leave; the event names them as actor", async () => {
    const bob = await addHuman("Bob", "member");
    const left = await call("DELETE", `${ORG}/members/me`, undefined, bob.token);
    expect(left.status).toBe(200);
    expect(left.body).toMatchObject({ identityId: bob.id, left: true });
    expect((await events("membership.removed"))[0]).toMatchObject({ actor: bob.id, metadata: { left: true } });
  });
});

describe("the last admin and role changes", () => {
  it("the last admin can neither be removed, nor leave, nor be demoted", async () => {
    for (const res of [
      await call("DELETE", `${ORG}/members/me`),
      await call("DELETE", `${ORG}/members/${admin.id}`),
      await call("PATCH", `${ORG}/members/${admin.id}`, { role: "member" }),
    ]) {
      expect(res.status).toBe(422);
      expect(res.body.error.details).toEqual({ reason: "last-admin" });
    }
  });

  it("promotes and demotes, records the change, and keeps explicit Grants", async () => {
    const bob = await addHuman("Bob", "member");
    const promoted = await call("PATCH", `${ORG}/members/${bob.id}`, { role: "admin" });
    expect(promoted.body).toEqual({ identityId: bob.id, role: "admin", previousRole: "member" });
    // The same role again changes and records nothing.
    expect((await call("PATCH", `${ORG}/members/${bob.id}`, { role: "admin" })).body.previousRole).toBe("admin");
    expect(await events("membership.role_changed")).toHaveLength(1);

    // The first admin demotes themselves now that Bob is an admin too.
    await grant(admin.id, { kind: "organization" }, ["audit.read"]);
    expect((await call("PATCH", `${ORG}/members/${admin.id}`, { role: "member" })).status).toBe(200);
    expect((await call("GET", `${ORG}/audit-events?limit=1`)).status).toBe(200);
    expect((await call("POST", `${ORG}/invitations`, { name: "Eve", role: "member" })).status).toBe(403);
    // Bob is the last admin now.
    expect((await call("DELETE", `${ORG}/members/me`, undefined, bob.token)).status).toBe(422);
    expect((await events("membership.role_changed")).map((e) => e.metadata)).toEqual([
      { previousRole: "member", role: "admin" },
      { previousRole: "admin", role: "member" },
    ]);
  });

  it("refuses an unknown role", async () => {
    const bob = await addHuman("Bob", "member");
    expect((await call("PATCH", `${ORG}/members/${bob.id}`, { role: "owner" })).status).toBe(422);
  });
});

describe("the authority snapshot", () => {
  it("records granted value actions per environment with their sources, and Requirements as copies", async () => {
    const bob = await addHuman("Bob", "member");
    const reveal = await grant(bob.id, { kind: "environments", projectId, selector: { kind: "environments", environmentIds: [prodId] } }, ["secret.reveal"]);
    const group = (await call("POST", `${ORG}/groups`, { name: "readers" })).body.id as string;
    await call("POST", `${ORG}/groups/${group}/members`, { identityId: bob.id });
    const viaGroup = (await call("POST", `${ORG}/grants`, { subjectGroupId: group, scope: { kind: "project", projectId }, actions: ["config.metadata.read"] })).body.id;
    const requirement = await call("POST", `${ORG}/requirements`, {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    expect(requirement.status).toBe(201);

    const removed = await call("DELETE", `${ORG}/members/${bob.id}`);
    const removalId = removed.body.removalId as string;
    const rows = (
      await ctx.db.query(
        "SELECT environment_id, action, source, role, grant_id, via_group_id FROM removal_authority WHERE removal_id = $1 ORDER BY environment_id, action, source",
        [removalId],
      )
    ).rows as Record<string, string | null>[];
    const prod = rows.filter((r) => r.environment_id === prodId).map((r) => `${r.action} ${r.source}`);
    expect(prod.sort()).toEqual(
      [
        "config.metadata.read role:member",
        `config.metadata.read grant:${viaGroup}`,
        `secret.reveal grant:${reveal}`,
      ].sort(),
    );
    expect(rows.find((r) => r.grant_id === viaGroup && r.environment_id === prodId)?.via_group_id).toBe(group);
    const dev = rows.filter((r) => r.environment_id === devId).map((r) => `${r.action} ${r.source}`);
    expect(dev).toEqual(
      expect.arrayContaining(["config.value.read role:member", "secret.reveal role:member", "config.metadata.read role:member"]),
    );

    // Production's conditioned actions are conditional on the Requirement, copied as defined.
    const conditions = (await ctx.db.query("SELECT environment_id, requirement_id FROM removal_conditions WHERE removal_id = $1", [removalId])).rows;
    expect(conditions).toEqual([{ environment_id: prodId, requirement_id: requirement.body.id }]);
    const edited = await call("PATCH", `${ORG}/requirements/${requirement.body.id}`, {
      expectedVersion: requirement.body.version,
      selector: { tailnet: "example.ts.net", tags: ["tag:other"] },
    });
    expect(edited.status, JSON.stringify(edited.body)).toBe(200);
    const copy = (await ctx.db.query("SELECT selector FROM removal_requirements WHERE removal_id = $1", [removalId])).rows[0] as { selector: unknown };
    const selector = typeof copy.selector === "string" ? JSON.parse(copy.selector) : copy.selector;
    expect(selector).toEqual({ tailnet: "example.ts.net", tags: ["tag:prod"] });
  });
});

describe("the review list", () => {
  it("lists what the person created or changed, with states, before and at removal", async () => {
    const bob = await addHuman("Bob", "member");
    await grant(bob.id, { kind: "organization" }, ["config.sync.manage", "organization.manage", "identity.manage", "policy.manage"]);
    const own = (await call("POST", `${ORG}/platform-connections`, {
      platform: "coolify", baseIdentity: "https://coolify.example.com", name: "bob's", credential: "token-bob",
    }, bob.token)).body;
    expect(own.id).toEqual(expect.any(String));
    const shared = (await call("POST", `${ORG}/platform-connections`, {
      platform: "coolify", baseIdentity: "https://coolify2.example.com", name: "shared", credential: "token-admin",
    })).body;
    expect((await call("POST", `${ORG}/platform-connections/${shared.id}/credential`, { credential: "token-bob-2", expectedVersion: shared.version }, bob.token)).status).toBe(200);
    const target = await call("POST", `${P}/environments/development/sync-targets`, {
      connectionId: own.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" },
    }, bob.token);
    expect(target.status, JSON.stringify(target.body)).toBe(201);
    const hook = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hooks?token=secret" }, bob.token)).body;
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service", credentialTtlSeconds: 1 }, bob.token)).body;
    const personal = await call("POST", `${P}/environments`, { name: "development/bob", kind: "personal", parentEnvironmentId: devId }, bob.token);
    expect(personal.status, JSON.stringify(personal.body)).toBe(201);

    const preview = await call("GET", `${ORG}/members/${bob.id}/review`);
    expect(preview.status).toBe(200);
    expect(preview.body.syncTargets).toEqual([
      expect.objectContaining({ id: target.body.id, state: "active", changes: ["created"], platform: "coolify" }),
    ]);
    expect(preview.body.connections).toEqual([
      expect.objectContaining({ id: own.id, name: "bob's", revoked: false, changes: ["created"] }),
      expect.objectContaining({ id: shared.id, name: "shared", revoked: false, changes: ["credential_replaced"] }),
    ]);
    expect(preview.body.webhooks).toEqual([{ id: hook.id, host: "sink.example", revoked: false }]);
    expect(preview.body.credentials).toEqual([
      expect.objectContaining({ identityId: svc.id, identityName: "deployer", state: expect.stringMatching(/^(valid|expired)$/) }),
    ]);
    expect(preview.body.personalEnvironments).toEqual([{ id: personal.body.id, name: "development/bob", projectId }]);
    expect(JSON.stringify(preview.body)).not.toContain("token=secret");

    // A member may see their own list, not someone else's.
    expect((await call("GET", `${ORG}/members/me/review`, undefined, bob.token)).status).toBe(200);
    expect((await call("GET", `${ORG}/members/${admin.id}/review`, undefined, bob.token)).status).toBe(403);

    // Removal changes none of it, and returns the same list.
    await ctx.db.query("UPDATE credentials SET revoked_at = now() WHERE identity_id = $1", [svc.id]);
    const removed = await call("DELETE", `${ORG}/members/${bob.id}`);
    expect(removed.body.review.credentials[0].state).toBe("revoked");
    expect(removed.body.review.syncTargets).toEqual(preview.body.syncTargets);
    expect((await call("GET", `${P}/environments/development/sync-targets`)).body.items).toHaveLength(1);
  });
});

describe("withSerializableTx", () => {
  function fakeDb(failures: number): Querier & { statements: string[] } {
    let failed = 0;
    const statements: string[] = [];
    return {
      statements,
      query: async (sql: string) => {
        statements.push(sql);
        if (sql === "WORK" && failed < failures) {
          failed++;
          throw Object.assign(new Error("could not serialize access"), { code: "40001" });
        }
        return { rows: [] };
      },
    } as unknown as Querier & { statements: string[] };
  }

  it("runs the whole transaction again on a serialization failure", async () => {
    const db = fakeDb(2);
    let runs = 0;
    await withSerializableTx(db, async (tx) => {
      runs++;
      await tx.query("WORK");
    }, { backoffMs: 0 });
    expect(runs).toBe(3);
    expect(db.statements.filter((s) => s.startsWith("BEGIN ISOLATION LEVEL SERIALIZABLE"))).toHaveLength(3);
    expect(db.statements.at(-1)).toBe("COMMIT");
  });

  it("gives up after five attempts, having changed nothing", async () => {
    const db = fakeDb(99);
    await expect(withSerializableTx(db, (tx) => tx.query("WORK"), { backoffMs: 0 })).rejects.toBeInstanceOf(
      SerializationRetriesExhausted,
    );
    expect(db.statements.filter((s) => s === "ROLLBACK")).toHaveLength(5);
    expect(db.statements).not.toContain("COMMIT");
  });

  it("does not retry other errors, and refuses to nest", async () => {
    const db = fakeDb(0);
    await expect(withSerializableTx(db, async () => { throw new Error("boom"); }, { backoffMs: 0 })).rejects.toThrow("boom");
    await expect(withTx(ctx.db, (tx) => withSerializableTx(tx, async () => 1))).rejects.toThrow(/cannot start inside/);
  });
});
