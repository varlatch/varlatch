// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withAttribution } from "../src/audit/attribution.js";
import { recordAuditEvent } from "../src/audit/events.js";
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

/**
 * Attribution (ADR-0016 §9): an event an authenticated /v1 request records
 * for its own identity names the credential that made the request and the
 * client its User-Agent describes, so the audit log tells a person's
 * dashboard from their CLI, a coding agent in assisted mode from the human,
 * and one machine from another sharing an identity. A caller's explicit
 * credentialId (the credential an event is about) is never replaced, and
 * events no authenticated request records stay unattributed.
 */

const UA = {
  assisted: "varlatch-cli/0.16.0 (linux; x64; assisted)",
  cli: "varlatch-cli/0.16.0 (darwin; arm64)",
  mcp: "varlatch-mcp/0.16.0 (linux; x64)",
  firefox: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  curl: "curl/8.9.1",
};

const ENV = "/v1/organizations/acme/projects/api/environments/production";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let cli: { credentialId: string; token: string };
let browser: { credentialId: string; token: string };

async function call(
  method: string,
  path: string,
  opts: { token?: string; ua?: string; body?: unknown } = {},
): Promise<{ status: number; body: any }> {
  const res = await app.request(path, {
    method,
    headers: {
      Authorization: `Bearer ${opts.token ?? cli.token}`,
      "Content-Type": "application/json",
      ...(opts.ua ? { "User-Agent": opts.ua } : {}),
    },
    ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

interface Row {
  id: string;
  event_type: string;
  actor_identity_id: string | null;
  credential_id: string | null;
  client: string | null;
}

async function rows(where = "true", params: unknown[] = []): Promise<Row[]> {
  const res = await ctx.db.query(
    `SELECT id, event_type, actor_identity_id, credential_id, client FROM audit_events WHERE ${where} ORDER BY event_order`,
    params,
  );
  return res.rows as Row[];
}

async function last(eventType: string): Promise<Row> {
  const found = await rows("event_type = $1", [eventType]);
  expect(found.length, eventType).toBeGreaterThan(0);
  return found[found.length - 1]!;
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
  cli = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", name: "laptop CLI", client: "varlatch CLI 0.16.0 on Linux" });
  browser = await issueCredential(ctx.db, { identityId: adminId, kind: "browser", name: "dashboard session bearer", client: "Firefox on Linux" });
  app = buildApp(ctx);
  expect((await call("POST", "/v1/organizations", { body: { name: "Acme", slug: "acme" } })).status).toBe(201);
  expect((await call("POST", "/v1/organizations/acme/projects", { body: { name: "API", slug: "api", contractAuthority: "git" } })).status).toBe(201);
  expect(
    (await call("POST", "/v1/organizations/acme/projects/api/environments", { body: { name: "production", tier: "production" } })).status,
  ).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("events a request records name its credential and client", () => {
  it("value writes, disclosures, and validations carry the acting credential and client", async () => {
    expect((await call("PUT", `${ENV}/values/API_TOKEN`, { ua: UA.assisted, body: { value: "tok-abc-123" } })).status).toBe(200);
    expect(await last("value.written")).toMatchObject({
      actor_identity_id: adminId,
      credential_id: cli.credentialId,
      client: "varlatch CLI 0.16.0 on Linux, assisted",
    });

    // The same person from the dashboard: another credential, another client.
    expect((await call("POST", `${ENV}/disclosures`, { token: browser.token, ua: UA.firefox, body: { items: ["API_TOKEN"] } })).status).toBe(200);
    expect(await last("secret.disclosed")).toMatchObject({
      actor_identity_id: adminId,
      credential_id: browser.credentialId,
      client: "Firefox on Linux",
    });

    // Validation decrypts, and is audited before it does.
    const contract = {
      schemaVersion: 1,
      items: [
        { name: "API_TOKEN", required: { kind: "always" }, sensitive: true, type: "string" },
        { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number" },
      ],
    };
    const pushed = await call("POST", "/v1/organizations/acme/projects/api/contract/revisions", { body: { contract } });
    expect(pushed.status).toBe(201);
    expect((await call("POST", `/v1/organizations/acme/projects/api/contract/revisions/${pushed.body.id}/activate`, { body: {} })).status).toBe(200);
    expect((await call("PUT", `${ENV}/values/PORT`, { body: { value: "8080" } })).status).toBe(200);
    expect((await call("POST", `${ENV}/validate`, { ua: UA.mcp, body: {} })).status).toBe(200);
    for (const type of ["secret.validated", "value.validated"]) {
      expect(await last(type), type).toMatchObject({ credential_id: cli.credentialId, client: "varlatch MCP 0.16.0 on Linux" });
    }
    // Contract changes are attributed too: every event of the identity is.
    expect(await last("contract.activated")).toMatchObject({ credential_id: cli.credentialId, client: null });
  });

  it("names the credential when the client is not recognized, and a denial's client too", async () => {
    expect((await call("PUT", `${ENV}/values/PORT`, { ua: UA.curl, body: { value: "8080" } })).status).toBe(200);
    expect(await last("value.written")).toMatchObject({ credential_id: cli.credentialId, client: null });

    const svc = await call("POST", "/v1/organizations/acme/identities", { body: { name: "runner", kind: "service" } });
    expect(svc.status).toBe(201);
    const runnerCredential = (await ctx.db.query("SELECT id FROM credentials WHERE identity_id = $1", [svc.body.id])).rows[0] as { id: string };
    expect((await call("GET", "/v1/organizations/acme/audit-events", { token: svc.body.credential, ua: UA.cli })).status).toBe(403);
    expect(await last("authorization.denied")).toMatchObject({
      actor_identity_id: svc.body.id,
      credential_id: runnerCredential.id,
      client: "varlatch CLI 0.16.0 on macOS",
    });
  });

  it("never replaces a credential the event is about", async () => {
    // A machine identity's creation: identity.created is the admin acting,
    // credential.issued names the machine's new credential.
    const svc = await call("POST", "/v1/organizations/acme/identities", { ua: UA.firefox, token: browser.token, body: { name: "runner", kind: "service" } });
    const issuedFor = (await ctx.db.query("SELECT id FROM credentials WHERE identity_id = $1", [svc.body.id])).rows[0] as { id: string };
    expect(await last("identity.created")).toMatchObject({ credential_id: browser.credentialId, client: "Firefox on Linux" });
    expect(await last("credential.issued")).toMatchObject({ actor_identity_id: adminId, credential_id: issuedFor.id });

    // Revoking another of one's own credentials from the dashboard: the event
    // names the revoked credential, and the client the request came from.
    const spare = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", name: "old laptop" });
    expect((await call("DELETE", `/v1/me/credentials/${spare.credentialId}`, { token: browser.token, ua: UA.firefox })).status).toBe(204);
    expect(await last("credential.revoked")).toMatchObject({
      actor_identity_id: adminId,
      credential_id: spare.credentialId,
      client: "Firefox on Linux",
    });

    // The CLI exchange revokes the presenting browser bearer and issues a CLI credential.
    const handoff = await issueCredential(ctx.db, { identityId: adminId, kind: "browser", name: "handoff" });
    const exchanged = await call("POST", "/v1/me/credentials/cli", { token: handoff.token, ua: UA.cli, body: {} });
    expect(exchanged.status).toBe(201);
    expect(await last("credential.revoked")).toMatchObject({ credential_id: handoff.credentialId, client: "varlatch CLI 0.16.0 on macOS" });
    expect(await last("credential.issued")).toMatchObject({ credential_id: exchanged.body.id });
  });

  it("advertises audit.attribution", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("audit.attribution");
  });

  it("leaves events no authenticated request records unattributed", async () => {
    // A failed authentication has no principal, whatever its User-Agent says.
    expect((await call("GET", "/v1/organizations", { token: "vlt_cli_not-a-credential", ua: UA.assisted })).status).toBe(401);
    expect(await last("authentication.failed")).toMatchObject({ actor_identity_id: null, credential_id: null, client: null });
  });
});

describe("the audit writer's rule", () => {
  const acting = { identityId: "idn_actor", credentialId: "crd_acting", client: "varlatch CLI 0.16.0 on Linux, assisted" };
  async function written(event: Parameters<typeof recordAuditEvent>[1], inRequest = true) {
    const id = inRequest
      ? await withAttribution(acting, () => recordAuditEvent(ctx.db, event))
      : await recordAuditEvent(ctx.db, event);
    return (await rows("id = $1", [id]))[0];
  }

  it("fills the credential and client only for the request's own identity", async () => {
    expect(await written({ eventType: "test.own", decision: "info", actorIdentityId: "idn_actor" })).toMatchObject({
      credential_id: "crd_acting",
      client: acting.client,
    });
    for (const actorIdentityId of ["idn_other", null, undefined]) {
      expect(await written({ eventType: "test.other", decision: "info", actorIdentityId }), String(actorIdentityId)).toMatchObject({
        credential_id: null,
        client: null,
      });
    }
  });

  it("keeps what the caller gave, null included, field by field", async () => {
    const actor = { eventType: "test.explicit", decision: "info" as const, actorIdentityId: "idn_actor" };
    expect(await written({ ...actor, credentialId: "crd_subject" })).toMatchObject({ credential_id: "crd_subject", client: acting.client });
    expect(await written({ ...actor, credentialId: null })).toMatchObject({ credential_id: null, client: acting.client });
    expect(await written({ ...actor, client: null })).toMatchObject({ credential_id: "crd_acting", client: null });
  });

  it("attributes nothing outside a request: background work keeps its events as they are", async () => {
    expect(await written({ eventType: "sync.push_attempted", decision: "info", actorIdentityId: "idn_actor" }, false)).toMatchObject({
      credential_id: null,
      client: null,
    });
  });

  it("ends with the request: work started after it is not attributed", async () => {
    await withAttribution(acting, async () => undefined);
    expect(await written({ eventType: "test.after", decision: "info", actorIdentityId: "idn_actor" }, false)).toMatchObject({
      credential_id: null,
    });
  });
});
