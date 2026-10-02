// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VarlatchClient } from "@varlatch/sdk";
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
 * Server-side audit filters (capability audit.filters) on the listing and
 * the NDJSON export: ANDed, validated with VALIDATION_FAILED, authorization
 * unchanged, and cursor pagination still exact and deterministic.
 */

interface Event {
  eventId: string;
  eventType: string;
  occurredAt: string;
  decision: string;
  actorIdentityId: string | null;
  resource: Record<string, string | null> | null;
  metadata: Record<string, unknown> | null;
}

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let adminToken: string;
let client: VarlatchClient;
let orgId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  const fetchImpl: typeof fetch = (input, init) =>
    app.request(input instanceof Request ? input : String(input).replace("http://varlatch", ""), init);
  client = new VarlatchClient({ server: "http://varlatch", token: adminToken, fetch: fetchImpl });
  orgId = (await client.createOrganization({ name: "Acme", slug: "acme" })).id;
});
afterEach(async () => {
  await ctx.close();
});

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

/** Every page of a filtered listing, following cursors with the same filters. */
async function everyPage(filters: Parameters<VarlatchClient["listAuditEvents"]>[1] = {}, limit = 500): Promise<Event[]> {
  const events: Event[] = [];
  let cursor: string | undefined;
  for (let pages = 0; pages < 100; pages++) {
    const page = await client.listAuditEvents("acme", { ...filters, limit, ...(cursor ? { cursor } : {}) });
    events.push(...(page.items as unknown as Event[]));
    if (!page.nextCursor) return events;
    cursor = page.nextCursor;
  }
  throw new Error("pagination did not end");
}

async function exported(filters: Parameters<VarlatchClient["exportAuditEventsNdjson"]>[1] = {}): Promise<Event[]> {
  const text = await client.exportAuditEventsNdjson("acme", filters);
  return text.trim() === "" ? [] : text.trim().split("\n").map((line) => JSON.parse(line) as Event);
}

describe("filters over real events", () => {
  let api: { id: string };
  let web: { id: string };
  let dev: { id: string };
  let prod: { id: string };
  let svc: { id: string; credential: string };

  beforeEach(async () => {
    api = await client.createProject("acme", { name: "API", slug: "api", contractAuthority: "git" });
    web = await client.createProject("acme", { name: "Web", slug: "web", contractAuthority: "git" });
    dev = await client.createEnvironment("acme", "api", { name: "development", tier: "development" });
    prod = await client.createEnvironment("acme", "api", { name: "production", tier: "production" });
    await client.createEnvironment("acme", "web", { name: "development", tier: "development" });
    await client.setValue("acme", "api", "development", "DB_URL", { value: "postgres://dev" });
    await client.setValue("acme", "api", "development", "DB_URL_RO", { value: "postgres://ro" });
    await client.setValue("acme", "api", "production", "DB_URL", { value: "postgres://prod" });
    await client.setValue("acme", "web", "development", "DB_URL", { value: "postgres://web" });
    await client.deleteValue("acme", "api", "development", "DB_URL_RO");
    await client.discloseSecrets("acme", "api", "development", { items: ["DB_URL"] });
    svc = (await call("POST", "/v1/organizations/acme/identities", { name: "runner", kind: "service" })).body;
    // A denial: the machine identity has no grants.
    expect((await call("GET", "/v1/organizations/acme/audit-events", undefined, svc.credential)).status).toBe(403);
  });

  it("filters by decision, exact event type, and event type prefix", async () => {
    const all = await everyPage();
    const denied = await everyPage({ decision: "deny" });
    expect(denied.length).toBeGreaterThan(0);
    expect(denied).toEqual(all.filter((e) => e.decision === "deny"));
    expect(denied.map((e) => e.eventType)).toContain("authorization.denied");

    const written = await everyPage({ eventType: "value.written" });
    expect(written.map((e) => e.eventType)).toEqual(["value.written", "value.written", "value.written", "value.written"]);

    const values = await everyPage({ eventType: "value.*" });
    expect(new Set(values.map((e) => e.eventType))).toEqual(new Set(["value.written", "value.deleted"]));
    expect(values).toEqual(all.filter((e) => e.eventType.startsWith("value.")));
    // A prefix ends at a dot: value.* is not values.* nor a substring match.
    expect(await everyPage({ eventType: "valu.*" })).toEqual([]);
    expect(await everyPage({ eventType: "value" })).toEqual([]);
  });

  it("filters by actor, project, environment, and item, ANDed", async () => {
    const all = await everyPage();
    expect(await everyPage({ actorIdentityId: svc.id })).toEqual(all.filter((e) => e.actorIdentityId === svc.id));
    expect((await everyPage({ actorIdentityId: svc.id })).length).toBeGreaterThan(0);

    const apiEvents = await everyPage({ projectId: api.id });
    expect(apiEvents).toEqual(all.filter((e) => e.resource?.projectId === api.id));
    expect(apiEvents.some((e) => e.eventType === "project.created")).toBe(true);
    expect(apiEvents.every((e) => e.resource?.projectId !== web.id)).toBe(true);

    expect(await everyPage({ environmentId: prod.id })).toEqual(all.filter((e) => e.resource?.environmentId === prod.id));

    // An item matches its resource (writes, deletions) and disclosure lists
    // (NAME@version), by exact name: DB_URL is not DB_URL_RO.
    const dbUrl = await everyPage({ item: "DB_URL" });
    expect(dbUrl.map((e) => e.eventType).sort()).toEqual(["secret.disclosed", "value.written", "value.written", "value.written"]);
    const disclosed = dbUrl.find((e) => e.eventType === "secret.disclosed")!;
    expect(String(disclosed.metadata?.items)).toMatch(/^DB_URL@ver_/);
    const ro = await everyPage({ item: "DB_URL_RO" });
    expect(ro.map((e) => e.eventType).sort()).toEqual(["value.deleted", "value.written"]);
    expect(await everyPage({ item: "DB" })).toEqual([]);

    const anded = await everyPage({ item: "DB_URL", eventType: "value.*", environmentId: dev.id, decision: "info" });
    expect(anded).toHaveLength(1);
    expect(anded[0]).toMatchObject({ eventType: "value.written", resource: { environmentId: dev.id, itemName: "DB_URL" } });
    expect(await everyPage({ item: "DB_URL", projectId: web.id, eventType: "secret.disclosed" })).toEqual([]);
  });

  it("filters the NDJSON export the same way", async () => {
    // The export runs in commit order, the listing by (occurredAt, eventId):
    // the same events, not necessarily in reverse order of each other.
    const ids = (events: Event[]) => events.map((e) => e.eventId).sort();
    for (const filters of [{ eventType: "value.*" }, { item: "DB_URL", projectId: api.id }, { decision: "deny" as const }]) {
      const listed = await everyPage(filters);
      expect(listed.length).toBeGreaterThan(0);
      expect(ids(await exported(filters))).toEqual(ids(listed));
    }
    expect(ids(await exported())).toEqual(ids(await everyPage()));
  });

  it("leaves authorization unchanged", async () => {
    const res = await call("GET", "/v1/organizations/acme/audit-events?decision=deny&item=DB_URL", undefined, svc.credential);
    expect(res.status).toBe(403);
    const exportRes = await call("GET", "/v1/organizations/acme/audit-events/export?eventType=value.*", undefined, svc.credential);
    expect(exportRes.status).toBe(403);
  });
});

describe("time windows and pagination", () => {
  /** Synthetic events at chosen instants, some sharing one instant. */
  async function seed(): Promise<{ id: string; at: string; decision: string; type: string }[]> {
    const rows = [];
    for (let i = 0; i < 24; i++) {
      // Pairs share a timestamp, so the eventId tie-break decides their order.
      const at = `2026-09-01T00:00:${String(Math.floor(i / 2)).padStart(2, "0")}.000001Z`;
      const row = {
        id: `evt_t${String(i).padStart(2, "0")}${i % 3 === 0 ? "a" : "b"}`,
        at,
        decision: i % 2 === 0 ? "deny" : "allow",
        type: i % 4 === 0 ? "test.alpha" : "test.beta",
      };
      await ctx.db.query(
        "INSERT INTO audit_events (id, event_type, organization_id, decision, occurred_at) VALUES ($1,$2,$3,$4,$5::timestamptz)",
        [row.id, row.type, orgId, row.decision, row.at],
      );
      rows.push(row);
    }
    return rows;
  }
  const newestFirst = (a: { at: string; id: string }, b: { at: string; id: string }) =>
    a.at === b.at ? (a.id < b.id ? 1 : -1) : a.at < b.at ? 1 : -1;

  it("pages a filtered listing exactly and deterministically", async () => {
    const rows = await seed();
    const expected = rows.filter((r) => r.decision === "deny" && r.type.startsWith("test.")).sort(newestFirst);
    for (const limit of [1, 2, 5, 7]) {
      const ids = (await everyPage({ decision: "deny", eventType: "test.*" }, limit)).map((e) => e.eventId);
      expect(ids, `limit ${limit}`).toEqual(expected.map((r) => r.id));
    }
    // Twice the same: deterministic.
    const again = (await everyPage({ decision: "deny", eventType: "test.*" }, 3)).map((e) => e.eventId);
    expect(again).toEqual(expected.map((r) => r.id));
  });

  it("includes since and excludes until, to the microsecond", async () => {
    const rows = await seed();
    const window = await everyPage({ eventType: "test.*", since: "2026-09-01T00:00:03.000001Z", until: "2026-09-01T00:00:06.000001Z" });
    const expected = rows.filter((r) => r.at >= "2026-09-01T00:00:03.000001Z" && r.at < "2026-09-01T00:00:06.000001Z").sort(newestFirst);
    expect(window.map((e) => e.eventId)).toEqual(expected.map((r) => r.id));
    expect(expected).toHaveLength(6);

    // One microsecond later excludes the events at since.
    const later = await everyPage({ eventType: "test.*", since: "2026-09-01T00:00:03.000002Z", until: "2026-09-01T00:00:06.000001Z" });
    expect(later).toHaveLength(4);
    // Offsets are honoured: the same instant written in another zone.
    const offset = await everyPage({ eventType: "test.*", since: "2026-09-01T02:00:03.000001+02:00", until: "2026-08-31T19:00:06.000001-05:00" });
    expect(offset.map((e) => e.eventId)).toEqual(expected.map((r) => r.id));
    // Lowercase t and z are RFC 3339 too.
    expect(await everyPage({ eventType: "test.*", since: "2026-09-01t00:00:03.000001z", until: "2026-09-01t00:00:06.000001z" })).toHaveLength(6);
    // since equal to until is an empty window, not an error.
    expect(await everyPage({ since: "2026-09-01T00:00:03Z", until: "2026-09-01T00:00:03Z" })).toEqual([]);

    const exportedWindow = await exported({ eventType: "test.*", since: "2026-09-01T00:00:03.000001Z", until: "2026-09-01T00:00:06.000001Z" });
    expect(new Set(exportedWindow.map((e) => e.eventId))).toEqual(new Set(expected.map((r) => r.id)));
  });
});

describe("validation", () => {
  const list = (query: string) => call("GET", `/v1/organizations/acme/audit-events?${query}`);
  const exportWith = (query: string) => call("GET", `/v1/organizations/acme/audit-events/export?${query}`);

  it("refuses malformed, empty, and repeated filters with VALIDATION_FAILED", async () => {
    const bad = [
      "decision=maybe",
      "decision=ALLOW",
      "decision=",
      "decision=allow&decision=deny",
      "eventType=*",
      "eventType=value.",
      "eventType=value.**",
      "eventType=Value.written",
      "eventType=value.wr*",
      "eventType=.value",
      `eventType=${"a".repeat(201)}`,
      "actorIdentityId=idn%20x",
      `projectId=${"p".repeat(201)}`,
      "environmentId=",
      "item=database_url",
      "item=1PASSWORD",
      "item=DB%20URL",
      "since=2026-10-01",
      "since=2026-10-01T00:00:00",
      "since=2026-10-01 00:00:00Z",
      "since=2026-02-30T00:00:00Z",
      "since=2026-13-01T00:00:00Z",
      "since=2026-10-01T24:00:00Z",
      "since=2026-10-01T00:60:00Z",
      "since=2026-10-01T00:00:60Z",
      "since=2026-10-01T00:00:00+24:00",
      "since=0000-01-01T00:00:00Z",
      "since=yesterday",
      "until=2026-10-01T00:00:00.1234567890Z",
      "since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
    ];
    for (const query of bad) {
      const res = await list(query);
      expect(res.status, query).toBe(422);
      expect(res.body.error.code, query).toBe("VALIDATION_FAILED");
      expect(res.body.error.message.length, query).toBeGreaterThan(10);
      const exp = await exportWith(query);
      expect(exp.status, `export ${query}`).toBe(422);
    }
  });

  it("accepts every well-formed filter, including a leap day", async () => {
    const res = await list(
      "decision=info&eventType=organization.*&actorIdentityId=" + adminId +
        "&since=2024-02-29T00:00:00.5%2B01:00&until=2099-12-31T23:59:59.999999Z",
    );
    expect(res.status).toBe(200);
    expect(res.body.items.map((e: Event) => e.eventType)).toEqual(["organization.created"]);
    expect((await list("projectId=prj_x&environmentId=env_x&item=DB_URL")).body).toEqual({ items: [], nextCursor: null });
  });

  it("advertises audit.filters", async () => {
    expect((await client.meta()).capabilities).toContain("audit.filters");
  });
});
