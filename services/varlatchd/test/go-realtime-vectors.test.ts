// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for Go's realtime signals (ADR-0059 step 3.5): the
 * changeSignals and identitySignals this server's own mirror publisher
 * (src/mirror/publisher.ts, syncNewMirrorEvents) pushes for fixed batches of
 * audit events, which go/server/realtime must work out the same way
 * (go/server/realtime/testdata/ts-vectors.json, read by vectors_test.go).
 *
 * Each batch is written to audit_events, then one syncNewMirrorEvents pass
 * reads exactly that batch, against a stand-in for Convex that records the
 * upserts. The batches cover every audit event type in and out of an
 * Organization, with and without an actor, read-only events, membership
 * changes (the affected person's id well formed, missing or empty),
 * organization.deleted in the middle of a batch, and the events of an
 * Organization deleted before publication. The positions all have six
 * digits: the publisher orders a pass by event_order as text, which differs
 * from numeric order across a change in the number of digits (Go orders by
 * the number).
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change to the publisher or this fixture, regenerate it and commit
 * the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-realtime-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { expect, it } from "vitest";
import { AUDIT_EVENT_TYPES } from "../src/audit/events.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { syncNewMirrorEvents, type MirrorConfig } from "../src/mirror/publisher.js";
import { migratedTestDb } from "./helpers/pglite.js";

const OUT = new URL("../../../go/server/realtime/testdata/ts-vectors.json", import.meta.url);

const ORGS = [
  { id: "org_a", slug: "a", deleted: false },
  { id: "org_b", slug: "b", deleted: false },
  { id: "org_gone", slug: "gone", deleted: true },
];

interface VectorEvent {
  id: string;
  type: string;
  organizationId: string | null;
  actor: string | null;
  credentialId: string | null;
  resource: unknown;
  occurredAt: string;
}

interface Signal {
  kind: "change" | "identity";
  key: string;
  lastEventId: string;
  occurredAt: string;
  domains: string[];
}

let clock = Date.parse("2026-11-14T10:00:00.000Z");
let serial = 0;
const ev = (type: string, organizationId: string | null, actor: string | null, resource: unknown = null, credentialId: string | null = null): VectorEvent => {
  serial++;
  clock += 1234;
  return {
    id: `evt_${String(serial).padStart(4, "0")}`,
    type,
    organizationId,
    actor,
    credentialId,
    resource,
    occurredAt: new Date(clock).toISOString(),
  };
};

const BATCHES: { name: string; events: VectorEvent[] }[] = [
  {
    name: "every event type in an Organization",
    events: AUDIT_EVENT_TYPES.map((t, i) => ev(t, i % 3 === 0 ? "org_b" : "org_a", i % 2 === 0 ? "idn_alice" : null)),
  },
  {
    name: "every event type outside an Organization",
    events: AUDIT_EVENT_TYPES.map((t, i) => ev(t, null, ["idn_alice", "idn_bob", null][i % 3] ?? null)),
  },
  {
    name: "read-only events only",
    events: [
      ev("value.disclosed", "org_a", "idn_alice"),
      ev("authorization.denied", "org_a", "idn_bob"),
      ev("authentication.failed", null, "idn_bob"),
      ev("capability.exercised", "org_b", null),
    ],
  },
  {
    name: "membership changes",
    events: [
      ev("membership.removed", "org_a", "idn_alice", { identityId: "idn_bob" }),
      ev("membership.role_changed", "org_b", "idn_alice", { identityId: "idn_carol", role: "admin" }),
      ev("membership.removed", "org_a", "idn_alice", { identityId: "" }),
      ev("membership.removed", "org_a", "idn_alice", null),
      ev("membership.removed", null, "idn_alice", { identityId: "idn_dave" }),
      ev("membership.created", "org_b", "idn_alice", { identityId: "idn_erin" }),
      ev("project.created", "org_a", "idn_bob"),
    ],
  },
  {
    name: "organization.deleted in the middle of a batch",
    events: [
      ev("project.created", "org_b", "idn_alice"),
      ev("grant.created", "org_a", "idn_alice"),
      ev("organization.deleted", "org_b", "idn_alice", { organizationId: "org_b" }),
      ev("membership.removed", "org_b", "idn_alice", { identityId: "idn_bob" }),
      ev("environment.created", "org_b", "idn_alice"),
      ev("organization.deleted", "org_a", "idn_alice"),
    ],
  },
  {
    name: "an Organization deleted before publication",
    events: [
      ev("project.created", "org_gone", "idn_alice"),
      ev("membership.removed", "org_gone", "idn_alice", { identityId: "idn_bob" }),
      ev("value.updated", "org_a", "idn_alice"),
      ev("credential.revoked", null, "idn_alice", { identityId: "idn_alice" }, "crd_1"),
    ],
  },
  {
    name: "empty Organization and actor ids",
    events: [ev("project.created", "", "idn_alice"), ev("credential.issued", null, ""), ev("credential.issued", "", "")],
  },
];

it("go/server/realtime/testdata/ts-vectors.json is what the mirror publisher pushes", async () => {
  const db = await migratedTestDb();
  const ctx: AppCtx & { close: () => Promise<void> } = { db, rootKek: generateKey(), close: db.close };
  try {
    for (const o of ORGS) {
      await db.query(
        `INSERT INTO organizations (id, slug, name, wrapped_org_kek, deleted_at) VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
        [o.id, o.slug, o.slug.toUpperCase(), o.deleted ? new Date(clock) : null],
      );
    }
    // Positions with the same number of digits throughout: the publisher's
    // pass orders by event_order cast to text (its output column), which is
    // numeric order only while the digit count does not change. Go orders
    // by the number (a difference recorded in go/server/realtime).
    await db.query("UPDATE audit_position SET value = 100000 WHERE singleton");
    const config: MirrorConfig = { convexUrl: "https://convex.test", issuer: "http://localhost" };
    const out: { name: string; events: VectorEvent[]; signals: Signal[] }[] = [];
    for (const batch of BATCHES) {
      const before = ((await db.query("SELECT coalesce(max(event_order),0)::text AS position FROM audit_events")).rows[0] as { position: string }).position;
      for (const e of batch.events) {
        await db.query(
          `INSERT INTO audit_events (id, event_type, decision, organization_id, actor_identity_id, credential_id, resource, occurred_at)
           VALUES ($1, $2, 'info', $3, $4, $5, $6::jsonb, $7)`,
          [e.id, e.type, e.organizationId, e.actor, e.credentialId, e.resource === null ? null : JSON.stringify(e.resource), e.occurredAt],
        );
      }
      const signals: Signal[] = [];
      const fakeConvex = (async (_url: unknown, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as {
          path: string;
          args: { kind: string; resourceId: string; data?: { lastEventId: string; occurredAt: unknown; domains: string[] } };
        };
        if (body.path === "mirror:upsert" && (body.args.kind === "changeSignal" || body.args.kind === "identitySignal")) {
          const d = body.args.data!;
          signals.push({
            kind: body.args.kind === "changeSignal" ? "change" : "identity",
            key: body.args.resourceId,
            lastEventId: d.lastEventId,
            occurredAt: new Date(d.occurredAt as string).toISOString(),
            domains: d.domains,
          });
        }
        return new Response(JSON.stringify({ status: "success" }), { status: 200 });
      }) as typeof fetch;
      const result = await syncNewMirrorEvents(ctx, config, { order: before }, fakeConvex);
      const after = ((await db.query("SELECT max(event_order)::text AS position FROM audit_events")).rows[0] as { position: string }).position;
      expect(result.cursor.order, `${batch.name}: one pass reads the whole batch`).toBe(after);
      out.push({ name: batch.name, events: batch.events, signals });
    }
    const text = `${JSON.stringify({ organizations: ORGS, batches: out }, null, 1)}\n`;
    if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") writeFileSync(OUT, text);
    let committed = "";
    try {
      committed = readFileSync(OUT, "utf8");
    } catch {
      // missing: reported below
    }
    expect(committed === text, "go/server/realtime/testdata/ts-vectors.json is stale: regenerate it (see the header of this file)").toBe(true);
  } finally {
    await ctx.close();
  }
}, 60_000);
