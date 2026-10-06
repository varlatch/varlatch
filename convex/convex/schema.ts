// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * Application Plane schema (ADR-0005): everything here is a non-authoritative
 * Mirror or product metadata. Corrupting these tables breaks the UI, never
 * authorization — varlatchd is the source of truth and republishes on sync.
 */
export default defineSchema({
  // One-way Mirrors of Secret Plane state, keyed by kind + Varlatch domain ID.
  mirrors: defineTable({
    kind: v.string(), // organization | project | environment | changeSignal | identitySignal (auditEvent: retired)
    resourceId: v.string(), // Varlatch domain ID (never a Convex ID)
    organizationId: v.union(v.string(), v.null()),
    data: v.any(),
    mirroredAt: v.number(), // when the payload last changed (an unchanged republish writes nothing)
  })
    .index("by_kind_org", ["kind", "organizationId", "resourceId"])
    .index("by_resource", ["resourceId"]),
});
