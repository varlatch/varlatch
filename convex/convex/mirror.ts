// SPDX-License-Identifier: AGPL-3.0-or-later
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Mirror sync surface. Writes are restricted to varlatchd's dedicated mirror
 * identity (a claim in the varlatchd-signed JWT — Convex cannot mint these).
 * Reads are scoped by the caller's orgIds claim. None of this grants any
 * Secret Plane authority; a stale or corrupted mirror is a UI problem only.
 */

interface VarlatchIdentity {
  subject: string;
  role?: string;
  orgIds?: string[];
  installationAdmin?: boolean;
}

async function identityOf(ctx: {
  auth: { getUserIdentity: () => Promise<Record<string, unknown> | null> };
}): Promise<VarlatchIdentity | null> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) return null;
  return identity as unknown as VarlatchIdentity;
}

export const upsert = mutation({
  args: {
    kind: v.string(),
    resourceId: v.string(),
    organizationId: v.union(v.string(), v.null()),
    data: v.any(),
  },
  handler: async (ctx, args) => {
    const identity = await identityOf(ctx);
    if (!identity || identity.role !== "mirror") {
      throw new Error("Mirror writes require varlatchd's mirror identity");
    }
    const existing = await ctx.db
      .query("mirrors")
      .withIndex("by_resource", (q) => q.eq("resourceId", args.resourceId))
      .filter((q) => q.eq(q.field("kind"), args.kind))
      .unique();
    const doc = { ...args, mirroredAt: Date.now() };
    if (existing) await ctx.db.replace(existing._id, doc);
    else await ctx.db.insert("mirrors", doc);
  },
});

export const remove = mutation({
  args: {
    kind: v.string(),
    resourceId: v.string(),
  },
  handler: async (ctx, args) => {
    const identity = await identityOf(ctx);
    if (!identity || identity.role !== "mirror") {
      throw new Error("Mirror writes require varlatchd's mirror identity");
    }
    const existing = await ctx.db
      .query("mirrors")
      .withIndex("by_resource", (q) => q.eq("resourceId", args.resourceId))
      .filter((q) => q.eq(q.field("kind"), args.kind))
      .unique();
    if (existing) await ctx.db.delete(existing._id);
  },
});

/**
 * Mirror kinds nothing reads any more. Per-event `auditEvent` Mirrors
 * (ADR-0036): the dashboard reads audit history from /v1, and they grew
 * with every audit event. Purged in bounded batches by varlatchd.
 */
const RETIRED_KINDS = ["auditEvent"];
const PURGE_BATCH = 256;

export const purgeRetired = mutation({
  args: { kind: v.string() },
  handler: async (ctx, args) => {
    const identity = await identityOf(ctx);
    if (!identity || identity.role !== "mirror") {
      throw new Error("Mirror writes require varlatchd's mirror identity");
    }
    if (!RETIRED_KINDS.includes(args.kind)) throw new Error("Only retired Mirror kinds can be purged");
    const batch = await ctx.db
      .query("mirrors")
      .withIndex("by_kind_org", (q) => q.eq("kind", args.kind))
      .take(PURGE_BATCH);
    for (const doc of batch) await ctx.db.delete(doc._id);
    return { deleted: batch.length, done: batch.length < PURGE_BATCH };
  },
});

export const listMine = query({
  args: { kind: v.string() },
  handler: async (ctx, args) => {
    const identity = await identityOf(ctx);
    // Self-only: the resource key is the verified token's subject, never a
    // request argument — one identity can never observe another's signal.
    if (args.kind !== "identitySignal" || !identity?.subject) return [];
    return await ctx.db
      .query("mirrors")
      .withIndex("by_resource", (q) => q.eq("resourceId", identity.subject))
      .filter((q) => q.eq(q.field("kind"), args.kind))
      .collect();
  },
});

export const list = query({
  args: { kind: v.string(), organizationId: v.string() },
  handler: async (ctx, args) => {
    const identity = await identityOf(ctx);
    // Org scope derives from the verified token's memberships, never from
    // the request alone (ADR-0005 §3).
    // Only invalidation signals are public. Legacy project/environment/audit
    // mirrors must never bypass the Secret Plane's per-resource permissions.
    if (args.kind !== "changeSignal" || !identity?.orgIds?.includes(args.organizationId)) return [];
    return await ctx.db
      .query("mirrors")
      .withIndex("by_kind_org", (q) =>
        q.eq("kind", args.kind).eq("organizationId", args.organizationId),
      )
      .collect();
  },
});
