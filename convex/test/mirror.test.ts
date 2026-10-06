// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
vi.mock("../convex/_generated/server", () => ({ query: (x: unknown) => x, mutation: (x: unknown) => x }));
import { list, listMine, purgeRetired, sameValue, upsert } from "../convex/mirror";
// Exercise the registered handlers with verified claims; denial must never
// touch the database, even for administrators or org-associated machines.
const run = (fn: unknown, identity: unknown, args: unknown) => (fn as { handler: Function }).handler({
  auth: { getUserIdentity: async () => identity },
  db: { query: () => { throw new Error("unexpected database read"); } },
}, args);
describe("mirror read authority", () => {
  it("does not disclose audit, project, or environment records using org claims", async () => {
    for (const kind of ["auditEvent", "project", "environment"]) {
      expect(await run(list, { subject: "machine", orgIds: ["acme"], installationAdmin: true }, { kind, organizationId: "acme" })).toEqual([]);
    }
  });
  it("rejects foreign organization signals and non-signal self queries", async () => {
    expect(await run(list, { subject: "machine", orgIds: ["acme"] }, { kind: "changeSignal", organizationId: "other" })).toEqual([]);
    expect(await run(listMine, { subject: "machine" }, { kind: "auditEvent" })).toEqual([]);
  });
});

describe("retired Mirror purge (ADR-0036)", () => {
  it("is for varlatchd's mirror identity and retired kinds only, and touches nothing otherwise", async () => {
    await expect(run(purgeRetired, { subject: "machine", orgIds: ["acme"], installationAdmin: true }, { kind: "auditEvent" })).rejects.toThrow(/mirror identity/);
    await expect(run(purgeRetired, { subject: "varlatchd-mirror", role: "mirror" }, { kind: "changeSignal" })).rejects.toThrow(/retired/);
  });
  it("deletes one bounded batch and says whether more remain", async () => {
    const deleted: string[] = [];
    const docs = (n: number) => Array.from({ length: n }, (_, i) => ({ _id: `m${i}` }));
    const purge = (available: number) => (purgeRetired as unknown as { handler: Function }).handler({
      auth: { getUserIdentity: async () => ({ subject: "varlatchd-mirror", role: "mirror" }) },
      db: {
        query: () => ({ withIndex: () => ({ take: async (n: number) => docs(Math.min(n, available)) }) }),
        delete: async (id: string) => { deleted.push(id); },
      },
    }, { kind: "auditEvent" });
    expect(await purge(300)).toEqual({ deleted: 256, done: false });
    expect(await purge(10)).toEqual({ deleted: 10, done: true });
    expect(deleted).toHaveLength(266);
  });
});

describe("Mirror upsert", () => {
  const mirror = { subject: "varlatchd-mirror", role: "mirror" };
  const args = { kind: "project", resourceId: "prj_1", organizationId: "org_1", data: { slug: "api", name: "API", activeContractRevisionId: null } };
  const upsertWith = async (existing: unknown, input: unknown = args) => {
    const writes: string[] = [];
    await (upsert as unknown as { handler: Function }).handler({
      auth: { getUserIdentity: async () => mirror },
      db: {
        query: () => ({ withIndex: () => ({ filter: () => ({ unique: async () => existing }) }) }),
        insert: async () => { writes.push("insert"); },
        replace: async () => { writes.push("replace"); },
      },
    }, input);
    return writes;
  };
  const stored = (over: Record<string, unknown> = {}) => ({ _id: "m1", ...args, mirroredAt: 1, ...over });

  it("writes nothing when a republished Mirror has not changed, whatever its key order", async () => {
    expect(await upsertWith(stored())).toEqual([]);
    expect(await upsertWith(stored({ data: { activeContractRevisionId: null, name: "API", slug: "api" } }))).toEqual([]);
  });

  it("replaces a Mirror whose payload or organization changed, and inserts a new one", async () => {
    expect(await upsertWith(stored({ data: { ...args.data, name: "Old name" } }))).toEqual(["replace"]);
    expect(await upsertWith(stored({ data: { ...args.data, activeContractRevisionId: "rev_2" } }))).toEqual(["replace"]);
    expect(await upsertWith(stored({ organizationId: "org_2" }))).toEqual(["replace"]);
    expect(await upsertWith(stored({ data: { slug: "api", name: "API" } }))).toEqual(["replace"]);
    expect(await upsertWith(null)).toEqual(["insert"]);
  });

  it("is for varlatchd's mirror identity only", async () => {
    await expect((upsert as unknown as { handler: Function }).handler({
      auth: { getUserIdentity: async () => ({ subject: "machine", orgIds: ["org_1"], installationAdmin: true }) },
      db: { query: () => { throw new Error("unexpected database read"); } },
    }, args)).rejects.toThrow(/mirror identity/);
  });
});

describe("sameValue", () => {
  it("compares JSON values by content", () => {
    expect(sameValue({ a: [1, { b: null }], c: "x" }, { c: "x", a: [1, { b: null }] })).toBe(true);
    expect(sameValue({ a: [1, 2] }, { a: [2, 1] })).toBe(false);
    expect(sameValue({ a: 1 }, { a: 1, b: undefined })).toBe(false);
    expect(sameValue({ a: null }, { a: 0 })).toBe(false);
    expect(sameValue([], {})).toBe(false);
    expect(sameValue("1", 1)).toBe(false);
  });
});
