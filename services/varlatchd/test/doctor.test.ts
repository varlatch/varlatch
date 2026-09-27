// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Maintenance } from "@varlatch/backup";
import { generateKey } from "../src/crypto/aead.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { checkFunctions, checkPublicUrl, serverDoctor } from "../src/doctor.js";
import { recordAuditEvent } from "../src/audit/events.js";
import { evaluateMirror, MirrorStatusReporter, readMirrorStatus, type MirrorStatus } from "../src/mirror/status.js";
import { migratedTestDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };
let stateDir: string;
beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  stateDir = mkdtempSync(join(tmpdir(), "doctor-state-"));
});
afterEach(async () => {
  await ctx.close();
});

const status = (over: Partial<MirrorStatus> = {}): MirrorStatus => ({
  cursorOrder: "0", lastIncrementalAt: null, lastFullSyncAt: null, lastError: null, updatedAt: new Date().toISOString(), ...over,
});
const byId = (checks: { id: string }[], id: string) => checks.find((c) => c.id === id);

describe("checkPublicUrl", () => {
  it("accepts HTTPS origins and loopback HTTP", () => {
    expect(checkPublicUrl("https://vault.example.com")).toMatchObject({ status: "pass" });
    expect(checkPublicUrl("http://localhost:8787")).toMatchObject({ status: "pass" });
  });
  it("rejects unset, non-HTTPS public, and path-carrying URLs", () => {
    expect(checkPublicUrl(undefined)).toMatchObject({ status: "fail", class: "mandatory" });
    expect(checkPublicUrl("http://vault.example.com").detail).toContain("not HTTPS");
    expect(checkPublicUrl("https://example.com/varlatch").detail).toContain("without path");
    expect(checkPublicUrl("vault")).toMatchObject({ status: "fail" });
  });
});

describe("evaluateMirror", () => {
  it("compares the published cursor against the watermark numerically", () => {
    expect(evaluateMirror(status({ cursorOrder: "10" }), "9")).toEqual({ state: "caught-up" });
    expect(evaluateMirror(status({ cursorOrder: "9" }), "10")).toMatchObject({ state: "behind" });
    expect(evaluateMirror(null, "1")).toMatchObject({ state: "unknown" });
  });
  it("classifies Convex auth rejections as a trust problem", () => {
    const at = new Date().toISOString();
    expect(evaluateMirror(status({ lastError: { at, message: "Convex mutation mirror:upsert failed: HTTP 401" } }), "0"))
      .toMatchObject({ state: "rejected" });
    expect(evaluateMirror(status({ lastError: { at, message: "fetch failed" } }), "0")).toMatchObject({ state: "failing" });
  });
});

describe("MirrorStatusReporter", () => {
  it("persists on change only and clears errors on success", () => {
    const writes: MirrorStatus[] = [];
    const reporter = new MirrorStatusReporter(stateDir, (_path, value) => writes.push(structuredClone(value as MirrorStatus)));
    reporter.incremental("5");
    reporter.incremental("5");
    reporter.failure(new Error("HTTP 401"));
    reporter.failure(new Error("HTTP 401"));
    reporter.incremental("5");
    reporter.fullSync();
    expect(writes.map((w) => [w.cursorOrder, w.lastError?.message ?? null])).toEqual([
      ["5", null], ["5", "HTTP 401"], ["5", null], ["5", null],
    ]);
  });
  it("writes a file the doctor can read", () => {
    new MirrorStatusReporter(stateDir).incremental("7");
    expect(readMirrorStatus(stateDir)?.cursorOrder).toBe("7");
  });
});

describe("serverDoctor", () => {
  const input = () => ({
    ctx, db: ctx.db, stateDir, publicUrl: "https://vault.example.com", convexUrl: "http://convex-backend:3210", waitMs: 0,
    sleep: async () => {},
  });

  it("reports a healthy installation without writing anything", async () => {
    await ensureInstallation(ctx);
    const before = await ctx.db.query("SELECT count(*)::int AS n FROM audit_events");
    const report = await serverDoctor({ ...input(), readStatus: () => status({ cursorOrder: "999" }) });
    expect(byId(report.checks, "secret-plane.ready")).toMatchObject({ status: "pass" });
    expect(byId(report.checks, "config.public-url")).toMatchObject({ status: "pass" });
    expect(byId(report.checks, "mirror.catch-up")).toMatchObject({ status: "pass" });
    expect(byId(report.checks, "custody.attestations")).toMatchObject({ status: "fail", class: "advisory" });
    expect(report.facts).toMatchObject({ publicUrl: "https://vault.example.com", convexConfigured: true });
    const after = await ctx.db.query("SELECT count(*)::int AS n FROM audit_events");
    expect(after.rows).toEqual(before.rows);
  });

  it("fails readiness on a wrong or missing Root KEK and on a missing installation", async () => {
    await ensureInstallation(ctx);
    const wrong = await serverDoctor({ ...input(), ctx: { db: ctx.db, rootKek: generateKey() } });
    expect(byId(wrong.checks, "secret-plane.ready")!).toMatchObject({ status: "fail" });
    expect((byId(wrong.checks, "secret-plane.ready") as { detail: string }).detail).toContain("canary");
    const missing = await serverDoctor({ ...input(), ctx: null });
    expect((byId(missing.checks, "secret-plane.ready") as { detail: string }).detail).toContain("could not be loaded");
  });

  it("waits for Mirrors to reach the watermark, then fails if they do not", async () => {
    await ensureInstallation(ctx);
    await recordAuditEvent(ctx.db, { eventType: "test.event", decision: "info" });
    let reads = 0;
    const caughtUp = await serverDoctor({
      ...input(), waitMs: 60_000,
      readStatus: () => status({ cursorOrder: ++reads > 2 ? "999" : "0" }),
    });
    expect(byId(caughtUp.checks, "mirror.catch-up")).toMatchObject({ status: "pass" });
    const stuck = await serverDoctor({ ...input(), readStatus: () => status({ cursorOrder: "0" }) });
    expect(byId(stuck.checks, "mirror.catch-up")).toMatchObject({ status: "fail" });
  });

  it("reports maintenance instead of failing Mirrors during a backup", async () => {
    await ensureInstallation(ctx);
    new Maintenance(stateDir).beginCapture(60_000);
    const report = await serverDoctor({ ...input(), readStatus: () => null });
    expect((byId(report.checks, "secret-plane.ready") as { detail: string }).detail).toContain("capture in progress");
    expect(byId(report.checks, "mirror.catch-up")).toMatchObject({ status: "unknown" });
  });

  it("flags an unconfigured Application Plane and missing backups", async () => {
    await ensureInstallation(ctx);
    const report = await serverDoctor({ ...input(), convexUrl: undefined });
    expect(byId(report.checks, "mirror.catch-up")).toMatchObject({ status: "fail", class: "mandatory" });
    expect(byId(report.checks, "backups.status")).toMatchObject({ status: "fail", class: "advisory" });
  });
});

describe("checkFunctions (ADR-0035 D4)", () => {
  const base = { ctx: null, db: null as never, stateDir: "/nonexistent", publicUrl: undefined, convexUrl: "http://convex-backend:3210" };
  const fp = "c".repeat(64);
  it("passes only when Convex serves this release's fingerprint", async () => {
    expect(await checkFunctions({ ...base, expectedFunctions: () => fp, observeFunctions: async () => fp }, false)).toMatchObject({ status: "pass", class: "mandatory" });
    const stale = await checkFunctions({ ...base, expectedFunctions: () => fp, observeFunctions: async () => "d".repeat(64) }, false);
    expect(stale).toMatchObject({ status: "fail", remedy: expect.stringContaining("convex-deploy") });
    expect((await checkFunctions({ ...base, expectedFunctions: () => fp, observeFunctions: async () => null }, false)).detail).toContain("does not report");
  });
  it("is unknown without an expected value, a Convex URL, or during maintenance", async () => {
    expect(await checkFunctions({ ...base, expectedFunctions: () => null }, false)).toMatchObject({ status: "unknown" });
    expect(await checkFunctions({ ...base, convexUrl: undefined }, false)).toMatchObject({ status: "unknown" });
    expect(await checkFunctions({ ...base, expectedFunctions: () => fp, observeFunctions: async () => fp }, true)).toMatchObject({ status: "unknown" });
  });
});
