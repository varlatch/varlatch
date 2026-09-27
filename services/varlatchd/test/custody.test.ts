// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKey } from "../src/crypto/aead.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { attestCustody, custodyStatus } from "../src/domain/custody.js";
import { checkCustody, CUSTODY_MAX_AGE_DAYS } from "../src/doctor.js";
import { migratedTestDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };
beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
});
afterEach(async () => { await ctx.close(); });

describe("custody attestations (ADR-0035 D9)", () => {
  it("records a dated claim per key, the Root KEK one bound to its key version", async () => {
    expect((await custodyStatus(ctx.db)).attestations).toEqual({ "root-kek": null, "backup-key": null });
    await attestCustody(ctx.db, { key: "root-kek", method: "passphrase-escrow" });
    await attestCustody(ctx.db, { key: "backup-key", method: "copy" });
    const status = await custodyStatus(ctx.db);
    expect(status.rootKekVersion).toBe(1);
    expect(status.attestations["root-kek"]).toMatchObject({ method: "passphrase-escrow", keyVersion: 1 });
    expect(status.attestations["backup-key"]).toMatchObject({ method: "copy", keyVersion: null });
  });
  it("uses the latest attestation per key", async () => {
    await attestCustody(ctx.db, { key: "backup-key", method: "copy" });
    await attestCustody(ctx.db, { key: "backup-key", method: "passphrase-escrow" });
    expect((await custodyStatus(ctx.db)).attestations["backup-key"]?.method).toBe("passphrase-escrow");
  });
  it("a replaced Root KEK voids the earlier attestation", async () => {
    await attestCustody(ctx.db, { key: "root-kek", method: "copy" });
    await ctx.db.query("UPDATE installation SET root_kek_version = 2");
    expect((await custodyStatus(ctx.db)).attestations["root-kek"]).toBeNull();
  });
  it("validates key and method and records no key material", async () => {
    await expect(attestCustody(ctx.db, { key: "kek", method: "copy" })).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    await expect(attestCustody(ctx.db, { key: "root-kek", method: "trust-me" })).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    await attestCustody(ctx.db, { key: "root-kek", method: "copy" });
    const rows = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'installation.custody_attested'");
    const meta = rows.rows[0] as { metadata: unknown };
    const parsed = typeof meta.metadata === "string" ? JSON.parse(meta.metadata) : meta.metadata;
    expect(Object.keys(parsed as object).sort()).toEqual(["key", "keyVersion", "method"]);
  });
});

describe("doctor custody check", () => {
  it("is an advisory finding without attestations, and never a verified pass", async () => {
    expect(await checkCustody(ctx.db)).toMatchObject({ status: "fail", class: "advisory" });
    await attestCustody(ctx.db, { key: "root-kek", method: "passphrase-escrow" });
    await attestCustody(ctx.db, { key: "backup-key", method: "copy" });
    const fresh = await checkCustody(ctx.db);
    expect(fresh).toMatchObject({ status: "pass", class: "advisory" });
    expect(fresh.title).toContain("attestation");
    expect(fresh.detail).toContain("cannot verify");
  });
  it(`ages into an advisory finding after ${CUSTODY_MAX_AGE_DAYS} days`, async () => {
    await attestCustody(ctx.db, { key: "root-kek", method: "copy" });
    await attestCustody(ctx.db, { key: "backup-key", method: "copy" });
    const later = Date.now() + (CUSTODY_MAX_AGE_DAYS + 1) * 86_400_000;
    const aged = await checkCustody(ctx.db, later);
    expect(aged).toMatchObject({ status: "fail" });
    expect(aged.detail).toContain("re-confirm");
  });
});
