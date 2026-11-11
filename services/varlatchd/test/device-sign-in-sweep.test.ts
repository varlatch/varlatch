// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AppCtx } from "../src/domain/ctx.js";
import { requestDeviceSignIn } from "../src/domain/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { traceLog, traced } from "./helpers/trace.js";

/**
 * Device sign-in's housekeeping sweep (run with each new request), in the
 * lock order (ADR-0054 amendment E): one clock reading decides what lapsed,
 * the rows are locked in key order, and the writes change exactly the
 * locked rows, so none can cross a threshold between its lock and its
 * write. The lock-order check runs over every transaction here.
 */
describe("device sign-in sweep", () => {
  let db: Awaited<ReturnType<typeof migratedTestDb>>;
  let ctx: AppCtx;
  const log = traceLog();
  const request = (peer: string) => requestDeviceSignIn(ctx, { peer, userAgent: null, requestId: `req-${peer}` });

  beforeEach(async () => {
    db = await migratedTestDb();
    ctx = { db: traced(db, log), rootKek: Buffer.alloc(32, 7) };
  });
  afterEach(async () => {
    await db.close();
  });

  it("expires lapsed sign-ins, deletes day-old ones, keeps live ones, and writes only the rows it locked", async () => {
    const lapsed = await request("198.51.100.1");
    const old = await request("198.51.100.2");
    const live = await request("198.51.100.3");
    await db.query("UPDATE device_sign_ins SET expires_at = clock_timestamp() - interval '1 minute' WHERE id = $1", [lapsed.id]);
    await db.query("UPDATE device_sign_ins SET expires_at = clock_timestamp() - interval '2 days' WHERE id = $1", [old.id]);
    log.reset();
    await request("198.51.100.4");
    const status = async (id: string) => ((await db.query("SELECT status FROM device_sign_ins WHERE id = $1", [id])).rows[0] as { status: string } | undefined)?.status;
    expect(await status(lapsed.id)).toBe("expired");
    expect(await status(old.id)).toBeUndefined();
    expect(await status(live.id)).toBe("pending");
    // The writes name the locked rows; none reads the clock again.
    const writes = log.entries.flatMap((e) => (e.kind === "sql" && /^\s*(UPDATE|DELETE FROM) device_(sign_ins|sign_in_challenges|code_attempt_windows)\b/.test(e.text) ? [e.text] : []));
    expect(writes.length).toBeGreaterThan(0);
    for (const w of writes.filter((t) => !/^\s*UPDATE device_sign_ins SET (last_polled_at|poll_interval)/.test(t))) {
      expect(w, w).not.toMatch(/clock_timestamp|now\(\)/);
    }
  });
});
