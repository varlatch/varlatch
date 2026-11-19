// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The fixture kit's hour clock (onHourClock), paritytest's HourClock in
 * TypeScript: a replay's hourly report counts stay in one hour
 * (security_control_counters.bucket_hour, from PGlite's clock), and its
 * times never fall before what was written before it.
 */
import { describe, expect, it } from "vitest";
import { HOUR_MARGIN_MS, hourClockOffset, onHourClock, onRecordedClock } from "./go-fixture-kit.js";
import { migratedTestDb } from "./helpers/pglite.js";

const HOUR_MS = 3_600_000;
const at = (iso: string) => Date.parse(iso);

describe("onHourClock", () => {
  it("runs on the real clock with at least the margin left, else from the start of the next hour", () => {
    expect(HOUR_MARGIN_MS).toBe(30 * 60_000);
    expect(hourClockOffset(at("2026-11-17T07:00:00.000Z"))).toBe(0);
    expect(hourClockOffset(at("2026-11-17T07:29:59.999Z"))).toBe(0);
    expect(hourClockOffset(at("2026-11-17T07:30:00.000Z"))).toBe(0);
    expect(hourClockOffset(at("2026-11-17T07:30:00.001Z"))).toBe(30 * 60_000 - 1);
    expect(hourClockOffset(at("2026-11-17T07:59:59.000Z"))).toBe(1_000);
    // A margin of an hour always moves the clock (the tests below).
    expect(hourClockOffset(at("2026-11-17T07:00:00.001Z"), HOUR_MS)).toBe(HOUR_MS - 1);
  });

  it("moved, reads the next hour from Date.now() and new Date(), and leaves the rest of Date alone", async () => {
    const RealDate = Date;
    const before = RealDate.now();
    const nextHour = before - (before % HOUR_MS) + HOUR_MS;
    await onHourClock(async () => {
      expect(Date).not.toBe(RealDate);
      const now = Date.now();
      expect(now).toBeGreaterThanOrEqual(nextHour);
      expect(now - nextHour).toBeLessThan(5_000);
      expect(Math.abs(new Date().getTime() - Date.now())).toBeLessThan(1_000);
      // Time passes.
      const t0 = Date.now();
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(Date.now() - t0).toBeGreaterThanOrEqual(15);
      // An explicit time, the statics and instanceof are as before.
      expect(new Date(0).toISOString()).toBe("1970-01-01T00:00:00.000Z");
      expect(new Date("2026-11-17T07:00:00Z").getTime()).toBe(RealDate.UTC(2026, 10, 17, 7));
      expect(Date.parse("2026-11-17T07:00:00Z")).toBe(RealDate.UTC(2026, 10, 17, 7));
      expect(new RealDate() instanceof Date).toBe(true);
      expect(new Date() instanceof RealDate).toBe(true);
      expect(typeof Date()).toBe("string");
    }, HOUR_MS);
    expect(Date).toBe(RealDate);
  });

  it("with the margin left, leaves Date as it is", async () => {
    const RealDate = Date;
    await onHourClock(async () => {
      // Real time decides which case this run is in; both are checked.
      if (hourClockOffset(RealDate.now()) === 0) expect(Date).toBe(RealDate);
    }, 1);
    expect(Date).toBe(RealDate);
  });

  it("is the clock PGlite reads, and never goes back before rows written first", async () => {
    const db = await migratedTestDb();
    try {
      await db.query("CREATE TABLE clock_rows (name text, created_at timestamptz)");
      await db.query("INSERT INTO clock_rows VALUES ('seed', clock_timestamp())");
      await onHourClock(async () => {
        const row = (await db.query("SELECT extract(epoch FROM date_trunc('hour', clock_timestamp(), 'UTC')) * 1000 AS hour")).rows[0] as { hour: string | number };
        // One reading of the clock: two could straddle a millisecond and give an
        // expected value that is not on the hour.
        const now = Date.now();
        expect(Number(row.hour)).toBe(now - (now % HOUR_MS));
        await db.query("INSERT INTO clock_rows VALUES ('replayed', clock_timestamp())");
      }, HOUR_MS);
      // A list ordered by time keeps what was written first first.
      const names = (await db.query("SELECT name FROM clock_rows ORDER BY created_at")).rows.map((r) => (r as { name: string }).name);
      expect(names).toEqual(["seed", "replayed"]);
    } finally {
      await db.close();
    }
  });

  it("inside the recording's clock, moves nothing: that clock already has the margin left", async () => {
    // A recording that ended with 20 minutes of its hour left: the
    // recording's clock starts at the next hour, as the hour clock would.
    const rows = { audit_events: [{ occurred_at: "2026-11-16T09:00:00.000Z" }, { occurred_at: "2026-11-16T09:40:00.000Z" }] };
    await onRecordedClock(rows, async () => {
      const recording = Date;
      expect(Date.now() - at("2026-11-16T10:00:00.000Z")).toBeLessThan(5_000);
      await onHourClock(async () => {
        expect(Date).toBe(recording);
        expect(new Date().getUTCHours()).toBe(10);
      });
    });
  });

  it("refuses a second replay while one runs", async () => {
    let release!: () => void;
    const first = onHourClock(() => new Promise<void>((resolve) => (release = resolve)), HOUR_MS);
    await expect(onHourClock(async () => undefined)).rejects.toThrow("already running on the hour clock");
    release();
    await first;
    // Once the first has settled, the next may run.
    await expect(onHourClock(async () => 1)).resolves.toBe(1);
  });

  it("puts the real Date back when the replay fails or replaces Date", async () => {
    const RealDate = Date;
    await expect(onHourClock(async () => {
      throw new Error("boom");
    }, HOUR_MS)).rejects.toThrow("boom");
    expect(Date).toBe(RealDate);
    await expect(onHourClock(async () => {
      globalThis.Date = class extends RealDate {} as DateConstructor;
    }, HOUR_MS)).rejects.toThrow("replaced Date");
    expect(Date).toBe(RealDate);
  });
});
