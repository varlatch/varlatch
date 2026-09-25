// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { VarlatchClient, VarlatchApiError } from "../src/index.js";

const maintenance = () =>
  new Response(
    JSON.stringify({ error: { code: "MAINTENANCE", message: "Installation maintenance; retry later", requestId: "req_test" } }),
    { status: 503, headers: { "Retry-After": "0", "content-type": "application/json" } },
  );

describe("maintenance retry", () => {
  it("retries 503 MAINTENANCE honoring Retry-After until the window ends", async () => {
    let calls = 0;
    const client = new VarlatchClient({
      server: "https://example.test",
      fetch: async () => (++calls < 3 ? maintenance() : new Response(JSON.stringify({ apiMajor: 1 }), { status: 200 })),
    });
    const meta = await client.meta();
    expect(calls).toBe(3);
    expect(meta).toMatchObject({ apiMajor: 1 });
  });

  it("surfaces MAINTENANCE once the retry budget is exhausted", async () => {
    let calls = 0;
    const client = new VarlatchClient({
      server: "https://example.test",
      maintenanceRetryMs: 30,
      fetch: async () => (calls++, maintenance()),
    });
    await expect(client.meta()).rejects.toMatchObject({ code: "MAINTENANCE", status: 503 });
    expect(calls).toBeGreaterThan(1);
  });

  it("does not retry non-maintenance 503s or maintenanceRetryMs: 0", async () => {
    let calls = 0;
    const plain503 = () => new Response(JSON.stringify({ error: { code: "INTERNAL", message: "boom", requestId: "req_x" } }), { status: 503 });
    const client = new VarlatchClient({ server: "https://example.test", fetch: async () => (calls++, plain503()) });
    await expect(client.meta()).rejects.toBeInstanceOf(VarlatchApiError);
    expect(calls).toBe(1);

    let calls2 = 0;
    const disabled = new VarlatchClient({ server: "https://example.test", maintenanceRetryMs: 0, fetch: async () => (calls2++, maintenance()) });
    await expect(disabled.meta()).rejects.toMatchObject({ code: "MAINTENANCE" });
    expect(calls2).toBe(1);
  });

  it("shares one budget across the calls of a client, and resets after a normal answer", async () => {
    const waits: number[] = [];
    let open = false;
    const client = new VarlatchClient({
      server: "https://example.test",
      maintenanceRetryMs: 60,
      onMaintenance: (w) => waits.push(w.remainingMs),
      fetch: async () => (open ? new Response(JSON.stringify({ apiMajor: 1 }), { status: 200 }) : maintenance()),
    });
    await expect(client.meta()).rejects.toMatchObject({ code: "MAINTENANCE" });
    const firstCallWaits = waits.length;
    expect(firstCallWaits).toBeGreaterThan(0);
    // The second call in the same window does not get a fresh budget.
    await expect(client.meta()).rejects.toMatchObject({ code: "MAINTENANCE" });
    expect(waits.length).toBe(firstCallWaits);
    // A normal answer ends the window; the next one starts a new budget.
    open = true;
    await expect(client.meta()).resolves.toMatchObject({ apiMajor: 1 });
    open = false;
    await expect(client.meta()).rejects.toMatchObject({ code: "MAINTENANCE" });
    expect(waits.length).toBeGreaterThan(firstCallWaits);
  });

  it("jitters Retry-After within ±20% and reports each wait", async () => {
    const waits: { retryInMs: number; remainingMs: number }[] = [];
    let calls = 0;
    const slow = () => new Response(JSON.stringify({ error: { code: "MAINTENANCE", message: "m", requestId: "r" } }),
      { status: 503, headers: { "Retry-After": "1" } });
    const client = new VarlatchClient({
      server: "https://example.test",
      maintenanceRetryMs: 10_000,
      onMaintenance: (w) => waits.push(w),
      fetch: async () => (++calls < 2 ? slow() : new Response(JSON.stringify({ apiMajor: 1 }), { status: 200 })),
    });
    await client.meta();
    expect(waits).toHaveLength(1);
    expect(waits[0]!.retryInMs).toBeGreaterThanOrEqual(800);
    expect(waits[0]!.retryInMs).toBeLessThanOrEqual(1200);
  });
});
