// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { backendOf, chooseBackend } from "../src/lib/backend";
import {
  EVENTS_URL,
  reconnectDelay,
  REPLACED_WAIT_MS,
  SignalStream,
  type EventSourceLike,
  type SignalStreamDeps,
} from "../src/lib/sse";

vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});

/** An EventSource the test drives. */
class FakeSource implements EventSourceLike {
  onerror: ((event: Event) => void) | null = null;
  closed = false;
  private listeners = new Map<string, ((e: MessageEvent) => void)[]>();
  constructor(readonly url: string) {}
  addEventListener(type: string, listener: (e: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data: unknown) {
    for (const l of this.listeners.get(type) ?? []) l({ data: typeof data === "string" ? data : JSON.stringify(data) } as MessageEvent);
  }
  fail() {
    this.onerror?.(new Event("error"));
  }
}

function harness() {
  const sources: FakeSource[] = [];
  const timers: { fn: () => void; ms: number; cleared: boolean }[] = [];
  const deps: SignalStreamDeps = {
    open: (url) => {
      const s = new FakeSource(url);
      sources.push(s);
      return s;
    },
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => void ((t as { cleared: boolean }).cleared = true),
    random: () => 0.5,
  };
  const fire = () => {
    const t = timers.find((x) => !x.cleared);
    if (!t) throw new Error("no timer");
    t.cleared = true;
    t.fn();
    return t.ms;
  };
  return { deps, sources, timers, fire, last: () => sources[sources.length - 1]! };
}

describe("choosing the transport", () => {
  it("takes server-sent events when the Go server lists realtime.sse", () => {
    expect(backendOf(["auth.session", "realtime.sse"])).toEqual({ session: "varlatchd", realtime: "sse" });
    expect(backendOf(["auth.session"])).toEqual({ session: "varlatchd", realtime: "none" });
    // The TypeScript server never lists it; were it to, Convex stays.
    expect(backendOf(["realtime.sse"])).toEqual({ session: "better-auth", realtime: "convex" });
  });
});

describe("the signal stream", () => {
  it("is not loaded until the stream opens, then keeps each Organization's latest signal and the person's", () => {
    const h = harness();
    const stream = new SignalStream(h.deps);
    stream.start();
    expect(h.last().url).toBe(EVENTS_URL);
    expect(stream.orgDocs("org_a")).toBeUndefined();
    expect(stream.meDocs()).toBeUndefined();
    expect(stream.isConnected()).toBe(false);
    const changes: boolean[] = [];
    stream.onConnection((c) => changes.push(c));
    h.last().emit("ready", { identityId: "idn_1" });
    expect(stream.isConnected()).toBe(true);
    expect(changes).toEqual([true]);
    const empty = stream.orgDocs("org_a");
    expect(empty).toEqual([]);
    // Stable snapshots: the same object until the signal changes.
    expect(stream.orgDocs("org_a")).toBe(empty);
    h.last().emit("change", { organizationId: "org_a", lastEventId: "evt_1", occurredAt: "2026-11-14T10:00:00.000Z", domains: ["project"] });
    const a = stream.orgDocs("org_a");
    expect(a).toEqual([{ data: { lastEventId: "evt_1", occurredAt: "2026-11-14T10:00:00.000Z", domains: ["project"] } }]);
    expect(stream.orgDocs("org_a")).toBe(a);
    expect(stream.orgDocs("org_b")).toEqual([]);
    h.last().emit("identity", { lastEventId: "evt_2", occurredAt: "2026-11-14T10:00:01.000Z", domains: ["credential"] });
    expect(stream.meDocs()).toEqual([{ data: { lastEventId: "evt_2", occurredAt: "2026-11-14T10:00:01.000Z", domains: ["credential"] } }]);
    // Malformed events change nothing.
    h.last().emit("change", "not json");
    h.last().emit("change", { lastEventId: "evt_3" });
    h.last().emit("identity", { domains: ["x"] });
    expect(stream.orgDocs("org_a")).toBe(a);
  });

  it("reconnects by itself with backoff, keeps what it had, and stops for good when stopped", () => {
    const h = harness();
    const stream = new SignalStream(h.deps);
    stream.start();
    h.last().emit("ready", {});
    h.last().emit("change", { organizationId: "org_a", lastEventId: "evt_1", domains: [] });
    const first = h.last();
    first.fail();
    expect(first.closed).toBe(true);
    expect(stream.isConnected()).toBe(false);
    expect(stream.orgDocs("org_a")).toEqual([{ data: { lastEventId: "evt_1", domains: [] } }]);
    expect(h.fire()).toBe(reconnectDelay(0, () => 0.5));
    h.last().fail();
    expect(h.fire()).toBe(reconnectDelay(1, () => 0.5));
    // Events from a closed source are ignored.
    first.emit("change", { organizationId: "org_a", lastEventId: "evt_old", domains: [] });
    expect(stream.orgDocs("org_a")?.[0]?.data?.lastEventId).toBe("evt_1");
    h.last().emit("ready", {});
    expect(stream.isConnected()).toBe(true);
    h.last().fail();
    // The backoff starts again after a successful open.
    expect(h.timers.filter((t) => !t.cleared)[0]!.ms).toBe(reconnectDelay(0, () => 0.5));
    stream.stop();
    expect(h.timers.every((t) => t.cleared)).toBe(true);
    const opened = h.sources.length;
    stream.start();
    expect(h.sources.length).toBe(opened + 1);
    stream.stop();
    expect(h.last().closed).toBe(true);
  });

  it("goes on through a maintenance, however many answers it lasts, and opens again after it", () => {
    const h = harness();
    const stream = new SignalStream(h.deps);
    const connected: boolean[] = [];
    stream.onConnection((c) => connected.push(c));
    stream.start();
    h.last().emit("ready", {});
    h.last().emit("change", { organizationId: "org_a", lastEventId: "evt_1", domains: [] });
    // The server ends the stream as a barrier begins; behind it every attempt is 503, an error to the browser.
    h.last().emit("close", { reason: "shutdown" });
    h.last().fail();
    for (let attempt = 0; attempt < 40; attempt++) {
      expect(h.fire()).toBe(reconnectDelay(attempt, () => 0.5));
      expect(stream.isConnected()).toBe(false);
      h.last().fail();
    }
    expect(stream.orgDocs("org_a")).toEqual([{ data: { lastEventId: "evt_1", domains: [] } }]);
    h.fire();
    h.last().emit("ready", {});
    expect(stream.isConnected()).toBe(true);
    expect(connected).toEqual([true, false, true]);
    stream.stop();
  });

  it("waits longer after the server replaced the stream with another tab's", () => {
    const h = harness();
    const stream = new SignalStream(h.deps);
    stream.start();
    h.last().emit("ready", {});
    h.last().emit("close", { reason: "replaced" });
    h.last().fail();
    expect(h.fire()).toBe(REPLACED_WAIT_MS);
    h.last().emit("close", { reason: "membership-removed" });
    h.last().fail();
    expect(h.fire()).toBeLessThanOrEqual(reconnectDelay(1, () => 1));
  });

  it("reconnects once after a change of its scope, without a loop", () => {
    const h = harness();
    const stream = new SignalStream(h.deps);
    stream.start();
    h.last().emit("ready", {});
    h.last().emit("close", { reason: "scope-changed" });
    h.last().fail();
    h.last().fail();
    expect(h.timers.filter((t) => !t.cleared)).toHaveLength(1);
    expect(h.fire()).toBe(reconnectDelay(0, () => 0.5));
    expect(h.sources).toHaveLength(2);
    h.last().emit("ready", {});
    expect(stream.isConnected()).toBe(true);
    expect(h.timers.every((t) => t.cleared)).toBe(true);
    stream.stop();
  });

  it("bounds the backoff", () => {
    for (let i = 0; i < 20; i++) {
      expect(reconnectDelay(i, () => 1)).toBeLessThanOrEqual(36_000);
      expect(reconnectDelay(i, () => 0)).toBeGreaterThanOrEqual(800);
    }
  });
});

describe("realtime.ts's hooks over server-sent events", () => {
  let root: ReactTestRenderer | null = null;
  beforeEach(() => {
    vi.resetModules();
  });
  afterEach(async () => {
    if (root) await act(async () => root!.unmount());
    root = null;
    chooseBackend({ session: "better-auth", realtime: "convex" });
  });

  it("invalidate on their domains' signals, after the first snapshot, and only for their Organization", async () => {
    // realtime.ts and sseProvider.tsx read the choice when they load.
    const backendModule = await import("../src/lib/backend");
    backendModule.chooseBackend({ session: "varlatchd", realtime: "sse" });
    vi.doMock("../src/lib/session", () => ({ useSession: () => ({ api: {} }) }));
    const { useLiveUpdatesBack, useMirrorInvalidation, useMeSignal, useRealtimeConnected } = await import("../src/lib/realtime");
    const { SseProvider } = await import("../src/lib/sseProvider");
    const h = harness();
    const qc = new QueryClient();
    const invalidated: unknown[] = [];
    qc.invalidateQueries = (async (filters?: { queryKey?: unknown }) => void invalidated.push(filters?.queryKey)) as typeof qc.invalidateQueries;
    const membership: number[] = [];
    let back = 0;
    let connected = false;
    function Page() {
      useMirrorInvalidation("org_a", ["project"], [["projects", "org_a"]]);
      useMeSignal(["membership"], () => membership.push(1));
      useLiveUpdatesBack(() => back++);
      connected = useRealtimeConnected();
      return null;
    }
    await act(async () => {
      root = create(
        <QueryClientProvider client={qc}>
          <SseProvider deps={h.deps}>
            <Page />
          </SseProvider>
        </QueryClientProvider>,
      );
    });
    expect(h.sources).toHaveLength(1);
    const send = async (type: string, data: unknown) => act(async () => h.last().emit(type, data));
    await send("ready", { identityId: "idn_1" });
    expect(connected).toBe(true);
    // The first signal after the baseline invalidates.
    await send("change", { organizationId: "org_a", lastEventId: "evt_1", domains: ["project"] });
    expect(invalidated).toEqual([["projects", "org_a"]]);
    // Another Organization, another domain, the same event again: nothing.
    await send("change", { organizationId: "org_b", lastEventId: "evt_2", domains: ["project"] });
    await send("change", { organizationId: "org_a", lastEventId: "evt_3", domains: ["grant"] });
    await send("change", { organizationId: "org_a", lastEventId: "evt_3", domains: ["project"] });
    expect(invalidated).toHaveLength(1);
    await send("identity", { lastEventId: "evt_4", domains: ["credential"] });
    expect(membership).toEqual([]);
    await send("identity", { lastEventId: "evt_5", domains: ["membership"] });
    expect(membership).toEqual([1]);
    // A gap: nothing on the drop itself or on a failed attempt, once when it is over.
    await act(async () => h.last().fail());
    expect(connected).toBe(false);
    await act(async () => void h.fire());
    await act(async () => h.last().fail());
    expect(back).toBe(0);
    await act(async () => void h.fire());
    await send("ready", { identityId: "idn_1" });
    expect(connected).toBe(true);
    expect(back).toBe(1);
    await send("identity", { lastEventId: "evt_6", domains: ["credential"] });
    expect(back).toBe(1);
    await act(async () => root!.unmount());
    root = null;
    expect(h.sources.every((s) => s.closed)).toBe(true);
  });

  it("opens no stream without a session", async () => {
    const backendModule = await import("../src/lib/backend");
    backendModule.chooseBackend({ session: "varlatchd", realtime: "sse" });
    const { SseProvider } = await import("../src/lib/sseProvider");
    const h = harness();
    await act(async () => {
      root = create(
        <SseProvider deps={h.deps} enabled={false}>
          <span />
        </SseProvider>,
      );
    });
    expect(h.sources).toHaveLength(0);
  });
});
