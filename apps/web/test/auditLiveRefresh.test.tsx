// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The Audit page's live updates must not feed on its own failures: a refused
 * read is an audit event, which moves the org's change signal. After any
 * failed read, every automatic trigger (signals, the reconnect catch-up,
 * polling, focus) waits out one backoff and collapses into one read. Try
 * again and a membership change skip the wait; an owner's live updates are
 * immediate.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  signal: undefined as (() => void) | undefined,
  membership: undefined as (() => void) | undefined,
}));
vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
vi.hoisted(() => {
  vi.stubGlobal("matchMedia", () => ({ matches: true, addEventListener: () => {}, removeEventListener: () => {} }));
  vi.stubGlobal("window", { addEventListener: () => {}, removeEventListener: () => {} });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/lib/realtime", () => ({
  useRealtimeConnected: () => true,
  useMirrorSignal: (orgId: string | undefined, _domains: unknown, onChange: () => void) => {
    fake.signal = orgId ? onChange : undefined;
  },
  useMeSignal: (_domains: unknown, onChange: () => void) => {
    fake.membership = onChange;
  },
}));
vi.mock("react-router-dom", () => ({
  useParams: () => ({ org: "acme" }),
  useSearchParams: () => [new URLSearchParams()],
}));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ error: () => {}, success: () => {} }) }));
vi.mock("../src/components/PageHeader", () => ({
  PageHeader: ({ actions }: { actions?: React.ReactNode }) => <div>{actions}</div>,
}));
vi.mock("../src/features/audit/WebhooksSection", () => ({ WebhooksSection: () => null }));
vi.mock("../src/features/projects/hooks", () => ({
  useOrgName: (org: string) => org,
  useCapability: () => false,
  useProjects: () => ({ data: { items: [] } }),
}));
vi.mock("../src/features/audit/useAuditNames", () => ({
  useAuditNames: () => ({ names: {}, identities: [], identityById: new Map() }),
}));

import { VarlatchApiError } from "@varlatch/sdk";
import { focusManager } from "@tanstack/react-query";
import { AuditPage } from "../src/features/audit/AuditPage";
import { AUDIT_BACKOFF_MS } from "../src/features/audit/liveRefresh";

const apiError = (status: number, code: string) =>
  new VarlatchApiError(status, { code, message: `${code} (${status})`, requestId: "req_1" } as never);
const denied = () => apiError(403, "PERMISSION_DENIED");
const PAGE = { items: [], nextCursor: null };

let root: ReactTestRenderer;
let client: QueryClient;
async function flush() {
  // 1 ms, not 0: a zero-delay timer created while the fake clock ticks is due
  // 1 ms later (React Query schedules its notifications that way).
  for (let i = 0; i < 6; i++) await act(async () => void (await vi.advanceTimersByTimeAsync(1)));
}
async function advance(ms: number) {
  await act(async () => void (await vi.advanceTimersByTimeAsync(ms)));
  await flush();
}
async function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <AuditPage />
      </QueryClientProvider>,
    );
  });
  await flush();
}
async function signal(times = 1) {
  for (let i = 0; i < times; i++) {
    await act(async () => fake.signal?.());
    await flush();
  }
}
const reads = () => fake.api.listAuditEvents!.mock.calls.length;
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
// The loading skeleton inside the feed (the "Live" dot elsewhere pulses too).
const skeletons = () =>
  byTestId("audit-feed")[0]!.findAll((n) => typeof n.type === "string" && String(n.props.className ?? "").includes("animate-pulse"));
const refused = () => {
  expect(byTestId("audit-denied")).toHaveLength(1);
  expect(skeletons()).toHaveLength(0);
};
const showsLog = () => {
  expect(byTestId("audit-denied")).toHaveLength(0);
  expect(byTestId("audit-error")).toHaveLength(0);
  expect(skeletons()).toHaveLength(0);
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  fake.signal = undefined;
  fake.membership = undefined;
  fake.api = {
    getOrganization: vi.fn(async () => ({ id: "org_1", slug: "acme", name: "Acme" })),
    listAuditEvents: vi.fn(),
  };
});
afterEach(() => {
  root?.unmount();
  focusManager.setFocused(undefined);
  vi.useRealTimers();
});

describe("audit page after a failed read", () => {
  it("shows a stable refusal and collapses change signals into one read per backoff", async () => {
    fake.api.listAuditEvents!.mockRejectedValue(denied());
    await mount();
    expect(reads()).toBe(1);
    refused();

    // Each refusal is recorded and moves the signal.
    await signal(10);
    expect(reads()).toBe(1);
    refused();
    await advance(AUDIT_BACKOFF_MS - 1_000);
    expect(reads()).toBe(1);
    refused();
    await advance(1_000);
    expect(reads()).toBe(2);
    refused();
  });

  it("picks up access granted without a membership change after the backoff", async () => {
    fake.api.listAuditEvents!.mockRejectedValueOnce(denied()).mockResolvedValue(PAGE);
    await mount();
    refused();
    // The grant (directly, or through a team) moves the org signal only.
    await signal();
    expect(reads()).toBe(1);
    await advance(AUDIT_BACKOFF_MS);
    expect(reads()).toBe(2);
    showsLog();
  });

  it.each([
    ["a concealed 404", () => apiError(404, "NOT_FOUND")],
    ["a 502", () => apiError(502, "INTERNAL")],
    ["a network error", () => new TypeError("Failed to fetch")],
  ])("bounds the loop on %s to one read per backoff", async (_name, failure) => {
    // Every failed read is recorded server-side and moves the signal.
    fake.api.listAuditEvents!.mockImplementation(async () => {
      setTimeout(() => fake.signal?.(), 0);
      throw failure();
    });
    await mount();
    for (let t = 0; t < 95_000; t += 5_000) await advance(5_000);
    // Reads at 0, 30, 60 and 90 seconds.
    expect(reads()).toBe(4);
    expect(byTestId("audit-error")).toHaveLength(1);
    expect(skeletons()).toHaveLength(0);
  });

  it("does not let the reconnect catch-up skip the backoff", async () => {
    fake.api.listAuditEvents!.mockRejectedValue(denied());
    await mount();
    // LiveUpdatesStatus: scope "all" invalidates every query.
    await act(async () => {
      for (let i = 0; i < 5; i++) void client.invalidateQueries();
    });
    await flush();
    expect(reads()).toBe(1);
    refused();
    await advance(AUDIT_BACKOFF_MS);
    expect(reads()).toBe(2);
  });

  it("holds back window focus and degraded polling too", async () => {
    fake.api.listAuditEvents!.mockRejectedValue(denied());
    await mount();
    for (let i = 0; i < 3; i++) {
      await act(async () => {
        focusManager.setFocused(false);
        focusManager.setFocused(true);
      });
      // LiveUpdatesStatus polling: refetch what is on screen.
      await act(async () => void client.refetchQueries({ type: "active" }));
      await flush();
    }
    expect(reads()).toBe(1);
    refused();
    await advance(AUDIT_BACKOFF_MS);
    expect(reads()).toBe(2);
  });

  it("reads at once when the member tries again", async () => {
    fake.api.listAuditEvents!.mockRejectedValue(denied());
    await mount();
    await signal();
    await act(async () => byTestId("audit-retry")[0]!.props.onClick());
    await flush();
    expect(reads()).toBe(2);
    refused();
  });

  it("shows the log after a promotion that lands while a refused read is in flight", async () => {
    let refuse: (err: Error) => void = () => {};
    fake.api.listAuditEvents!
      .mockImplementationOnce(() => new Promise((_, reject) => (refuse = reject)))
      .mockResolvedValue(PAGE);
    await mount();
    expect(reads()).toBe(1);

    // The person's membership signal, then the shell watcher's refetch-all.
    await act(async () => fake.membership?.());
    await flush();
    await act(async () => void client.invalidateQueries());
    await flush();
    // The read sent before the promotion is refused, but no longer counts.
    await act(async () => refuse(denied()));
    await flush();
    // Before, the promotion read, and the watcher's refetch of a log that loaded.
    expect(reads()).toBe(3);
    showsLog();
  });
});

describe("audit page live updates", () => {
  it("refetches at once on every signal for an owner", async () => {
    fake.api.listAuditEvents!.mockResolvedValue(PAGE);
    await mount();
    expect(reads()).toBe(1);
    await signal();
    expect(reads()).toBe(2);
    await signal(2);
    expect(reads()).toBe(4);
    showsLog();
  });

  it("reads once more for an owner when signals arrive during a read", async () => {
    const pending: ((page: unknown) => void)[] = [];
    fake.api.listAuditEvents!.mockImplementation(() => new Promise((resolve) => pending.push(resolve)));
    await mount();
    expect(reads()).toBe(1);

    // Two signals during the read collapse into one follow-up read.
    await signal(2);
    expect(reads()).toBe(1);
    await act(async () => pending[0]!(PAGE));
    await flush();
    expect(reads()).toBe(2);
    await act(async () => pending[1]!(PAGE));
    await flush();
    expect(reads()).toBe(2);
  });
});
