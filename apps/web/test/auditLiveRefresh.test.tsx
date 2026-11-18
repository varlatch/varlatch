// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The Audit page's live updates must not feed on its own refusals: a refused
 * read is an audit event, which moves the org's change signal. A member
 * without audit.read sees a stable refusal and no further reads; an owner
 * still gets live updates.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  signal: undefined as (() => void) | undefined,
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
import { AuditPage } from "../src/features/audit/AuditPage";

const denied = () =>
  new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "audit.read required", requestId: "req_1" } as never);

let root: ReactTestRenderer;
async function flush() {
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
// The loading skeleton inside the feed (the "Live" dot elsewhere pulses too).
const skeletons = () =>
  byTestId("audit-feed")[0]!.findAll((n) => typeof n.type === "string" && String(n.props.className ?? "").includes("animate-pulse"));

beforeEach(() => {
  fake.signal = undefined;
  fake.api = {
    getOrganization: vi.fn(async () => ({ id: "org_1", slug: "acme", name: "Acme" })),
    listAuditEvents: vi.fn(),
  };
});

describe("audit page live updates", () => {
  it("shows a member's refusal once and stops reading on change signals", async () => {
    fake.api.listAuditEvents!.mockImplementation(async () => {
      throw denied();
    });
    await mount();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    expect(byTestId("audit-denied")).toHaveLength(1);

    // Each refusal is recorded and moves the signal; none of that is read again.
    await signal(10);
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    expect(byTestId("audit-denied")).toHaveLength(1);
    expect(skeletons()).toHaveLength(0);
  });

  it("drops a signal that arrives while the refused read is still in flight", async () => {
    let refuse: (err: Error) => void = () => {};
    fake.api.listAuditEvents!.mockImplementation(() => new Promise((_, reject) => (refuse = reject)));
    await mount();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);

    // The denial event's signal can beat the 403 response to the browser.
    await signal(3);
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    await act(async () => refuse(denied()));
    await flush();
    await signal(3);
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    expect(byTestId("audit-denied")).toHaveLength(1);
    expect(skeletons()).toHaveLength(0);
  });

  it("reads again when the member retries by hand", async () => {
    fake.api.listAuditEvents!.mockImplementation(async () => {
      throw denied();
    });
    await mount();
    await act(async () => byTestId("audit-retry")[0]!.props.onClick());
    await flush();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(2);
    expect(byTestId("audit-denied")).toHaveLength(1);
  });

  it("keeps live updates for an owner", async () => {
    fake.api.listAuditEvents!.mockImplementation(async () => ({ items: [], nextCursor: null }));
    await mount();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    await signal();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(2);
    await signal(2);
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(4);
    expect(byTestId("audit-denied")).toHaveLength(0);
  });

  it("reads once more for an owner when a signal arrives during a read", async () => {
    const pending: ((page: unknown) => void)[] = [];
    fake.api.listAuditEvents!.mockImplementation(() => new Promise((resolve) => pending.push(resolve)));
    await mount();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);

    // Two signals during the read collapse into one follow-up read.
    await signal(2);
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(1);
    await act(async () => pending[0]!({ items: [], nextCursor: null }));
    await flush();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(2);
    await act(async () => pending[1]!({ items: [], nextCursor: null }));
    await flush();
    expect(fake.api.listAuditEvents).toHaveBeenCalledTimes(2);
  });
});
