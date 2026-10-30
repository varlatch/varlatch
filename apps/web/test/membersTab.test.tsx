// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Who reaches exposure reports from the Members tab and the audit log
 * (ADR-0052 Decision 6): anyone who may read the audit log, whatever their
 * role, and a failed check is said, with a way to try again.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  // useNow ticks with window timers; the filter input listens for its hotkey.
  vi.stubGlobal("window", {
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    addEventListener: () => {},
    removeEventListener: () => {},
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, identityId: "idn_me", accessChanged: () => {} }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/features/projects/hooks", () => ({ useCapability: (c: string) => c === "members.lifecycle", useMeta: () => ({ data: { capabilities: ["members.lifecycle"] } }) }));
vi.mock("../src/features/access/useAccessNames", () => ({
  useAccessNames: () => ({ names: { project: () => undefined, environment: () => undefined, team: () => undefined }, nameOf: String, roleName: () => null }),
}));
vi.mock("../src/features/access/shared", async () => {
  const { useQuery } = await import("@tanstack/react-query");
  return { useIdentities: (org: string) => useQuery({ queryKey: ["identities", org], queryFn: () => fake.api.listIdentities!(org) }) };
});
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, children, footer, "data-testid": id }: Record<string, React.ReactNode> & { open: boolean; "data-testid"?: string }) =>
    open ? (
      <div data-testid={id}>
        <h2>{title}</h2>
        {children}
        {footer}
      </div>
    ) : null,
  useConfirm: () => async () => true,
}));

import { VarlatchApiError } from "@varlatch/sdk";
import { MembersTab } from "../src/features/access/MembersTab";
import { ExposureButton } from "../src/features/access/ExposureDialog";

const denied = () => new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "Not authorized for this action", requestId: "req_1" });
const REPORT = {
  member: { identityId: "idn_old", name: "Old", role: null, removedAt: "2026-10-01T10:00:00.000Z" },
  coverage: { complete: true },
  received: [],
  authorityAtRemoval: null,
  indirect: { syncTargets: [], connections: [], webhooks: [], oidcBindings: [], credentials: [], personalEnvironments: [] },
};

let root: ReactTestRenderer;
async function mount(element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>{element}</MemoryRouter>
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

beforeEach(() => {
  fake.api = {
    listIdentities: vi.fn(async () => ({
      items: [
        { id: "idn_me", name: "Me", kind: "human", disabled: false, orgRole: "member", removedAt: null },
        { id: "idn_old", name: "Old", kind: "human", disabled: false, orgRole: null, removedAt: "2026-10-01T10:00:00.000Z" },
      ],
      nextCursor: null,
    })),
    listGrants: vi.fn(async () => ({ items: [], nextCursor: null })),
    getOrganization: vi.fn(async () => ({ id: "org_a", slug: "acme", name: "Acme" })),
    listAuditEvents: vi.fn(async () => ({ items: [], nextCursor: null })),
    memberExposure: vi.fn(async () => REPORT),
    listInvitations: vi.fn(async () => ({ items: [], nextCursor: null })),
  };
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

describe("reports from the Members tab", () => {
  it("are open to a member who may read the audit log, not only to admins", async () => {
    await mount(<MembersTab org="acme" onGrant={() => {}} />);
    expect(fake.api.listAuditEvents).toHaveBeenCalledWith("acme", { limit: 1 });
    expect(all("exposure-idn_old")).toHaveLength(1);
    expect(all("audit-access-error")).toHaveLength(0);
  });

  it("are hidden from someone who may not read the audit log", async () => {
    fake.api.listAuditEvents = vi.fn(async () => {
      throw denied();
    });
    await mount(<MembersTab org="acme" onGrant={() => {}} />);
    expect(all("exposure-idn_old")).toHaveLength(0);
    expect(all("audit-access-error")).toHaveLength(0);
  });

  it("say when the check failed, and try again on request", async () => {
    fake.api.listAuditEvents = vi.fn(async () => {
      throw new Error("Network error");
    });
    await mount(<MembersTab org="acme" onGrant={() => {}} />);
    const [callout] = all("audit-access-error");
    expect(text(callout!)).toContain("Network error");
    fake.api.listAuditEvents = vi.fn(async () => ({ items: [], nextCursor: null }));
    const retry = callout!.findAll((n) => n.type === "button" || (typeof n.type !== "string" && typeof n.props.onClick === "function"))[0]!;
    await act(async () => retry.props.onClick());
    for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
    expect(fake.api.listAuditEvents).toHaveBeenCalled();
    expect(all("audit-access-error")).toHaveLength(0);
    expect(all("exposure-idn_old")).toHaveLength(1);
  });

  it("point to the audit log when people cannot be listed here", async () => {
    fake.api.listIdentities = vi.fn(async () => {
      throw denied();
    });
    await mount(<MembersTab org="acme" onGrant={() => {}} />);
    expect(text(all("reports-from-audit")[0]!)).toContain("open a report from an event in the audit log");
  });
});

describe("reports from the audit log", () => {
  it("open with audit.read alone: no identity listing needed", async () => {
    fake.api.listIdentities = vi.fn(async () => {
      throw denied();
    });
    await mount(<ExposureButton org="acme" person={{ id: "idn_old", name: "idn_old" }} />);
    await act(async () => all("audit-exposure")[0]!.props.onClick());
    for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
    expect(fake.api.memberExposure).toHaveBeenCalledWith("acme", "idn_old");
    // The report names the person, whatever the event knew.
    expect(text(all("exposure-dialog")[0]!)).toContain("What Old received");
  });
});
