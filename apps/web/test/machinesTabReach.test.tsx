// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Reach stays current in Access, Machines (ADR-0054 Decision 8): a
 * mutation that changes a machine's state or credentials (reactivate,
 * retire, issue, revoke) refetches the open Reach panel.
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
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/features/projects/hooks", () => ({
  useCapability: (c: string) => ["identity.lifecycle", "identity.reach", "identity.credentials.issue"].includes(c),
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
  usePrompt: () => async () => null,
}));
// The real menu opens a popover; here every item is a plain button.
vi.mock("../src/components/Select", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  Menu: ({ items }: { items: { label: React.ReactNode; onSelect: () => void; "data-testid"?: string }[] }) => (
    <div>
      {items.map((item, i) => (
        <button key={i} type="button" data-testid={item["data-testid"]} onClick={item.onSelect}>
          {item.label}
        </button>
      ))}
    </div>
  ),
}));

import { MachinesTab } from "../src/features/access/MachinesTab";

type State = "live" | "retired";
let state: State;
let liveCredentials: number;

const reach = () => ({
  identity: { id: "idn_svc", name: "deployer", kind: "service", state, disabledReason: null, liveCredentials },
  organizationActions: [],
  projects: [],
  requirements: [],
  notes: [],
});

let root: ReactTestRenderer;
const settle = async () => {
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MachinesTab org="acme" onGrant={() => {}} />
      </QueryClientProvider>,
    );
  });
  await settle();
}
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const click = async (node: ReactTestInstance) => {
  await act(async () => node.props.onClick({ stopPropagation: () => {}, preventDefault: () => {} }));
  await settle();
};
const expand = async () => {
  const row = root.root.find((n) => n.type === "tr" && n.props["data-identity-id"] === "idn_svc");
  await click(row);
};
const reachState = () => text(byTestId("reach-state")[0]!);

beforeEach(() => {
  state = "live";
  liveCredentials = 1;
  fake.api = {
    listIdentities: vi.fn(async () => ({
      items: [
        { id: "idn_svc", name: "deployer", kind: "service", disabled: state === "retired", lastSeenAt: null, orgRole: null },
        // Another retired machine, so "Show retired" is offered from the start.
        { id: "idn_old", name: "old", kind: "service", disabled: true, lastSeenAt: null, orgRole: null },
      ],
      nextCursor: null,
    })),
    listGrants: vi.fn(async () => ({ items: [], nextCursor: null })),
    listOidcBindings: vi.fn(async () => ({ items: [], nextCursor: null })),
    listIdentityCredentials: vi.fn(async () => ({
      items:
        liveCredentials > 0
          ? [{ id: "crd_1", kind: "service", name: "deploy", createdAt: "2026-11-01T00:00:00.000Z", expiresAt: null, revokedAt: null, lastUsedAt: null }]
          : [],
      nextCursor: null,
    })),
    machineReach: vi.fn(async () => reach()),
    reactivateIdentity: vi.fn(async () => {
      state = "live";
      return { id: "idn_svc", disabled: false };
    }),
    retireIdentity: vi.fn(async () => {
      state = "retired";
      liveCredentials = 0;
      return { id: "idn_svc", disabled: true };
    }),
    revokeIdentityCredential: vi.fn(async () => {
      liveCredentials = 0;
    }),
  };
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

describe("Reach in Access, Machines", () => {
  it("refetches after reactivating an expanded retired machine", async () => {
    state = "retired";
    await mount();
    await click(byTestId("show-retired")[0]!);
    await expand();
    expect(reachState()).toContain("retired");
    expect(fake.api.machineReach).toHaveBeenCalledTimes(1);

    await click(byTestId("machine-reactivate-idn_svc")[0]!);
    expect(fake.api.reactivateIdentity).toHaveBeenCalledWith("acme", "idn_svc");
    expect(fake.api.machineReach).toHaveBeenCalledTimes(2);
    expect(reachState()).toContain("live");
  });

  it("refetches after retiring an expanded machine", async () => {
    await mount();
    // Retired machines shown, so the row and its panel stay after retiring.
    await click(byTestId("show-retired")[0]!);
    await expand();
    expect(reachState()).toContain("live");
    await click(byTestId("machine-retire-idn_svc")[0]!);
    expect(fake.api.retireIdentity).toHaveBeenCalledWith("acme", "idn_svc");
    expect(reachState()).toContain("retired");
    expect(reachState()).toContain("0 live credentials");
  });

  it("refetches after revoking a credential, so the live count is current", async () => {
    await mount();
    await expand();
    expect(reachState()).toContain("1 live credential");
    await click(byTestId("revoke-credential-crd_1")[0]!);
    expect(fake.api.revokeIdentityCredential).toHaveBeenCalledWith("acme", "idn_svc", "crd_1");
    expect(fake.api.machineReach).toHaveBeenCalledTimes(2);
    expect(reachState()).toContain("0 live credentials");
  });
});
