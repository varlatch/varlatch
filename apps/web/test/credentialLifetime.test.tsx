// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * credential-lifetime in Access, Machines (ADR-0054 step 4.3): while the
 * Organization enforces it, the lifetime fields say what leaving them empty
 * does (the default) and keep a lifetime above the maximum from being
 * sent; otherwise they say what they always did. The server decides
 * either way (CREDENTIAL_LIFETIME_EXCEEDED).
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>>, capabilities: [] as string[] }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
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
vi.mock("../src/features/projects/hooks", () => ({ useCapability: (c: string) => fake.capabilities.includes(c) }));
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

import { enforcedLifetime, lifetimeError, lifetimeHint } from "../src/features/access/credentialLifetime";
import { MachinesTab } from "../src/features/access/MachinesTab";

const LIFETIMES = { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 };
const control = (mode: "off" | "report" | "enforce", config: typeof LIFETIMES | null = LIFETIMES) => ({
  control: "credential-lifetime" as const, mode, config, version: 1, changedAt: null, changedBy: null,
});

describe("the helpers", () => {
  it("find the lifetimes only while credential-lifetime is enforced", () => {
    expect(enforcedLifetime(undefined)).toBeNull();
    expect(enforcedLifetime({ items: [control("report")] })).toBeNull();
    expect(enforcedLifetime({ items: [control("off", null)] })).toBeNull();
    expect(enforcedLifetime({ items: [control("enforce")] })).toEqual(LIFETIMES);
  });

  it("say what an empty field does, and refuse a lifetime above the maximum", () => {
    expect(lifetimeHint(null)).toBe("Empty: no expiry, revocation only.");
    expect(lifetimeHint(LIFETIMES)).toBe("Empty: this organization's default, 1 hour. At most 1 day (86400 seconds).");
    expect(lifetimeError("", LIFETIMES)).toBeUndefined();
    expect(lifetimeError("0", null)).toBe("Whole seconds, at least 1.");
    expect(lifetimeError("86400", LIFETIMES)).toBeUndefined();
    expect(lifetimeError("86401", LIFETIMES)).toBe("This organization allows at most 1 day (86400 seconds).");
    expect(lifetimeError("315360000", null)).toBeUndefined();
  });
});

let root: ReactTestRenderer;
const settle = async () => {
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

async function openNewMachine() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MachinesTab org="acme" onGrant={() => {}} />
      </QueryClientProvider>,
    );
  });
  await settle();
  await act(async () => byTestId("new-machine")[0]!.props.onClick());
  await settle();
  await act(async () => byTestId("machine-name")[0]!.props.onChange({ target: { value: "deploy-bot" } }));
}
const typeTtl = async (value: string) => act(async () => byTestId("machine-ttl")[0]!.props.onChange({ target: { value } }));
const dialog = () => text(byTestId("new-machine-dialog")[0]!);
const createDisabled = () => byTestId("create-machine")[0]!.props.disabled as boolean;

beforeEach(() => {
  fake.capabilities = ["identity.lifecycle", "security.controls"];
  fake.api = {
    listIdentities: vi.fn(async () => ({ items: [], nextCursor: null })),
    listGrants: vi.fn(async () => ({ items: [], nextCursor: null })),
    listSecurityControls: vi.fn(async () => ({ items: [control("enforce")], availableModes: ["off", "report"] })),
  };
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

describe("New machine", () => {
  it("names the default and the maximum while the organization enforces credential-lifetime, and keeps a longer lifetime back", async () => {
    await openNewMachine();
    expect(fake.api.listSecurityControls).toHaveBeenCalledWith("acme");
    expect(dialog()).toContain("Empty: this organization's default, 1 hour. At most 1 day (86400 seconds).");
    await typeTtl("86401");
    expect(dialog()).toContain("This organization allows at most 1 day");
    expect(createDisabled()).toBe(true);
    await typeTtl("86400");
    expect(createDisabled()).toBe(false);
  });

  it("says what it always did when the control is not enforced, or the server has no controls", async () => {
    fake.api.listSecurityControls = vi.fn(async () => ({ items: [control("report")], availableModes: ["off", "report"] }));
    await openNewMachine();
    expect(dialog()).toContain("Empty: no expiry, revocation only.");
    await typeTtl("315360000");
    expect(createDisabled()).toBe(false);
    await act(async () => root.unmount());

    fake.capabilities = ["identity.lifecycle"];
    fake.api.listSecurityControls = vi.fn();
    await openNewMachine();
    expect(fake.api.listSecurityControls).not.toHaveBeenCalled();
    expect(dialog()).toContain("Empty: no expiry, revocation only.");
  });
});
