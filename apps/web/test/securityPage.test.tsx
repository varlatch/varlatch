// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { OwnPasskey } from "@varlatch/sdk";

/**
 * The account Security page (ADR-0054 Decision 4): each passkey says
 * whether it is trusted or unconfirmed and why, an unconfirmed one can be
 * confirmed with a trusted one, a person with no trusted passkey is told
 * the way back, and removal goes through Varlatch's route, not Better
 * Auth's.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  startAuthentication: vi.fn(),
  confirmed: true,
}));
vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }), addPasskey: vi.fn() }));
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: fake.startAuthentication }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({ useConfirm: () => async () => fake.confirmed, usePrompt: () => async () => null }));
vi.mock("../src/components/Select", () => ({
  Select: () => null,
  Menu: ({ items, label }: { items: { label: string; onSelect: () => void; disabled?: boolean; "data-testid"?: string }[]; label: string }) => (
    <div data-menu={label}>
      {items.map((item) => (
        <button key={item.label} data-testid={item["data-testid"]} disabled={item.disabled} onClick={item.onSelect}>
          {item.label}
        </button>
      ))}
    </div>
  ),
}));

import { SecurityPage, provenanceText } from "../src/features/account/SecurityPage";

const key = (id: string, over: Partial<OwnPasskey> = {}): OwnPasskey => ({
  id,
  name: id,
  deviceType: "multiDevice",
  backedUp: true,
  createdAt: "2026-11-01T10:00:00Z",
  trust: "trusted",
  trustedVia: "existing-at-upgrade",
  trustedAt: "2026-11-01T10:00:00Z",
  setupGrantKind: null,
  confirmedByPasskeyId: null,
  ...over,
});
const UNCONFIRMED = { trust: "unconfirmed", trustedVia: null, trustedAt: null } as const;

let root: ReactTestRenderer;
async function mount(items: OwnPasskey[]) {
  fake.api.listMyPasskeys = vi.fn(async () => ({ items, nextCursor: null }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <SecurityPage />
      </QueryClientProvider>,
    );
  });
  await settle();
}
const settle = async () => {
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);

beforeEach(() => {
  fake.api = {
    removeMyPasskey: vi.fn(async () => undefined),
    startPasskeyConfirmation: vi.fn(async () => ({ publicKey: { challenge: "c1", userVerification: "required" } })),
    confirmMyPasskey: vi.fn(async (id: string) => key(id, { trustedVia: "confirmed", confirmedByPasskeyId: "pk_a" })),
  };
  fake.startAuthentication.mockReset();
  fake.startAuthentication.mockResolvedValue({ id: "cred-a", response: {} });
  fake.confirmed = true;
});

describe("the account Security page", () => {
  it("shows each passkey's provenance, and offers the confirmation for unconfirmed ones only", async () => {
    await mount([key("pk_a"), key("pk_new", UNCONFIRMED)]);
    expect(text(byTestId("passkey-trust-pk_a")[0]!)).toContain("Trusted");
    expect(text(byTestId("passkey-trust-pk_new")[0]!)).toContain("Unconfirmed");
    expect(text(byTestId("passkey-provenance-pk_new")[0]!)).toContain("Confirm it with a trusted passkey");
    expect(byTestId("confirm-passkey-pk_a")).toHaveLength(0);
    expect(byTestId("confirm-passkey-pk_new")).toHaveLength(1);
    expect(byTestId("no-trusted-passkey")).toHaveLength(0);
    expect(text(byTestId("passkey-trust-explainer")[0]!)).toContain("Only a trusted passkey can approve a change");
  });

  it("confirms with the browser's passkey prompt over the server's challenge", async () => {
    await mount([key("pk_a"), key("pk_new", UNCONFIRMED)]);
    await act(async () => byTestId("confirm-passkey-pk_new")[0]!.props.onClick());
    await settle();
    expect(fake.api.startPasskeyConfirmation).toHaveBeenCalledWith("pk_new");
    expect(fake.startAuthentication).toHaveBeenCalledWith({ optionsJSON: { challenge: "c1", userVerification: "required" } });
    expect(fake.api.confirmMyPasskey).toHaveBeenCalledWith("pk_new", { id: "cred-a", response: {} });
    // The list is read again.
    expect(fake.api.listMyPasskeys).toHaveBeenCalledTimes(2);
  });

  it("sends nothing when the passkey prompt is cancelled", async () => {
    fake.startAuthentication.mockRejectedValue(Object.assign(new Error("cancelled"), { name: "NotAllowedError" }));
    await mount([key("pk_a"), key("pk_new", UNCONFIRMED)]);
    await act(async () => byTestId("confirm-passkey-pk_new")[0]!.props.onClick());
    await settle();
    expect(fake.api.confirmMyPasskey).not.toHaveBeenCalled();
  });

  it("tells a person with no trusted passkey that the host operator can enroll one, and offers no confirmation", async () => {
    await mount([key("pk_1", UNCONFIRMED), key("pk_2", UNCONFIRMED)]);
    const callout = byTestId("no-trusted-passkey");
    expect(callout).toHaveLength(1);
    expect(text(callout[0]!)).toContain("varlatch admin reenroll");
    expect(text(callout[0]!)).toContain("Signing in works as before");
    expect(byTestId("confirm-passkey-pk_1")).toHaveLength(0);
  });

  it("removes a passkey through Varlatch's route, and never the last one", async () => {
    await mount([key("pk_a"), key("pk_b", UNCONFIRMED)]);
    await act(async () => byTestId("remove-passkey-pk_b")[0]!.props.onClick());
    await settle();
    expect(fake.api.removeMyPasskey).toHaveBeenCalledWith("pk_b");

    await mount([key("pk_only")]);
    expect(byTestId("remove-passkey-pk_only")[0]!.props.disabled).toBe(true);
  });

  it("says where a trusted passkey's trust comes from", () => {
    expect(provenanceText(key("a", { trustedVia: "setup-grant", setupGrantKind: "invite" }))).toBe("Trusted: enrolled with an invitation link.");
    expect(provenanceText(key("a", { trustedVia: "setup-grant", setupGrantKind: "reenroll" }))).toBe("Trusted: enrolled with a link from whoever runs this server.");
    expect(provenanceText(key("a", { trustedVia: "confirmed", trustedAt: "2026-11-02T10:00:00Z" }))).toMatch(/^Trusted: confirmed with another passkey on /);
    expect(provenanceText(key("a"))).toContain("already enrolled");
  });
});
