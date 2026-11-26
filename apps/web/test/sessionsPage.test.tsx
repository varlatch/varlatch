// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

/**
 * Active sessions: "Sign out everywhere else" signs the other browsers out
 * by their sessions (POST /v1/me/sessions/sign-out-others), so a browser
 * with no bearer of its own is reached too, and revokes the other live
 * non-browser credentials one by one; "Sign out" on this browser ends its
 * session with the cookie sign-out, and says so when the server refuses.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  signOut: vi.fn(),
  toastError: vi.fn(),
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", {
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    addEventListener: () => {},
    removeEventListener: () => {},
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, signOut: fake.signOut }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: fake.toastError }) }));
vi.mock("../src/components/Dialog", () => ({ useConfirm: () => async () => true }));

import { SessionsPage } from "../src/features/account/SessionsPage";

const later = new Date(Date.now() + 10 * 60_000).toISOString();
const earlier = new Date(Date.now() - 10 * 60_000).toISOString();
const cred = (id: string, kind: string, extra: Record<string, unknown> = {}) => ({
  id, kind, name: null, createdAt: earlier, expiresAt: later, revokedAt: null, maxUses: null, useCount: 0, current: false, client: null, ...extra,
});
const ITEMS = [
  cred("crd_this", "browser", { current: true }),
  cred("crd_other_browser", "browser"),
  cred("crd_idle_browser", "browser", { expiresAt: earlier }),
  cred("crd_cli", "cli", { expiresAt: null }),
  cred("crd_old_cli", "cli", { revokedAt: earlier }),
];

let root: ReactTestRenderer;
beforeEach(() => {
  fake.api = {
    listMyCredentials: vi.fn(async () => ({ items: ITEMS, nextCursor: null })),
    revokeMyCredential: vi.fn(async () => undefined),
    signOutOtherSessions: vi.fn(async () => ({ endedSessions: 2 })),
  };
  fake.signOut = vi.fn(async () => undefined);
  fake.toastError = vi.fn();
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
});

async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <SessionsPage />
      </QueryClientProvider>,
    );
  });
  await flush();
}
const flush = () =>
  act(async () => {
    for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  });
const click = async (testId: string) => {
  const button = root.root.find((n) => n.props["data-testid"] === testId && typeof n.props.onClick === "function");
  await act(async () => {
    await button.props.onClick();
  });
  await flush();
};

it("signs the other browsers out by their sessions and revokes the other live credentials", async () => {
  await mount();
  await click("revoke-others");
  expect(fake.api.signOutOtherSessions).toHaveBeenCalledTimes(1);
  expect(fake.api.revokeMyCredential!.mock.calls.map((c) => c[0])).toEqual(["crd_cli"]);
});

it("signs this browser out with its session cookie", async () => {
  await mount();
  await click("revoke-credential-crd_this");
  expect(fake.signOut).toHaveBeenCalledTimes(1);
  expect(fake.api.revokeMyCredential).not.toHaveBeenCalled();
  expect(fake.toastError).not.toHaveBeenCalled();
});

it("says so when the server does not sign this browser out", async () => {
  fake.signOut = vi.fn(async () => {
    throw new Error("sign-out failed: 503");
  });
  await mount();
  await click("revoke-credential-crd_this");
  expect(fake.toastError).toHaveBeenCalledWith("Could not sign out", { description: "sign-out failed: 503" });
});
