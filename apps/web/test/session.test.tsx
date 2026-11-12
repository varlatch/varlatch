// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
vi.hoisted(() => {
  vi.stubGlobal("location", { origin: "https://varlatch.example", hostname: "varlatch.example" });
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
vi.mock("better-auth/client", () => ({ createAuthClient: () => ({ signOut: async () => {}, signIn: { passkey: async () => ({}) } }) }));
vi.mock("@better-auth/passkey/client", () => ({ passkeyClient: () => ({}) }));
import { SessionProvider, useSession } from "../src/lib/session";
let state: ReturnType<typeof useSession>;
let root: ReactTestRenderer;
const probe = () => { state = useSession(); return null; };
async function mount() {
  const client = new QueryClient();
  await act(async () => {
    root = create(<QueryClientProvider client={client}><SessionProvider>{React.createElement(probe)}</SessionProvider></QueryClientProvider>);
  });
  return client;
}
afterEach(async () => { if (root) await act(async () => root.unmount()); vi.unstubAllGlobals(); });
it("clears cached data on logout and rejects a late response from the old identity", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("location", { origin: "https://varlatch.example" });
  let resolve!: (r: Response) => void;
  vi.stubGlobal("fetch", async (url: unknown) => String(url).includes("varlatch-token")
    ? Response.json({ token: "old-token", identityId: "old-id" })
    : new Promise<Response>(r => { resolve = r; }));
  const client = await mount();
  client.setQueryData(["values"], "private old values");
  const pending = state.api.listOrganizations();
  const denied = expect(pending).rejects.toMatchObject({ name: "AbortError" });
  await act(async () => state.signOut());
  expect(client.getQueryCache().getAll()).toHaveLength(0);
  expect(state.needsAuth).toBe(true);
  resolve(Response.json({ items: [{ id: "old-org" }] }));
  await denied;
});
it("clears caches when a silent refresh discovers a different identity", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("location", { origin: "https://varlatch.example" });
  let exchanges = 0;
  vi.stubGlobal("fetch", async (url: unknown) => String(url).includes("varlatch-token")
    ? Response.json({ token: "token", identityId: ++exchanges === 1 ? "first" : "second" })
    : new Response(null, { status: 401 }));
  const client = await mount();
  client.setQueryData(["values"], "first identity values");
  await act(async () => { await expect(state.api.listOrganizations()).rejects.toMatchObject({ name: "AbortError" }); });
  expect(state.identityId).toBe("second");
  expect(client.getQueryCache().getAll()).toHaveLength(0);
});
it("shows maintenance, never sign-in, when the session exchange answers MAINTENANCE (ADR-0036 D6)", async () => {
  vi.useFakeTimers();
  try {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    vi.stubGlobal("location", { origin: "https://varlatch.example" });
    let open = false;
    vi.stubGlobal("fetch", async (url: unknown) => {
      if (!String(url).includes("varlatch-token")) return Response.json({ items: [] });
      return open
        ? Response.json({ token: "token", identityId: "me" })
        : Response.json({ error: { code: "MAINTENANCE", message: "Installation maintenance; retry later", requestId: "r" } },
            { status: 503, headers: { "Retry-After": "2" } });
    });
    await mount();
    expect(state.maintenance).toBe(true);
    expect(state.needsAuth).toBe(false);
    expect(state.identityId).toBeNull();
    // The exchange retries on its own once the window ends.
    open = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(state.identityId).toBe("me");
    expect(state.maintenance).toBe(false);
    expect(state.needsAuth).toBe(false);
  } finally { vi.useRealTimers(); }
});
it("notes a refusal by passkey-verification, offers to sign in again, and forgets it after a new sign-in (ADR-0054 Decision 7)", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("location", { origin: "https://varlatch.example", hostname: "varlatch.example" });
  let exchanges = 0;
  vi.stubGlobal("fetch", async (url: unknown) => {
    if (String(url).includes("varlatch-token")) return Response.json({ token: `token-${++exchanges}`, identityId: "me" });
    return Response.json(
      { error: { code: "PASSKEY_VERIFICATION_REQUIRED", message: "Sign in again", requestId: "r", details: { control: "passkey-verification", reason: "not-user-verified" } } },
      { status: 403 },
    );
  });
  const { PasskeyVerificationBanner, VERIFICATION_GAP_TEXT } = await import("../src/shell/AuthScreens");
  const client = new QueryClient();
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <SessionProvider>
          {React.createElement(probe)}
          <PasskeyVerificationBanner />
        </SessionProvider>
      </QueryClientProvider>,
    );
  });
  const banner = () => root.root.findAll((n) => n.props["data-testid"] === "passkey-verification-required");
  expect(state.verificationRequired).toBeNull();
  expect(banner()).toHaveLength(0);
  await act(async () => { await expect(state.api.listOrganizations()).rejects.toMatchObject({ code: "PASSKEY_VERIFICATION_REQUIRED" }); });
  expect(state.verificationRequired).toBe("not-user-verified");
  expect(banner()).toHaveLength(1);
  const text = (node: { children: unknown[] }): string => node.children.map((c) => (typeof c === "string" ? c : text(c as { children: unknown[] }))).join("");
  expect(text(banner()[0]!)).toContain(VERIFICATION_GAP_TEXT["not-user-verified"]);
  // "Sign in again" signs out: the route-preserving sign-in screen follows.
  const again = root.root.findAll((n) => n.props["data-testid"] === "passkey-verification-sign-in-again" && typeof n.props.onClick === "function")[0]!;
  await act(async () => { again.props.onClick(); });
  expect(state.needsAuth).toBe(true);
  // The next sign-in starts without the note.
  await act(async () => { await state.signInWithPasskey(); });
  expect(state.needsAuth).toBe(false);
  expect(state.verificationRequired).toBeNull();
});
it("raises no banner for turning passkey-verification on from a sign-in it would refuse (details.change refused)", async () => {
  const { verificationGapOf } = await import("../src/lib/session");
  const answer = (details: Record<string, unknown>) =>
    Response.json({ error: { code: "PASSKEY_VERIFICATION_REQUIRED", message: "no", requestId: "r", details } }, { status: 403 });
  expect(await verificationGapOf(answer({ control: "passkey-verification", reason: "no-evidence", change: "refused" }))).toBeNull();
  expect(await verificationGapOf(answer({ control: "passkey-verification", reason: "untrusted-passkey" }))).toBe("untrusted-passkey");
  expect(await verificationGapOf(Response.json({ error: { code: "PERMISSION_DENIED", message: "no", requestId: "r" } }, { status: 403 }))).toBeNull();
});
