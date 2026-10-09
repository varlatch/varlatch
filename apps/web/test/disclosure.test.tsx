// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});
const discloseSecrets = vi.fn();
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: { discloseSecrets }, authEpoch: 0 }) }));
import { useDisclosure, type DisclosureApi } from "../src/features/values/useDisclosure";

/**
 * Plaintext revealed before a Tailnet Requirement appeared: hidden in the
 * render the restriction arrives, dropped from memory, and a disclosure in
 * flight at that moment is discarded when it lands.
 */

const NONE: ReadonlySet<string> = new Set();
const PROD: ReadonlySet<string> = new Set(["production"]);
let hook: DisclosureApi;
let root: ReactTestRenderer | undefined;
// What each render showed, before its effects ran.
let rendered: { restricted: boolean; value: string | undefined }[] = [];

function Probe({ restricted }: { restricted: ReadonlySet<string> }) {
  hook = useDisclosure("acme", "api", restricted);
  rendered.push({ restricted: restricted.has("production"), value: hook.shown("production", "DATABASE_URL")?.value });
  return null;
}
async function render(restricted: ReadonlySet<string>) {
  await act(async () => {
    if (root) root.update(<Probe restricted={restricted} />);
    else root = create(<Probe restricted={restricted} />);
  });
}
const disclosed = (items: Record<string, string>) => ({
  items: Object.entries(items).map(([name, value]) => ({ name, value })),
  withheld: [],
});

beforeEach(() => {
  discloseSecrets.mockReset();
  rendered = [];
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
});

describe("disclosures when an environment turns tailnet-only", () => {
  it("hides what was revealed at once, and drops it from memory", async () => {
    discloseSecrets.mockResolvedValueOnce(disclosed({ DATABASE_URL: "postgres://prod" }));
    await render(NONE);
    await act(async () => void (await hook.reveal("production", ["DATABASE_URL"])));
    expect(hook.shown("production", "DATABASE_URL")?.value).toBe("postgres://prod");

    await render(PROD);
    // Including the first restricted render, before the cleanup effect.
    const restrictedRenders = rendered.filter((r) => r.restricted);
    expect(restrictedRenders.length).toBeGreaterThan(0);
    expect(restrictedRenders.every((r) => r.value === undefined)).toBe(true);
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
    expect(hook.isDisclosed("production", "DATABASE_URL")).toBe(false);
    expect(hook.revealedEnvs).toEqual([]);
    expect(hook.count).toBe(0);

    // Gone, not just hidden: lifting the restriction brings nothing back.
    await render(NONE);
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
  });

  it("discards a disclosure that lands after the restriction", async () => {
    let land!: (r: ReturnType<typeof disclosed>) => void;
    discloseSecrets.mockReturnValueOnce(new Promise((r) => (land = r)));
    await render(NONE);
    let pending!: Promise<unknown>;
    await act(async () => {
      pending = hook.reveal("production", "all");
    });
    await render(PROD);
    const refused = expect(pending).rejects.toMatchObject({ code: "TAILNET_ONLY" });
    await act(async () => land(disclosed({ DATABASE_URL: "postgres://prod" })));
    await refused;
    await render(NONE);
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
  });

  it("keeps a disclosure discarded when the restriction is lifted before it lands", async () => {
    let land!: (r: ReturnType<typeof disclosed>) => void;
    discloseSecrets.mockReturnValueOnce(new Promise((r) => (land = r)));
    await render(NONE);
    let pending!: Promise<unknown>;
    await act(async () => {
      pending = hook.reveal("production", ["DATABASE_URL"]);
    });
    // Reveal, then a requirement is added, then removed, then the response lands.
    await render(PROD);
    await render(NONE);
    const refused = expect(pending).rejects.toMatchObject({ code: "DISCLOSURE_DISCARDED" });
    await act(async () => land(disclosed({ DATABASE_URL: "postgres://prod" })));
    await refused;
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
    // A reveal started after the cleanup works again.
    discloseSecrets.mockResolvedValueOnce(disclosed({ DATABASE_URL: "postgres://prod-2" }));
    await act(async () => void (await hook.reveal("production", ["DATABASE_URL"])));
    expect(hook.shown("production", "DATABASE_URL")?.value).toBe("postgres://prod-2");
  });

  it("discards a disclosure in flight when everything is masked", async () => {
    let land!: (r: ReturnType<typeof disclosed>) => void;
    discloseSecrets.mockReturnValueOnce(new Promise((r) => (land = r)));
    await render(NONE);
    let pending!: Promise<unknown>;
    await act(async () => {
      pending = hook.reveal("development", ["DATABASE_URL"]);
    });
    await act(async () => hook.maskAll());
    const refused = expect(pending).rejects.toMatchObject({ code: "DISCLOSURE_DISCARDED" });
    await act(async () => land(disclosed({ DATABASE_URL: "postgres://dev" })));
    await refused;
    expect(hook.shown("development", "DATABASE_URL")).toBeUndefined();
  });

  it("refuses a reveal in a restricted environment without asking the server", async () => {
    await render(PROD);
    await expect(hook.reveal("production", ["DATABASE_URL"])).rejects.toMatchObject({ code: "TAILNET_ONLY" });
    expect(discloseSecrets).not.toHaveBeenCalled();
  });

  it("clears an environment when the server answers with a tailnet denial", async () => {
    discloseSecrets.mockResolvedValueOnce(disclosed({ DATABASE_URL: "postgres://prod" }));
    discloseSecrets.mockRejectedValueOnce(Object.assign(new Error("denied"), { code: "TAILNET_CONTEXT_REQUIRED" }));
    await render(NONE);
    await act(async () => void (await hook.reveal("production", ["DATABASE_URL"])));
    await act(async () => {
      await expect(hook.reveal("production", ["API_KEY"])).rejects.toMatchObject({ code: "TAILNET_CONTEXT_REQUIRED" });
    });
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
  });

  it("leaves other environments alone", async () => {
    discloseSecrets.mockResolvedValueOnce(disclosed({ DATABASE_URL: "postgres://dev" }));
    discloseSecrets.mockResolvedValueOnce(disclosed({ DATABASE_URL: "postgres://prod" }));
    await render(NONE);
    await act(async () => void (await hook.reveal("development", ["DATABASE_URL"])));
    await act(async () => void (await hook.reveal("production", ["DATABASE_URL"])));
    await render(PROD);
    expect(hook.shown("development", "DATABASE_URL")?.value).toBe("postgres://dev");
    expect(hook.shown("production", "DATABASE_URL")).toBeUndefined();
    expect(hook.revealedEnvs).toEqual(["development"]);
  });
});
