// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Environment } from "@varlatch/protocol";
import type { VarlatchClient } from "@varlatch/sdk";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});
const ordinary = { discloseSecrets: vi.fn(), effectiveConfiguration: vi.fn() };
const tailnet = { discloseSecrets: vi.fn(), effectiveConfiguration: vi.fn() };
let tailnetClient: typeof tailnet | null = null;
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: ordinary, authEpoch: 0 }) }));
vi.mock("../src/lib/tailnetConnection", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/lib/tailnetConnection")>()),
  useTailnetConnection: () => ({ client: tailnetClient }),
}));
import { loadEnvValues, tailnetAccess } from "../src/features/values/queries";
import { useDisclosure, type DisclosureApi } from "../src/features/values/useDisclosure";
import { TailnetUnreachableError } from "../src/lib/tailnetConnection";
import { TailnetOnlyError } from "../src/lib/tailnet";

/**
 * Which origin protected value reads go to (ADR-0046 Decision 5): the
 * tailnet endpoint once this tab is connected, never the dashboard's own
 * origin, and only value reads and disclosures.
 */

const env = (name: string, tailnetRequired: boolean) => ({ id: `env_${name}`, name, tailnetRequired }) as unknown as Environment;
const PROD = env("production", true);
const DEV = env("development", false);
const DEVICE = { recognized: true, tailnet: "example.ts.net", nodeId: "nLAPTOP", nodeName: "laptop", tags: ["tag:prod"] };
const config = (items: { name: string; value: string | null; sensitive: boolean }[]) => ({ items, callerView: { withheld: [], unexpanded: [] } });
const denial = (code: string) => Object.assign(new Error(code), { code });
const reader = () => ({ client: tailnet as unknown as VarlatchClient, device: DEVICE });

beforeEach(() => {
  for (const fn of [...Object.values(ordinary), ...Object.values(tailnet)]) fn.mockReset();
  tailnetClient = null;
});

describe("value reads", () => {
  it("a protected environment, not connected: metadata from the dashboard's origin, never its values", async () => {
    ordinary.effectiveConfiguration.mockResolvedValue(config([{ name: "PORT", value: null, sensitive: false }]));
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", PROD);
    expect(ordinary.effectiveConfiguration).toHaveBeenCalledExactlyOnceWith("acme", "api", "production");
    expect(values.tailnetOnly).toBe(true);
    expect(tailnetAccess(PROD, values)).toMatchObject({ isProtected: true, readable: false, blocked: true });
  });

  it("a protected environment, connected: values through the endpoint only, as the device", async () => {
    tailnet.effectiveConfiguration.mockResolvedValue(config([{ name: "PORT", value: "8080", sensitive: false }]));
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", PROD, reader());
    expect(tailnet.effectiveConfiguration).toHaveBeenCalledExactlyOnceWith("acme", "api", "production", { includeValues: true });
    expect(ordinary.effectiveConfiguration).not.toHaveBeenCalled();
    expect(values.byName.get("PORT")?.value).toBe("8080");
    expect(tailnetAccess(PROD, values)).toMatchObject({ isProtected: true, readable: true, blocked: false, device: DEVICE });
  });

  it("connected, but the device does not meet the requirement: metadata only, and it says so", async () => {
    tailnet.effectiveConfiguration.mockRejectedValue(denial("TAILNET_CONTEXT_UNAVAILABLE"));
    ordinary.effectiveConfiguration.mockResolvedValue(config([{ name: "PORT", value: null, sensitive: false }]));
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", PROD, reader());
    expect(ordinary.effectiveConfiguration).toHaveBeenCalledExactlyOnceWith("acme", "api", "production");
    expect(tailnetAccess(PROD, values)).toMatchObject({ blocked: true, deviceRefused: true });
  });

  it("connected, but the endpoint stops answering: metadata only, no value read on the dashboard's origin", async () => {
    tailnet.effectiveConfiguration.mockRejectedValue(new TailnetUnreachableError());
    ordinary.effectiveConfiguration.mockResolvedValue(config([]));
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", PROD, reader());
    expect(ordinary.effectiveConfiguration).toHaveBeenCalledExactlyOnceWith("acme", "api", "production");
    expect(values.tailnetOnly).toBe(true);
  });

  it("an unprotected environment stays on the dashboard's origin, connected or not", async () => {
    ordinary.effectiveConfiguration.mockResolvedValue(config([{ name: "PORT", value: "3000", sensitive: false }]));
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", DEV, reader());
    expect(ordinary.effectiveConfiguration).toHaveBeenCalledExactlyOnceWith("acme", "api", "development", { includeValues: true });
    expect(tailnet.effectiveConfiguration).not.toHaveBeenCalled();
    expect(tailnetAccess(DEV, values)).toMatchObject({ isProtected: false, blocked: false });
  });

  it("a requirement the page did not know about: marked at once, then read through the endpoint", async () => {
    ordinary.effectiveConfiguration.mockRejectedValueOnce(denial("TAILNET_CONTEXT_REQUIRED"));
    tailnet.effectiveConfiguration.mockResolvedValue(config([{ name: "PORT", value: "3000", sensitive: false }]));
    const marked: string[] = [];
    const values = await loadEnvValues(ordinary as unknown as VarlatchClient, "acme", "api", DEV, reader(), (e) => marked.push(e));
    expect(marked).toEqual(["development"]);
    expect(ordinary.effectiveConfiguration).toHaveBeenCalledTimes(1);
    expect(values.viaTailnet).toEqual(DEVICE);
  });
});

describe("disclosures", () => {
  let hook: DisclosureApi;
  let root: ReactTestRenderer | undefined;
  const marked: string[] = [];
  function Probe({ restricted, protectedEnvs }: { restricted: ReadonlySet<string>; protectedEnvs: ReadonlySet<string> }) {
    hook = useDisclosure("acme", "api", restricted, { protectedEnvs, onTailnetOnly: (e) => marked.push(e) });
    return null;
  }
  const render = async (restricted: string[], protectedEnvs: string[]) =>
    act(async () => {
      const el = <Probe restricted={new Set(restricted)} protectedEnvs={new Set(protectedEnvs)} />;
      if (root) root.update(el);
      else root = create(el);
    });
  const disclosed = { items: [{ name: "DATABASE_URL", value: "postgres://prod" }], withheld: [] };
  afterEach(async () => {
    if (root) await act(async () => root!.unmount());
    root = undefined;
    marked.length = 0;
  });

  it("a protected environment discloses through the endpoint, never the dashboard's origin", async () => {
    tailnetClient = tailnet;
    tailnet.discloseSecrets.mockResolvedValue(disclosed);
    await render([], ["production"]);
    await act(async () => void (await hook.reveal("production", ["DATABASE_URL"])));
    expect(tailnet.discloseSecrets).toHaveBeenCalledOnce();
    expect(ordinary.discloseSecrets).not.toHaveBeenCalled();
    expect(hook.shown("production", "DATABASE_URL")?.value).toBe("postgres://prod");
  });

  it("protected but not connected, or held back: nothing is sent anywhere", async () => {
    await render([], ["production"]);
    await act(async () => void (await expect(hook.reveal("production", "all")).rejects.toBeInstanceOf(TailnetOnlyError)));
    tailnetClient = tailnet;
    await render(["production"], ["production"]);
    await act(async () => void (await expect(hook.reveal("production", "all")).rejects.toBeInstanceOf(TailnetOnlyError)));
    expect(tailnet.discloseSecrets).not.toHaveBeenCalled();
    expect(ordinary.discloseSecrets).not.toHaveBeenCalled();
  });

  it("a failed disclosure through the endpoint is not sent again, on any path", async () => {
    tailnetClient = tailnet;
    tailnet.discloseSecrets.mockRejectedValue(new TailnetUnreachableError());
    await render([], ["production"]);
    await act(async () => void (await expect(hook.reveal("production", "all")).rejects.toBeInstanceOf(TailnetUnreachableError)));
    expect(tailnet.discloseSecrets).toHaveBeenCalledOnce();
    expect(ordinary.discloseSecrets).not.toHaveBeenCalled();
  });

  it("a denial on the dashboard's origin marks the environment, so the next disclosure takes the protected path", async () => {
    ordinary.discloseSecrets.mockRejectedValue(denial("TAILNET_CONTEXT_REQUIRED"));
    await render([], []);
    await act(async () => void (await expect(hook.reveal("development", "all")).rejects.toMatchObject({ code: "TAILNET_CONTEXT_REQUIRED" })));
    expect(marked).toEqual(["development"]);
  });
});
