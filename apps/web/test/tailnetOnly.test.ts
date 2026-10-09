// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import type { EffectiveConfiguration, Environment } from "@varlatch/protocol";
import type { VarlatchClient } from "@varlatch/sdk";
vi.mock("../src/lib/session", () => ({ useSession: () => ({}) }));
import { loadEnvValues } from "../src/features/values/queries";
import { isTailnetDenial, isTailnetOnly } from "../src/lib/tailnet";

const env = (tailnetRequired?: boolean): Environment =>
  ({ id: "env_1", projectId: "prj_1", name: "production", kind: "shared", tier: "production", createdAt: "2026-10-01T00:00:00Z", ...(tailnetRequired === undefined ? {} : { tailnetRequired }) }) as Environment;
const metadata: EffectiveConfiguration = {
  environmentId: "env_1",
  items: [
    { name: "API_URL", sensitive: false, source: "self", versionId: "v1" },
    { name: "API_KEY", sensitive: true, source: "self", versionId: "v2" },
  ],
} as EffectiveConfiguration;
const denial = Object.assign(new Error("This operation requires trusted Tailnet Context"), { code: "TAILNET_CONTEXT_REQUIRED" });

function client(withValues: () => Promise<EffectiveConfiguration>) {
  const effectiveConfiguration = vi.fn(async (_org: string, _project: string, _env: string, opts?: { includeValues?: boolean }) =>
    opts?.includeValues ? withValues() : metadata,
  );
  return { api: { effectiveConfiguration } as unknown as VarlatchClient, effectiveConfiguration };
}

describe("values of a tailnet-only environment", () => {
  it("never asks for values: that would fail and record a denial on every load", async () => {
    const { api, effectiveConfiguration } = client(async () => {
      throw new Error("values must not be requested");
    });
    const values = await loadEnvValues(api, "acme", "api", env(true));
    expect(effectiveConfiguration).toHaveBeenCalledTimes(1);
    expect(effectiveConfiguration.mock.calls[0]![3]).toBeUndefined();
    expect(values.tailnetOnly).toBe(true);
    expect([...values.withheld]).toEqual(["API_URL"]);
    expect(values.byName.has("API_KEY")).toBe(true);
  });

  it("reads values as before where no Requirement applies, and on older servers", async () => {
    for (const e of [env(false), env()]) {
      const { api } = client(async () => ({ ...metadata, items: metadata.items!.map((i) => (i.sensitive ? i : { ...i, value: "https://api" })) }));
      const values = await loadEnvValues(api, "acme", "api", e);
      expect(values.tailnetOnly).toBe(false);
      expect(values.withheld.size).toBe(0);
    }
  });

  it("falls back to names and states when a Requirement appeared after the page loaded", async () => {
    const { api, effectiveConfiguration } = client(async () => {
      throw denial;
    });
    const values = await loadEnvValues(api, "acme", "api", env(false));
    expect(effectiveConfiguration).toHaveBeenCalledTimes(2);
    expect(values.tailnetOnly).toBe(true);
    expect([...values.withheld]).toEqual(["API_URL"]);
  });

  it("keeps other errors errors", async () => {
    const { api } = client(async () => {
      throw Object.assign(new Error("nope"), { code: "PERMISSION_DENIED" });
    });
    await expect(loadEnvValues(api, "acme", "api", env(false))).rejects.toThrow("nope");
  });
});

describe("tailnet helpers", () => {
  it("trusts only the server's flag, and recognizes both tailnet denials", () => {
    expect(isTailnetOnly(env(true))).toBe(true);
    expect(isTailnetOnly(env(false))).toBe(false);
    expect(isTailnetOnly(env())).toBe(false);
    expect(isTailnetOnly(undefined)).toBe(false);
    expect(isTailnetDenial(denial)).toBe(true);
    expect(isTailnetDenial({ code: "TAILNET_CONTEXT_UNAVAILABLE" })).toBe(true);
    expect(isTailnetDenial({ code: "PERMISSION_DENIED" })).toBe(false);
    expect(isTailnetDenial(new Error("x"))).toBe(false);
  });
});
