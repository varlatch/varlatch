// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EffectiveConfiguration, Environment } from "@varlatch/protocol";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
const effectiveConfiguration = vi.fn();
const discloseSecrets = vi.fn();
const api = { effectiveConfiguration, discloseSecrets };
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api }) }));
import { useExport } from "../src/features/values/useExport";

/**
 * The export dialog's data follows the environment as it is now: when it
 * turns tailnet-only, loaded values go, and a load or an export in flight
 * is discarded instead of written to a file.
 */

const env = (tailnetRequired: boolean): Environment =>
  ({ id: "env_prod", projectId: "prj_api", name: "production", kind: "shared", tier: "production", createdAt: "2026-10-01T00:00:00Z", tailnetRequired }) as Environment;
const values: EffectiveConfiguration = {
  environmentId: "env_prod",
  items: [
    { name: "API_URL", sensitive: false, source: "self", versionId: "v1", value: "https://api" },
    { name: "API_KEY", sensitive: true, source: "self", versionId: "v2", value: null },
  ],
} as EffectiveConfiguration;

let hook: ReturnType<typeof useExport>;
let root: ReactTestRenderer | undefined;
function Probe({ e }: { e: Environment | null }) {
  hook = useExport("acme", "api", e);
  return null;
}
async function render(e: Environment | null) {
  await act(async () => {
    if (root) root.update(<Probe e={e} />);
    else root = create(<Probe e={e} />);
  });
}
const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
};

beforeEach(() => {
  effectiveConfiguration.mockReset();
  discloseSecrets.mockReset();
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
});

describe("export of an environment that turns tailnet-only", () => {
  it("drops the values it loaded and refuses to build a file", async () => {
    effectiveConfiguration.mockResolvedValue(values);
    await render(env(false));
    expect(hook.plain.map((i) => i.name)).toEqual(["API_URL"]);
    await render(env(true));
    expect(hook.tailnetOnly).toBe(true);
    expect(hook.items).toBeNull();
    expect(hook.plain).toEqual([]);
    await expect(hook.build()).rejects.toMatchObject({ code: "TAILNET_ONLY" });
    // No values request for a tailnet-only environment.
    expect(effectiveConfiguration).toHaveBeenCalledTimes(1);
  });

  it("discards a values load still in flight", async () => {
    const load = deferred<EffectiveConfiguration>();
    effectiveConfiguration.mockReturnValueOnce(load.promise);
    await render(env(false));
    await render(env(true));
    await act(async () => load.resolve(values));
    expect(hook.items).toBeNull();
  });

  it("writes no file from an export still in flight", async () => {
    effectiveConfiguration.mockResolvedValue(values);
    const disclosure = deferred<{ items: { name: string; value: string }[]; withheld: string[] }>();
    discloseSecrets.mockReturnValueOnce(disclosure.promise);
    await render(env(false));
    await act(async () => hook.setIncludeSecrets(true));
    let pending!: Promise<unknown>;
    await act(async () => {
      pending = hook.build();
    });
    await render(env(true));
    const refused = expect(pending).rejects.toMatchObject({ code: "TAILNET_ONLY" });
    await act(async () => disclosure.resolve({ items: [{ name: "API_KEY", value: "sk_live" }], withheld: [] }));
    await refused;
  });

  it("builds the file as before for an unprotected environment, and keeps it across a refetched object", async () => {
    effectiveConfiguration.mockResolvedValue(values);
    await render(env(false));
    await render(env(false)); // a new object, same environment and protection: no reload
    expect(effectiveConfiguration).toHaveBeenCalledTimes(1);
    const file = await hook.build();
    expect(file.filename).toBe("api.production.env");
    expect(file.text).toContain("API_URL=https://api");
    expect(file.text).toContain("# API_KEY: secret, not exported");
  });
});
