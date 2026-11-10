// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * A machine's reach in Access, Machines (ADR-0054 Decision 8): actions per
 * project and environment, a Requirement as a condition label (never a
 * denial), the identity's state, and a refusal said in words.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));

import { VarlatchApiError, type OrgIdentity } from "@varlatch/sdk";
import { MachineReachPanel } from "../src/features/access/MachineReach";

const IDENTITY = { id: "idn_svc", name: "deployer", kind: "service", disabled: false } as OrgIdentity;
const grant = (grantId: string) => [{ grantId, viaGroupId: null, roleId: null }];
const REACH = {
  identity: { id: "idn_svc", name: "deployer", kind: "service", state: "live", disabledReason: null, liveCredentials: 2 },
  organizationActions: [{ action: "audit.read", grants: grant("grt_3"), conditions: [] }],
  projects: [
    {
      id: "prj_1",
      slug: "api",
      name: "API",
      actions: [],
      environments: [
        {
          id: "env_prod",
          name: "production",
          tier: "production",
          kind: "shared",
          parentEnvironmentId: null,
          actions: [
            { action: "config.metadata.read", grants: grant("grt_1"), conditions: [] },
            { action: "secret.use", grants: grant("grt_1"), conditions: ["req_1"] },
          ],
        },
      ],
    },
  ],
  requirements: [
    { id: "req_1", version: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] }, condition: "needs tailnet example.ts.net: tag:prod" },
  ],
  notes: [],
};

let root: ReactTestRenderer;
async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MachineReachPanel org="acme" identity={IDENTITY} />
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const byProp = (prop: string, value?: string) =>
  root.root.findAll((n) => typeof n.type === "string" && n.props[prop] !== undefined && (value === undefined || n.props[prop] === value));

beforeEach(() => {
  fake.api = { machineReach: vi.fn(async () => REACH) };
});

describe("machine reach panel", () => {
  it("shows actions per environment and a Requirement as a condition label, not a denial", async () => {
    await mount();
    expect(fake.api.machineReach).toHaveBeenCalledWith("acme", "idn_svc");
    const prod = byProp("data-reach-environment", "production")[0]!;
    expect(prod.findAll((n) => n.props["data-reach-action"] !== undefined && typeof n.type === "string").map((n) => n.props["data-reach-action"])).toEqual([
      "config.metadata.read",
      "secret.use",
    ]);
    expect(text(byProp("data-reach-condition", "req_1")[0]!)).toBe("needs tailnet example.ts.net: tag:prod");
    expect(text(byProp("data-testid", "reach-organization")[0]!)).toContain("audit.read");
    expect(text(byProp("data-testid", "reach-state")[0]!)).toContain("live");
    expect(text(byProp("data-testid", "reach-state")[0]!)).toContain("2 live credentials");
    expect(text(root.root)).not.toMatch(/denied/i);
  });

  it("says when the machine is retired, and shows the server's notes", async () => {
    fake.api.machineReach = vi.fn(async () => ({
      ...REACH,
      identity: { ...REACH.identity, state: "retired", liveCredentials: 0 },
      organizationActions: [],
      projects: [],
      requirements: [],
      notes: ["This identity is retired."],
    }));
    await mount();
    expect(text(byProp("data-testid", "reach-state")[0]!)).toContain("retired");
    expect(byProp("data-testid", "reach-empty")).toHaveLength(1);
    expect(text(byProp("data-testid", "reach-note")[0]!)).toBe("This identity is retired.");
  });

  it("says what permission is missing when the caller may not see it", async () => {
    fake.api.machineReach = vi.fn(async () => {
      throw new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "Not authorized for this action", requestId: "req_1" });
    });
    await mount();
    expect(text(byProp("data-testid", "reach-error")[0]!)).toContain("needs permission to read identities and policy");
  });
});
