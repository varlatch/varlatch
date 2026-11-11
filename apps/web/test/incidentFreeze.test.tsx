// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentFreeze } from "@varlatch/sdk";

/**
 * The incident freeze in the dashboard (ADR-0055 Decision 11): freezing
 * from the Security page after the slug is typed, with a reason; the open
 * freeze with who, when and why and "Lift freeze", which lists the Sync
 * Targets that resume; and the banner on every page, alone on pages that
 * cannot work while frozen.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, (...args: never[]) => unknown>,
  confirm: vi.fn(),
  toasts: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, identityId: "idn_ada" }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("../src/components/Dialog", () => ({ useConfirm: () => fake.confirm }));

import { FREEZE_CONSEQUENCES, FreezeGate, IncidentFreezeCard, pageWorksWhileFrozen } from "../src/features/security-controls/IncidentFreeze";

const FREEZE: IncidentFreeze = {
  id: "ofz_1",
  frozenAt: "2026-11-11T10:00:00.000Z",
  frozenBy: { id: "idn_ada", name: "Ada" },
  reason: "A CI token leaked",
  liftedAt: null,
  liftedBy: null,
  liftMethod: null,
};
const TARGET = { id: "snt_1", projectSlug: "api", environmentName: "production", platform: "coolify", destination: "app1" };

let root: ReactTestRenderer;
async function mount(element: React.ReactElement, path = "/o/acme/security") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}>{element}</MemoryRouter>
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 3; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

let open: IncidentFreeze | null;
beforeEach(() => {
  open = null;
  fake.toasts = [];
  fake.confirm.mockReset();
  fake.api = {
    meta: async () => ({ apiMajor: 1, capabilities: ["organizations.incident-freeze"] }),
    incidentFreeze: async () => ({ freeze: open, resumingTargets: open ? [TARGET] : [], history: [] }),
    freezeOrganization: vi.fn(async () => FREEZE),
    liftIncidentFreeze: vi.fn(async () => ({ freeze: { ...FREEZE, liftedAt: "2026-11-11T11:00:00.000Z" }, resumingTargets: [TARGET] })),
  };
});

describe("the Security page's section", () => {
  it("freezes after the slug is typed, with the reason, saying what stops", async () => {
    await mount(<IncidentFreezeCard org="acme" admin />);
    expect(all("freeze-org")[0]!.props.disabled).toBe(true);
    act(() => all("freeze-reason")[0]!.props.onChange({ target: { value: "  A CI token leaked " } }));
    fake.confirm.mockResolvedValue(true);
    await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault: () => {} }));
    await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
    const asked = fake.confirm.mock.calls[0]![0] as { typeToConfirm: string; consequences: { text: string }[] };
    expect(asked.typeToConfirm).toBe("acme");
    expect(asked.consequences.map((c) => c.text)).toEqual(FREEZE_CONSEQUENCES);
    expect(asked.consequences.map((c) => c.text).join("\n")).toContain("break-glass credential outside Varlatch");
    expect(fake.api.freezeOrganization).toHaveBeenCalledWith("acme", "A CI token leaked");
    expect(fake.toasts).toEqual(["Organization frozen"]);
  });

  it("offers nothing to a member", async () => {
    await mount(<IncidentFreezeCard org="acme" admin={false} />);
    expect(all("freeze-org")).toEqual([]);
    expect(text(all("incident-freeze")[0]!)).toContain("Only an admin of this organization can freeze it.");
  });

  it("shows who froze it, when and why; lifting lists the Targets that resume", async () => {
    open = FREEZE;
    await mount(<IncidentFreezeCard org="acme" admin />);
    const shown = text(all("incident-freeze-open")[0]!);
    expect(shown).toContain("Frozen by Ada");
    expect(shown).toContain("Reason: A CI token leaked");
    expect(shown).toContain("1 Sync Targets resume pushing when it is lifted.");
    fake.confirm.mockResolvedValue(true);
    await act(async () => all("lift-freeze")[0]!.props.onClick());
    await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
    const asked = fake.confirm.mock.calls[0]![0] as { consequences: { text: string }[] };
    expect(asked.consequences.map((c) => c.text)).toEqual(["Sync Target api/production (coolify, app1) resumes pushing."]);
    expect(fake.api.liftIncidentFreeze).toHaveBeenCalledWith("acme", "ofz_1");
    expect(fake.toasts).toEqual(["Freeze lifted"]);
  });
});

describe("the banner", () => {
  const Page = () => <p data-testid="page">page</p>;

  it("is absent when not frozen", async () => {
    await mount(<FreezeGate org="acme"><Page /></FreezeGate>, "/o/acme/projects");
    expect(all("incident-freeze-banner")).toEqual([]);
    expect(all("page")).toHaveLength(1);
  });

  it("shows above pages that work while frozen, and alone on the others", async () => {
    open = FREEZE;
    await mount(<FreezeGate org="acme"><Page /></FreezeGate>, "/o/acme/access");
    expect(text(all("incident-freeze-banner")[0]!)).toContain("This organization is frozen for an incident");
    expect(all("page")).toHaveLength(1);
    await mount(<FreezeGate org="acme"><Page /></FreezeGate>, "/o/acme/p/api/e/production");
    expect(text(all("incident-freeze-banner")[0]!)).toContain("This page is not available while the organization is frozen.");
    expect(all("page")).toEqual([]);
  });

  it("knows which pages work while frozen", () => {
    for (const p of ["/o/acme/security", "/o/acme/access", "/o/acme/audit", "/o/acme/settings"]) expect(pageWorksWhileFrozen(p, "acme"), p).toBe(true);
    for (const p of ["/o/acme/projects", "/o/acme/p/api", "/o/acme/connections", "/o/acme"]) expect(pageWorksWhileFrozen(p, "acme"), p).toBe(false);
  });
});
