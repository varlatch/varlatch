// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { OrganizationDeletion } from "@varlatch/protocol";

/**
 * Deleting projects and organizations in the dashboard (ADR-0051 Decision
 * 11): the name typed to confirm, the request with its approval state, who
 * may approve or cancel, and the banner of a frozen organization.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, (...args: never[]) => unknown>,
  me: "idn_ada",
  confirm: vi.fn(),
  toasts: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, identityId: fake.me }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("../src/components/Dialog", () => ({ useConfirm: () => fake.confirm }));

import { DeletionBanner, OrganizationDeletionCard, deletionState } from "../src/features/settings/OrganizationDeletion";
import { useDeleteProject } from "../src/features/projects/deleteProject";

const OPEN: OrganizationDeletion = {
  id: "odl_1",
  requestedBy: "idn_ada",
  scheduledAt: "2026-10-30T12:00:00.000Z",
  runAfter: "2026-11-06T12:00:00.000Z",
  approvalRequired: true,
  approvedBy: null,
  approvedAt: null,
  cancelledAt: null,
  completedAt: null,
};
const PEOPLE = [
  { id: "idn_ada", name: "Ada", kind: "human", orgRole: "admin", removedAt: null },
  { id: "idn_bob", name: "Bob", kind: "human", orgRole: "admin", removedAt: null },
  { id: "idn_eve", name: "Eve", kind: "human", orgRole: "member", removedAt: null },
];

let root: ReactTestRenderer;
async function mount(element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>{element}</MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
async function settle() {
  for (let i = 0; i < 3; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

let open: OrganizationDeletion | null;
beforeEach(() => {
  open = null;
  fake.me = "idn_ada";
  fake.toasts = [];
  fake.confirm.mockReset();
  fake.api = {
    meta: async () => ({ apiMajor: 1, capabilities: ["organizations.delete", "projects.delete"] }),
    listIdentities: async () => ({ items: PEOPLE, nextCursor: null }),
    organizationDeletion: async () => open,
    scheduleOrganizationDeletion: vi.fn(async () => OPEN),
    approveOrganizationDeletion: vi.fn(async () => ({ ...OPEN, approvedBy: "idn_bob" })),
    cancelOrganizationDeletion: vi.fn(async () => ({ ...OPEN, cancelledAt: "2026-10-31T00:00:00.000Z" })),
    deleteProject: vi.fn(async () => ({ projectId: "prj_1", slug: "api", environments: 2, values: 3, versionsErased: 5, capabilitiesRevoked: 0, targetsRevoked: 1, teamLinksRemoved: 0 })),
  };
});

describe("the request's state", () => {
  it("says when an overdue request waits for approval, and never runs without it", () => {
    const name = (id: string) => id;
    expect(deletionState(OPEN, name, Date.parse("2026-11-01T00:00:00.000Z")).approval).toBe("It waits for another admin's approval.");
    expect(deletionState(OPEN, name, Date.parse("2026-11-07T00:00:00.000Z")).approval).toBe("It waits for another admin's approval and never runs without it.");
    expect(deletionState({ ...OPEN, approvedBy: "idn_bob" }, (id) => (id === "idn_bob" ? "Bob" : id), 0).approval).toBe("Approved by Bob.");
    expect(deletionState({ ...OPEN, approvalRequired: false }, name, 0).approval).toBeNull();
  });
});

describe("the Settings danger zone", () => {
  it("schedules after the slug is typed, with the waiting period and the approval it will need", async () => {
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    act(() => all("org-deletion-days")[0]!.props.onChange({ target: { value: "3" } }));
    fake.confirm.mockResolvedValue(true);
    await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault: () => {} }));
    await settle();
    const asked = fake.confirm.mock.calls[0]![0] as { typeToConfirm: string; consequences: { text: string }[] };
    expect(asked.typeToConfirm).toBe("acme");
    expect(asked.consequences.map((c) => c.text).join("\n")).toContain("and another admin's approval");
    expect(fake.api.scheduleOrganizationDeletion).toHaveBeenCalledWith("acme", { afterDays: 3 });
    expect(fake.toasts).toEqual(["Deletion scheduled"]);
  });

  it("refuses an out-of-range waiting period, and offers nothing to a member", async () => {
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    act(() => all("org-deletion-days")[0]!.props.onChange({ target: { value: "31" } }));
    expect(all("delete-org")[0]!.props.disabled).toBe(true);
    fake.me = "idn_eve";
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    expect(all("delete-org")).toEqual([]);
    expect(text(root.root.findByProps({ "data-testid": "settings-danger" }))).toContain("Only an admin of this organization can delete it.");
  });

  it("shows the open request; another admin approves by typing the slug, any admin cancels", async () => {
    open = OPEN;
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    const request = text(all("org-deletion-request")[0]!);
    expect(request).toContain("Scheduled by you");
    expect(request).toContain("It waits for another admin's approval");
    // The requester cannot approve their own request.
    expect(all("approve-org-deletion")).toEqual([]);
    fake.confirm.mockResolvedValue(true);
    await act(async () => all("cancel-org-deletion")[0]!.props.onClick());
    await settle();
    expect(fake.api.cancelOrganizationDeletion).toHaveBeenCalledWith("acme", "odl_1");

    fake.me = "idn_bob";
    fake.confirm.mockReset().mockResolvedValue(true);
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    expect(text(all("org-deletion-request")[0]!)).toContain("Scheduled by Ada");
    await act(async () => all("approve-org-deletion")[0]!.props.onClick());
    await settle();
    expect((fake.confirm.mock.calls[0]![0] as { typeToConfirm: string }).typeToConfirm).toBe("acme");
    expect(fake.api.approveOrganizationDeletion).toHaveBeenCalledWith("acme", "odl_1");

    fake.me = "idn_eve";
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    expect(all("approve-org-deletion")).toEqual([]);
    expect(all("cancel-org-deletion")).toEqual([]);
  });

  it("does nothing when the confirmation is dismissed", async () => {
    open = OPEN;
    fake.me = "idn_bob";
    fake.confirm.mockResolvedValue(false);
    await mount(<OrganizationDeletionCard org="acme" slug="acme" id="org_1" />);
    await act(async () => all("approve-org-deletion")[0]!.props.onClick());
    await settle();
    expect(fake.api.approveOrganizationDeletion).not.toHaveBeenCalled();
  });
});

describe("the frozen banner", () => {
  it("appears while a deletion is open, linking to the request", async () => {
    await mount(<DeletionBanner org="acme" />);
    expect(all("org-deletion-banner")).toEqual([]);
    open = OPEN;
    await mount(<DeletionBanner org="acme" />);
    const banner = text(all("org-deletion-banner")[0]!);
    expect(banner).toContain("This organization is being deleted");
    expect(banner).toContain("changes are refused; reads still work");
    expect(all("org-deletion-review")[0]!.props.href).toBe("/o/acme/settings#settings-danger");
  });
});

describe("deleting a project", () => {
  function Probe({ onReady }: { onReady: (run: ReturnType<typeof useDeleteProject>) => void }) {
    onReady(useDeleteProject("acme"));
    return null;
  }

  it("asks for the slug, deletes, and leaves the page before dropping its caches", async () => {
    let run!: ReturnType<typeof useDeleteProject>;
    await mount(<Probe onReady={(r) => (run = r)} />);
    const left = vi.fn();
    fake.confirm.mockResolvedValue(false);
    expect(await act(async () => run({ slug: "api" }, left))).toBe(false);
    expect(fake.api.deleteProject).not.toHaveBeenCalled();
    fake.confirm.mockResolvedValue(true);
    expect(await act(async () => run({ slug: "api" }, left))).toBe(true);
    expect((fake.confirm.mock.calls[1]![0] as { typeToConfirm: string }).typeToConfirm).toBe("api");
    expect(fake.api.deleteProject).toHaveBeenCalledWith("acme", "api");
    expect(left).toHaveBeenCalledOnce();
    expect(fake.toasts).toEqual(["Project api deleted"]);
  });
});
