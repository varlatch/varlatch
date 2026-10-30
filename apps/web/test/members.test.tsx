// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Grant, MemberReview } from "@varlatch/protocol";

/**
 * Removing a person, leaving, and demotion in the dashboard (ADR-0052), and
 * what the dashboard drops when the signed-in person loses an organization
 * (Decision 9).
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, (...args: never[]) => unknown>,
  navigate: vi.fn(),
  toasts: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/lib/realtime", () => ({ useMeSignal: () => {} }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("react-router-dom", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react-router-dom")>()),
  useNavigate: () => fake.navigate,
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, description, children, footer, "data-testid": id }: Record<string, React.ReactNode> & { open: boolean; "data-testid"?: string }) =>
    open ? (
      <div data-testid={id}>
        <h2>{title}</h2>
        <p>{description}</p>
        {children}
        {footer}
      </div>
    ) : null,
}));

import { dropLostOrganizations, lostOrganizations, mentionsOrganization } from "../src/lib/membership";
import { DemoteDialog, RemoveMemberDialog, reviewCount } from "../src/features/access/MemberDialogs";
import type { Names } from "../src/features/access/model";

const names: Names = {
  project: (id) => (id === "prj_1" ? ({ id, slug: "api" } as never) : undefined),
  environment: (id) => (id === "env_1" ? ({ id, name: "production" } as never) : undefined),
  team: () => undefined,
};

const EMPTY: MemberReview = { syncTargets: [], connections: [], webhooks: [], oidcBindings: [], credentials: [], personalEnvironments: [] };
const REVIEW: MemberReview = {
  ...EMPTY,
  syncTargets: [{ id: "snt_1", projectId: "prj_1", environmentId: "env_1", platform: "coolify", state: "active", changes: ["created"] }],
  webhooks: [{ id: "whk_1", host: "sink.example", revoked: true }],
  credentials: [{ id: "crd_1", name: "deploy", identityId: "idn_svc", identityName: "deployer", state: "valid" }],
};

let root: ReactTestRenderer;
let client: QueryClient;
async function mount(element: React.ReactElement) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>{element}</MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
/** Lets queries resolve and the dialog render their results. */
async function settle() {
  for (let i = 0; i < 3; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const byTestId = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

beforeEach(() => {
  fake.api = {};
  fake.navigate.mockReset();
  fake.toasts = [];
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

describe("losing an organization", () => {
  const acme = { id: "org_a", slug: "acme", name: "Acme" };
  const other = { id: "org_o", slug: "other", name: "Other" };

  it("finds the organizations no longer listed, and the queries that name them", () => {
    expect(lostOrganizations([acme, other], [other])).toEqual([acme]);
    expect(mentionsOrganization(["grants", "acme"], acme)).toBe(true);
    expect(mentionsOrganization(["environments", "acme", "api"], acme)).toBe(true);
    expect(mentionsOrganization(["mirror", { organizationId: "org_a" }], acme)).toBe(true);
    expect(mentionsOrganization(["grants", "acme-two"], acme)).toBe(false);
    expect(mentionsOrganization(["orgs"], acme)).toBe(false);
  });

  it("cancels and drops every query of a lost organization, and keeps the others", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["orgs"], { items: [acme, other] });
    qc.setQueryData(["grants", "acme"], { items: [] });
    qc.setQueryData(["values", "acme", "api", "production"], { items: ["plain value"] });
    qc.setQueryData(["grants", "other"], { items: [] });
    const lost = await dropLostOrganizations(qc, async () => ({ items: [other] }));
    expect(lost).toEqual([acme]);
    expect(qc.getQueryData(["grants", "acme"])).toBeUndefined();
    expect(qc.getQueryData(["values", "acme", "api", "production"])).toBeUndefined();
    expect(qc.getQueryData(["grants", "other"])).toEqual({ items: [] });
    expect(qc.getQueryData(["orgs"])).toEqual({ items: [other] });
  });

  it("counts the page's own organization as lost when the list no longer has it, even unseen before", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["grants", "acme"], { items: [] });
    const lost = await dropLostOrganizations(qc, async () => ({ items: [other] }), "acme");
    expect(lost.map((o) => o.slug)).toEqual(["acme"]);
    expect(qc.getQueryData(["grants", "acme"])).toBeUndefined();
  });
});

describe("the remove dialog", () => {
  it("lists what the person set up, with states, before removing them", async () => {
    const removeMember = vi.fn(async () => ({ review: REVIEW }));
    fake.api = { reviewMember: vi.fn(async () => REVIEW), removeMember };
    await mount(<RemoveMemberDialog org="acme" orgName="Acme" person={{ id: "idn_bob", name: "Bob" }} self={false} names={names} onClose={() => {}} />);
    const dialog = byTestId("remove-member-dialog");
    expect(text(dialog)).toContain("Remove Bob from Acme?");
    expect(text(dialog)).toContain("3 things to review");
    const items = root.root.findAll((n) => typeof n.type === "string" && n.props["data-review-item"] !== undefined).map(text);
    expect(items).toEqual(["coolify for api / productioncreatedactive", "sink.examplerevoked", "deploy for deployervalid"]);
    expect(fake.api.reviewMember).toHaveBeenCalledWith("acme", "idn_bob");
    await act(async () => byTestId("confirm-remove-member").props.onClick());
    await settle();
    expect(removeMember).toHaveBeenCalledWith("acme", "idn_bob");
    expect(fake.toasts).toEqual(["Removed Bob from Acme"]);
    expect(fake.navigate).not.toHaveBeenCalled();
  });

  it("says when nothing needs review, and shows the server's refusal", async () => {
    fake.api = {
      reviewMember: vi.fn(async () => EMPTY),
      removeMember: vi.fn(async () => {
        throw new Error("This is the Organization's last admin. Make another member an admin first.");
      }),
    };
    await mount(<RemoveMemberDialog org="acme" orgName="Acme" person={{ id: "idn_me", name: "Me" }} self names={names} onClose={() => {}} />);
    expect(text(byTestId("remove-member-dialog"))).toContain("Leave Acme?");
    expect(text(byTestId("member-review-empty"))).toBe("Nothing you set up here needs review.");
    expect(fake.api.reviewMember).toHaveBeenCalledWith("acme", "me");
    await act(async () => byTestId("confirm-remove-member").props.onClick());
    await settle();
    expect(text(byTestId("remove-member-error"))).toContain("last admin");
    expect(fake.navigate).not.toHaveBeenCalled();
  });

  it("leaving drops the organization's data and leaves its pages", async () => {
    fake.api = {
      reviewMember: vi.fn(async () => EMPTY),
      removeMember: vi.fn(async () => ({ review: EMPTY })),
      listOrganizations: vi.fn(async () => ({ items: [] })),
    };
    await mount(<RemoveMemberDialog org="acme" orgName="Acme" person={{ id: "idn_me", name: "Me" }} self names={names} onClose={() => {}} />);
    client.setQueryData(["grants", "acme"], { items: [] });
    await act(async () => byTestId("confirm-remove-member").props.onClick());
    await settle();
    expect(fake.api.removeMember).toHaveBeenCalledWith("acme", "me");
    expect(client.getQueryData(["grants", "acme"])).toBeUndefined();
    expect(fake.navigate).toHaveBeenCalledWith("/", { replace: true });
    expect(fake.toasts).toEqual(["You left Acme"]);
    expect(reviewCount(REVIEW)).toBe(3);
  });
});

describe("the demote dialog", () => {
  const grant = (id: string, subject: { subjectIdentityId?: string; subjectGroupId?: string }): Grant =>
    ({ id, organizationId: "org_a", scope: { kind: "organization" }, actions: ["audit.read"], roleId: null, createdAt: "", subjectIdentityId: null, subjectGroupId: null, ...subject }) as Grant;

  it("lists the Grants that stay: direct ones, and those of groups the person is in", async () => {
    const changeMemberRole = vi.fn(async () => ({ identityId: "idn_bob", role: "member", previousRole: "admin" }));
    fake.api = {
      listGroupMembers: vi.fn(async (_org: string, group: string) => ({ items: group === "grp_in" ? [{ identityId: "idn_bob" }] : [] })),
      changeMemberRole,
    };
    const grants = [
      grant("grt_direct", { subjectIdentityId: "idn_bob" }),
      grant("grt_other", { subjectIdentityId: "idn_eve" }),
      grant("grt_in", { subjectGroupId: "grp_in" }),
      grant("grt_out", { subjectGroupId: "grp_out" }),
    ];
    await mount(
      <DemoteDialog
        org="acme"
        person={{ id: "idn_bob", name: "Bob" }}
        self={false}
        grants={grants}
        names={names}
        nameOf={(id) => (id === "grp_in" ? "ops" : String(id))}
        roleName={() => null}
        onClose={() => {}}
      />,
    );
    const staying = root.root.findAll((n) => typeof n.type === "string" && n.props["data-grant"] !== undefined).map((n) => n.props["data-grant"]);
    expect(staying).toEqual(["grt_direct", "grt_in"]);
    expect(text(byTestId("demote-staying"))).toContain("through ops");
    await act(async () => byTestId("confirm-demote").props.onClick());
    await settle();
    expect(changeMemberRole).toHaveBeenCalledWith("acme", "idn_bob", "member");
    expect(fake.toasts).toEqual(["Bob is now a member"]);
  });

  it("says when only the member defaults remain", async () => {
    fake.api = { listGroupMembers: vi.fn(async () => ({ items: [] })) };
    await mount(
      <DemoteDialog org="acme" person={{ id: "idn_me", name: "Me" }} self grants={[]} names={names} nameOf={String} roleName={() => null} onClose={() => {}} />,
    );
    expect(text(byTestId("demote-no-grants"))).toBe("No other Grants: after this, you have the member defaults only.");
  });
});
