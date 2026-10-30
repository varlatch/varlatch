// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExposureReport } from "@varlatch/protocol";

/**
 * The exposure report as a checklist (ADR-0052 Decisions 6 and 7): states
 * per version, Rotate only while Varlatch still serves it, a confirmation
 * the operator makes, never one made on its own, and Revoke for machine
 * credentials still valid.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>>, confirms: [] as string[] }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, children, footer, "data-testid": id }: Record<string, React.ReactNode> & { open: boolean; "data-testid"?: string }) =>
    open ? (
      <div data-testid={id}>
        <h2>{title}</h2>
        {children}
        {footer}
      </div>
    ) : null,
  useConfirm: () => async (opts: { title: string }) => {
    fake.confirms.push(opts.title);
    return true;
  },
}));

import { VarlatchApiError } from "@varlatch/sdk";
import { ExposureDialog, canReadAudit, firstReceived, openItems, versionState } from "../src/features/access/ExposureDialog";
import type { Names } from "../src/features/access/model";

const names: Names = {
  project: (id) => (id === "prj_1" ? ({ id, slug: "api" } as never) : undefined),
  environment: (id) =>
    ({ env_1: { id, name: "production", projectId: "prj_1" }, env_2: { id, name: "development/bob", projectId: "prj_1" } } as Record<string, never>)[id],
  team: () => undefined,
};

const version = (over: Partial<ExposureReport["received"][number]>): ExposureReport["received"][number] => ({
  itemName: "TOKEN",
  versionId: "ver_1",
  owningEnvironmentId: "env_1",
  projectId: "prj_1",
  state: "served",
  servedAs: "current",
  retiringUntil: null,
  notServedBecause: null,
  served: true,
  confirmation: null,
  rotationHint: "Issue a new token in the provider console.",
  receipts: [{ environmentId: "env_2", way: "delivered", firstAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:00:00.000Z" }],
  ...over,
});

const REPORT: ExposureReport = {
  member: { identityId: "idn_bob", name: "Bob", role: null, removedAt: "2026-10-01T10:00:00.000Z" },
  coverage: { complete: false, from: "2026-01-01T00:00:00.000Z", to: "2026-10-30T00:00:00.000Z" },
  received: [
    version({}),
    version({ itemName: "OLD_KEY", versionId: "ver_2", state: "not-served", servedAs: null, served: false, notServedBecause: "replaced", rotationHint: null }),
    version({ itemName: "DONE_KEY", versionId: "ver_3", state: "revocation-confirmed", servedAs: null, served: false, notServedBecause: "value-deleted", confirmation: { confirmedAt: "2026-10-02T00:00:00.000Z", actorIdentityId: "idn_admin" } }),
  ],
  authorityAtRemoval: {
    removalId: "mrm_1",
    removedAt: "2026-10-01T10:00:00.000Z",
    role: "member",
    left: false,
    environments: [{ environmentId: "env_1", actions: [{ action: "secret.reveal", sources: [] }], conditionalOn: ["req_1"] }],
    requirements: [
      { requirementId: "req_1", requirementVersion: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"], users: ["ops@example.com"] } },
    ],
  },
  indirect: {
    syncTargets: [],
    connections: [],
    webhooks: [],
    oidcBindings: [],
    credentials: [
      { id: "crd_1", name: "deploy", identityId: "idn_svc", identityName: "deployer", state: "valid" },
      { id: "crd_2", name: "old", identityId: "idn_svc", identityName: "deployer", state: "expired" },
    ],
    personalEnvironments: [],
  },
};

let root: ReactTestRenderer;
async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ExposureDialog org="acme" person={{ id: "idn_bob", name: "Bob" }} names={names} onClose={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
async function settle() {
  for (let i = 0; i < 3; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (pred: (n: ReactTestInstance) => boolean) => root.root.findAll((n) => typeof n.type === "string" && pred(n));
const byTestId = (id: string) => {
  const found = all((n) => n.props["data-testid"] === id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const row = (versionId: string) => all((n) => n.props["data-version"] === versionId)[0]!;
const inRow = (versionId: string, id: string) => row(versionId).findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);

beforeEach(() => {
  fake.api = {
    memberExposure: vi.fn(async () => REPORT),
    confirmExposureRevocation: vi.fn(async () => ({ versionId: "ver_1", confirmedAt: "2026-10-30T00:00:00.000Z", actorIdentityId: "idn_admin" })),
    revokeIdentityCredential: vi.fn(async () => undefined),
  };
  fake.confirms = [];
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

describe("version states", () => {
  it("say what Varlatch serves, and never call a replaced version safe", () => {
    expect(versionState(REPORT.received[0]!)).toMatchObject({ tone: "danger", label: "still served" });
    expect(versionState(REPORT.received[1]!).detail).toContain("Not safe until it is revoked at its provider");
    expect(versionState(REPORT.received[2]!)).toMatchObject({ label: "revoked at provider" });
    expect(versionState(version({ servedAs: "retiring", retiringUntil: "2026-11-01T00:00:00.000Z" })).detail).toContain("Retiring");
    expect(openItems(REPORT).map((v) => v.versionId)).toEqual(["ver_1", "ver_2"]);
  });

  it("date a version by its earliest receipt, whatever the order of its environments", () => {
    const v = version({
      receipts: [
        { environmentId: "env_1", way: "revealed", firstAt: "2026-09-05T10:00:00.000Z", lastAt: "2026-09-06T10:00:00.000Z" },
        { environmentId: "env_2", way: "delivered", firstAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:00:00.000Z" },
      ],
    });
    expect(firstReceived(v)).toBe(new Date("2026-09-01T10:00:00.000Z").toLocaleString());
  });
});

describe("who may open reports", () => {
  it("anyone who may read the audit log, whatever their role; a refusal is no, other failures are errors", async () => {
    const allowed = { listAuditEvents: vi.fn(async () => ({ items: [], nextCursor: null })) };
    expect(await canReadAudit(allowed as never, "acme")).toBe(true);
    expect(allowed.listAuditEvents).toHaveBeenCalledWith("acme", { limit: 1 });
    const refused = (status: number, code: string) => ({
      listAuditEvents: vi.fn(async () => {
        throw new VarlatchApiError(status, { code: code as never, message: "no", requestId: "req_1" });
      }),
    });
    expect(await canReadAudit(refused(403, "PERMISSION_DENIED") as never, "acme")).toBe(false);
    expect(await canReadAudit(refused(404, "RESOURCE_NOT_FOUND") as never, "acme")).toBe(false);
    await expect(canReadAudit(refused(500, "INTERNAL") as never, "acme")).rejects.toBeInstanceOf(VarlatchApiError);
  });
});

describe("the exposure dialog", () => {
  it("lists every kind of fact apart, with Rotate only while served", async () => {
    await mount();
    expect(fake.api.memberExposure).toHaveBeenCalledWith("acme", "idn_bob");
    expect(text(byTestId("exposure-coverage"))).toContain("not covered yet");
    expect(inRow("ver_1", "rotate-link")).toHaveLength(1);
    expect(inRow("ver_1", "rotate-link")[0]!.props.href).toBe("/o/acme/p/api/e/production?item=TOKEN");
    expect(text(row("ver_1"))).toContain("delivered to a process through api / development/bob");
    expect(text(row("ver_1"))).toContain("To rotate: Issue a new token in the provider console.");
    expect(inRow("ver_2", "rotate-link")).toHaveLength(0);
    // A confirmed version has no confirm action.
    expect(inRow("ver_3", "confirm-revoked")).toHaveLength(0);
    expect(text(byTestId("authority-conditions"))).toBe(
      "reading values needed a device in example.ts.net with tags tag:prod or users ops@example.com (Requirement on the production tier, as defined at removal)",
    );
    // Each row names its version, so two versions of one item are told apart.
    expect(text(inRow("ver_2", "version-id")[0]!)).toBe("ver_2");
    expect(text(byTestId("exposure-indirect"))).toContain("deploy for deployer still works");
  });

  it("records a confirmation only when the operator makes it", async () => {
    await mount();
    await act(async () => inRow("ver_1", "confirm-revoked")[0]!.props.onClick());
    await settle();
    expect(fake.confirms).toEqual(["Confirm TOKEN version ver_1 was revoked at its provider?"]);
    expect(fake.api.confirmExposureRevocation).toHaveBeenCalledWith("acme", "idn_bob", "ver_1");
    // The report is read again afterwards.
    expect(fake.api.memberExposure).toHaveBeenCalledTimes(2);
  });

  it("revokes a machine credential that still works, and offers nothing for one that does not", async () => {
    await mount();
    expect(all((n) => n.props["data-testid"] === "revoke-credential-crd_2")).toHaveLength(0);
    await act(async () => byTestId("revoke-credential-crd_1").props.onClick());
    await settle();
    expect(fake.api.revokeIdentityCredential).toHaveBeenCalledWith("acme", "idn_svc", "crd_1");
  });

  it("keeps a deleted environment apart by its ID", async () => {
    fake.api.memberExposure = vi.fn(async () => ({
      ...REPORT,
      received: [version({ owningEnvironmentId: "env_gone", receipts: [{ environmentId: "env_gone", way: "revealed", firstAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:00:00.000Z" }] })],
    }));
    await mount();
    expect(text(row("ver_1"))).toContain("in env_gone");
    expect(inRow("ver_1", "rotate-link")).toHaveLength(0);
  });

  it("shows a refusal, such as a missing audit.read", async () => {
    fake.api.memberExposure = vi.fn(async () => {
      throw new Error("Not authorized for this action");
    });
    await mount();
    expect(text(byTestId("exposure-error"))).toContain("Not authorized");
  });
});
