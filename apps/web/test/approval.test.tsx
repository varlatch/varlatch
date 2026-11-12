// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { APPROVAL_HEADER, VarlatchApiError, VarlatchClient, type Approval } from "@varlatch/sdk";

/**
 * Step-up approvals in the dashboard (ADR-0054 Decision 3): the approval
 * page a CLI points to, with each state it can be in, and the inline dialog
 * that answers a STEP_UP_REQUIRED for a change made in the dashboard, after
 * which the SDK repeats the change once with the approval.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, unknown>,
  setStepUpHandler: vi.fn(),
  startAuthentication: vi.fn(),
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
  vi.stubGlobal("location", { protocol: "https:", hostname: "varlatch.test", origin: "https://varlatch.test" });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, setStepUpHandler: fake.setStepUpHandler }) }));
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: fake.startAuthentication }));
vi.mock("../src/shell/BrandMark", () => ({ BrandMark: () => null }));
vi.mock("../src/shell/AuthScreens", () => ({
  CenteredCard: ({ children, testId }: { children: React.ReactNode; testId?: string }) => <main data-testid={testId}>{children}</main>,
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, description, children, onClose, "data-testid": id }: Record<string, unknown> & { open: boolean; onClose: () => void }) =>
    open ? (
      <div data-testid={id as string}>
        <h2>{title as React.ReactNode}</h2>
        <p>{description as React.ReactNode}</p>
        {children as React.ReactNode}
        <button data-testid="dialog-x" onClick={onClose}>
          x
        </button>
      </div>
    ) : null,
}));

import { ApprovalPage } from "../src/features/security-controls/ApprovalPage";
import { ApprovalDialogProvider, approvalOutcomeMessage, changeValue, durationWords, fieldLabel } from "../src/features/security-controls/approval";

const at = (offsetSeconds: number) => new Date(Date.now() + offsetSeconds * 1000).toISOString();
const approval = (over: Partial<Approval> = {}): Approval => ({
  id: "apr_1",
  operation: "security_control.change",
  organization: { id: "org_1", slug: "acme", name: "Acme" },
  summary: {
    title: "Change credential-lifetime in Acme",
    changes: [
      { field: "mode", from: "report", to: "off", loosens: true },
      { field: "maxTtlSeconds", from: "86400", to: "604800", loosens: true },
      { field: "defaultTtlSeconds", from: "7200", to: "3600", loosens: false },
    ],
  },
  state: "pending",
  closeReason: null,
  requestedBy: { credentialKind: "cli", client: "varlatch CLI 0.21.0 on Linux" },
  url: "https://varlatch.test/approve/apr_1",
  interval: 5,
  createdAt: at(-30),
  expiresAt: at(90),
  approvedAt: null,
  consumedAt: null,
  closedAt: null,
  ...over,
});
const apiError = (status: number, code: string, details?: Record<string, unknown>) =>
  new VarlatchApiError(status, { code: code as never, message: `${code} from the server`, requestId: "req_1", ...(details ? { details } : {}) });

let root: ReactTestRenderer;
async function mount(element: React.ReactElement, path = "/approve/apr_1") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/approve/:id" element={element} />
            <Route path="*" element={element} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
const settle = async () => {
  for (let i = 0; i < 8; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const byTestId = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string) => {
  const found = byTestId(id);
  expect(found, id).toHaveLength(1);
  return found[0]!;
};
const click = async (id: string) => {
  await act(async () => one(id).props.onClick());
  await settle();
};

beforeEach(() => {
  fake.startAuthentication.mockReset();
  fake.startAuthentication.mockResolvedValue({ id: "cred", response: {} });
  fake.setStepUpHandler.mockReset();
  fake.api = {
    getApproval: vi.fn(async () => approval()),
    startApproval: vi.fn(async () => ({ publicKey: { challenge: "c1", userVerification: "required" } })),
    approveApproval: vi.fn(async () => approval({ state: "approved", approvedAt: at(0) })),
    cancelApproval: vi.fn(async () => approval({ state: "closed", closeReason: "cancelled", closedAt: at(0) })),
  };
});

describe("the approval page", () => {
  it("shows the server's summary, the weakening parts, who asked and a live countdown", async () => {
    await mount(<ApprovalPage />);
    expect(fake.api.getApproval).toHaveBeenCalledWith("apr_1");
    expect(text(one("approval-title"))).toBe("Change credential-lifetime in Acme");
    expect(text(one("approval-organization"))).toContain("Acme");
    expect(text(one("approval-requester"))).toContain("You asked from the CLI (varlatch CLI 0.21.0 on Linux)");
    expect(text(one("approval-countdown"))).toMatch(/^01:(2\d|30)$/);
    const changes = byTestId("approval-change");
    expect(changes.map((c) => c.props["data-loosens"])).toEqual(["true", "true", "false"]);
    expect(text(changes[1]!)).toContain("1 day → 7 days");
    expect(byTestId("approval-approve")).toHaveLength(1);
  });

  it("approves with a trusted passkey over the server's challenge, then sends the person back", async () => {
    await mount(<ApprovalPage />);
    await click("approval-approve");
    expect(fake.api.startApproval).toHaveBeenCalledWith("apr_1");
    expect(fake.startAuthentication).toHaveBeenCalledWith({ optionsJSON: { challenge: "c1", userVerification: "required" } });
    expect(fake.api.approveApproval).toHaveBeenCalledWith("apr_1", { id: "cred", response: {} });
    expect(one("approval-finished").props["data-state"]).toBe("approved");
    expect(text(one("approval-finished"))).toContain("the CLI continues by itself");
    expect(byTestId("approval-approve")).toHaveLength(0);
  });

  it("denies: the approval is cancelled and nothing changes", async () => {
    await mount(<ApprovalPage />);
    await click("approval-deny");
    expect(fake.api.cancelApproval).toHaveBeenCalledWith("apr_1");
    expect(text(one("approval-finished"))).toContain("This approval was cancelled");
  });

  it.each([
    ["expired on the server", approval({ state: "expired" }), "expired before it was approved"],
    ["past its expiry here", approval({ expiresAt: at(-1) }), "expired before it was approved"],
    ["used", approval({ state: "consumed", consumedAt: at(0) }), "already used"],
    ["closed by the operator's reset", approval({ state: "closed", closeReason: "reset" }), "reset the organization's security controls"],
  ])("says when an approval is %s, and offers no approval", async (_, loaded, words) => {
    fake.api.getApproval = vi.fn(async () => loaded);
    await mount(<ApprovalPage />);
    expect(text(one("approval-finished"))).toContain(words);
    expect(byTestId("approval-approve")).toHaveLength(0);
    expect(byTestId("approval-countdown")).toHaveLength(0);
  });

  it("says only not found or not yours for someone else's approval", async () => {
    fake.api.getApproval = vi.fn(async () => {
      throw apiError(404, "RESOURCE_NOT_FOUND");
    });
    await mount(<ApprovalPage />);
    expect(text(one("approval-load-error"))).toBe(
      "This approval was not found, or it is not yours. Only the person who asked can see and approve it.",
    );
  });

  it("points a person without a trusted passkey to confirming one, and to the host operator", async () => {
    fake.api.startApproval = vi.fn(async () => {
      throw apiError(403, "PERMISSION_DENIED", { reason: "no-trusted-passkey" });
    });
    await mount(<ApprovalPage />);
    await click("approval-approve");
    const said = text(one("approval-error"));
    expect(said).toContain("Account, Security");
    expect(said).toContain("varlatch admin reenroll");
    expect(fake.startAuthentication).not.toHaveBeenCalled();
    // Still pending: the person may try again after confirming a passkey.
    expect(byTestId("approval-approve")).toHaveLength(1);
  });

  it("refuses a passkey that did not verify the user, and lets the person try again", async () => {
    fake.api.approveApproval = vi.fn(async () => {
      throw apiError(403, "PERMISSION_DENIED", { reason: "user-verification-required" });
    });
    await mount(<ApprovalPage />);
    await click("approval-approve");
    expect(text(one("approval-error"))).toContain("did not verify you with a PIN, fingerprint or face");
    expect(byTestId("approval-approve")).toHaveLength(1);
  });

  it("says nothing was approved when the browser's passkey prompt is cancelled", async () => {
    fake.startAuthentication.mockRejectedValue(Object.assign(new Error("cancelled"), { name: "NotAllowedError" }));
    await mount(<ApprovalPage />);
    await click("approval-approve");
    expect(text(one("approval-error"))).toContain("did not complete (NotAllowedError). Nothing was approved.");
    expect(fake.api.approveApproval).not.toHaveBeenCalled();
  });
});

describe("words", () => {
  it("writes lifetimes in words and names a failed approval", () => {
    expect(durationWords(3600)).toBe("1 hour");
    expect(durationWords(90)).toBe("90 seconds");
    expect(changeValue("defaultTtlSeconds", "172800")).toBe("2 days");
    expect(changeValue("mode", null)).toBe("none");
    expect(approvalOutcomeMessage(apiError(403, "STEP_UP_REQUIRED"))).toContain("it was not given");
    expect(approvalOutcomeMessage(apiError(409, "APPROVAL_INVALID", { reason: "mismatch" }))).toContain("a different change");
    expect(approvalOutcomeMessage(apiError(409, "VERSION_CONFLICT"))).toBeNull();
  });

  it("names the fields of a machine identity's approval (admin-step-up), and leaves their words as the server wrote them", () => {
    expect(fieldLabel("credentialExpiry")).toBe("Credential expires");
    expect(fieldLabel("credentialUses")).toBe("Credential uses");
    expect(fieldLabel("claims")).toBe("Required claims");
    expect(changeValue("credentialExpiry", "after 1 day")).toBe("after 1 day");
    expect(changeValue("credentialExpiry", null)).toBe("none");
  });

  it("names the fields of a Grant's or a role's approval (admin-step-up)", () => {
    expect(fieldLabel("scope")).toBe("Scope");
    expect(fieldLabel("permission")).toBe("Permission");
    expect(fieldLabel("actionsAdded")).toBe("Actions added");
    expect(fieldLabel("actionsRemoved")).toBe("Actions removed");
    expect(changeValue("actionsRemoved", null)).toBe("none");
  });

  it("names the role field of a person's invitation, promotion or demotion (admin-step-up)", () => {
    expect(fieldLabel("role")).toBe("Role");
    expect(changeValue("role", "admin")).toBe("admin");
    expect(changeValue("role", null)).toBe("none");
  });
});

describe("the inline approval dialog", () => {
  /** A real client over a fake server: the change first needs an approval, then succeeds with it. */
  function server() {
    const calls: { method: string; path: string; approval: string | null; body: unknown }[] = [];
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const pending = approval({ requestedBy: { credentialKind: "browser", client: "Firefox on Linux" }, expiresAt: at(110) });
    const fetchImpl = (async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      const headers = (init.headers ?? {}) as Record<string, string>;
      const method = init.method ?? "GET";
      calls.push({ method, path, approval: headers[APPROVAL_HEADER] ?? null, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/v1/organizations/acme/security/controls/credential-lifetime" && method === "PATCH") {
        if (headers[APPROVAL_HEADER] === "apr_1") {
          return json(200, { control: { control: "credential-lifetime", mode: "off", config: null, version: 3, changedAt: at(0), changedBy: null }, changed: true, loosened: true });
        }
        return json(403, { error: { code: "STEP_UP_REQUIRED", message: "needs approval", requestId: "req_1", details: { approval: pending } } });
      }
      if (path === "/v1/me/approvals/apr_1/options") return json(200, { publicKey: { challenge: "c9" } });
      if (path === "/v1/me/approvals/apr_1/approve") return json(200, { ...pending, state: "approved", approvedAt: at(0) });
      if (path === "/v1/me/approvals/apr_1/cancel") return json(200, { ...pending, state: "closed", closeReason: "cancelled" });
      return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "no route", requestId: "req_1" } });
    }) as unknown as typeof fetch;
    const client = new VarlatchClient({
      server: "https://varlatch.test",
      fetch: fetchImpl,
      onStepUp: (a) => {
        const handler = fake.setStepUpHandler.mock.calls.at(-1)?.[0] as ((a: Approval) => Promise<boolean>) | null;
        return handler ? handler(a) : Promise.resolve(false);
      },
    });
    fake.api = client as unknown as Record<string, unknown>;
    return { client, calls };
  }

  it("asks for the approval, then the SDK repeats the change once with it", async () => {
    const { client, calls } = server();
    await mount(<ApprovalDialogProvider>{null}</ApprovalDialogProvider>);
    let result: unknown;
    const change = client.changeSecurityControl("acme", "credential-lifetime", { mode: "off", expectedVersion: 2 }).then((r) => (result = r));
    await settle();
    expect(text(one("approval-dialog"))).toContain("Change credential-lifetime in Acme");
    expect(text(one("approval-requester"))).toContain("You asked from the dashboard");
    await click("approval-approve");
    await act(async () => change);
    expect(fake.startAuthentication).toHaveBeenCalledWith({ optionsJSON: { challenge: "c9" } });
    expect(result).toMatchObject({ changed: true, loosened: true });
    const patches = calls.filter((c) => c.method === "PATCH");
    expect(patches.map((c) => c.approval)).toEqual([null, "apr_1"]);
    // The identical request, carrying the approval.
    expect(patches[1]!.body).toEqual(patches[0]!.body);
    expect(byTestId("approval-dialog")).toHaveLength(0);
  });

  it("cancels: the approval is cancelled on the server and the change surfaces STEP_UP_REQUIRED", async () => {
    const { client, calls } = server();
    await mount(<ApprovalDialogProvider>{null}</ApprovalDialogProvider>);
    const change = client.changeSecurityControl("acme", "credential-lifetime", { mode: "off", expectedVersion: 2 }).catch((e: unknown) => e);
    await settle();
    await click("approval-deny");
    const err = await change;
    expect(err).toBeInstanceOf(VarlatchApiError);
    expect((err as VarlatchApiError).code).toBe("STEP_UP_REQUIRED");
    expect(calls.some((c) => c.path === "/v1/me/approvals/apr_1/cancel")).toBe(true);
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
    expect(byTestId("approval-dialog")).toHaveLength(0);
  });

  it("closing the dialog cancels a pending approval, best effort", async () => {
    const { client, calls } = server();
    await mount(<ApprovalDialogProvider>{null}</ApprovalDialogProvider>);
    const change = client.changeSecurityControl("acme", "credential-lifetime", { mode: "off", expectedVersion: 2 }).catch((e: unknown) => e);
    await settle();
    await click("dialog-x");
    expect(((await change) as VarlatchApiError).code).toBe("STEP_UP_REQUIRED");
    expect(calls.some((c) => c.path === "/v1/me/approvals/apr_1/cancel")).toBe(true);
  });
});
