// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  APPROVAL_HEADER,
  VarlatchApiError,
  VarlatchClient,
  type Approval,
  type ApprovalKeys,
  type CredentialReview,
  type SecurityControl,
  type SecurityControlReport,
} from "@varlatch/sdk";

/**
 * The Organization's Security page (ADR-0054 Decision 11). The fake API
 * refuses what the caller's permissions do not allow, as the server does,
 * and records each refusal. For an admin: every section (controls with
 * counts, approval keys, credentials with expiry warnings, Tailnet
 * Requirements, checklist). For a plain member: the controls and a note,
 * with no refused request. For a member with custom Grants: exactly what
 * they allow. Also: the permission lookup failing, the counts failing or
 * going stale, loosening through the approval dialog, enforce shown as
 * coming later, empty states, a server without controls.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, unknown>,
  me: "idn_ada",
  actions: [] as string[],
  refused: [] as string[],
  setStepUpHandler: vi.fn(),
  startAuthentication: vi.fn(),
  toasts: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({
  useSession: () => ({ api: fake.api, identityId: fake.me, setStepUpHandler: fake.setStepUpHandler }),
}));
vi.mock("../src/lib/realtime", () => ({ useOrgRealtime: () => undefined }));
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: fake.startAuthentication }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("../src/components/Select", () => ({
  Menu: () => null,
  Select: ({ options, onChange, "data-testid": id }: { options: { value: string; disabled?: boolean; description?: string }[]; onChange: (v: string) => void; "data-testid": string }) => (
    <div data-testid={id}>
      {options.map((o) => (
        <button key={o.value} data-testid={`${id}-${o.value}`} disabled={o.disabled} title={o.description} onClick={() => onChange(o.value)}>
          {o.value}
        </button>
      ))}
    </div>
  ),
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, children, onClose, "data-testid": id }: Record<string, unknown> & { open: boolean; onClose: () => void }) =>
    open ? (
      <div data-testid={id as string}>
        <h2>{title as React.ReactNode}</h2>
        {children as React.ReactNode}
        <button data-testid="dialog-x" onClick={onClose}>
          x
        </button>
      </div>
    ) : null,
}));

import { OrgSecurityPage } from "../src/features/security-controls/OrgSecurityPage";
import { ApprovalDialogProvider } from "../src/features/security-controls/approval";
import { CHECKLIST } from "../src/features/security-controls/checklist";

const CAPABILITIES = ["security.controls", "security.report", "security.approval-keys", "security.credential-review", "organizations.permissions"];
const ADMIN = ["organization.read", "organization.manage", "project.read", "project.manage", "identity.read", "identity.manage", "policy.read", "policy.manage", "audit.read"];
const MEMBER = ["organization.read", "project.read"];

/** An API call the server allows only with `action`; otherwise refused (403) and recorded, as the server audits it. */
function gated<A extends unknown[], R>(name: string, action: string, fn: (...args: A) => Promise<R>) {
  return vi.fn(async (...args: A) => {
    if (!fake.actions.includes(action)) {
      fake.refused.push(name);
      throw new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "Not authorized for this action", requestId: "req_1" });
    }
    return fn(...args);
  });
}
const control = (name: SecurityControl["control"], over: Partial<SecurityControl> = {}): SecurityControl => ({
  control: name,
  mode: "off",
  config: null,
  version: 0,
  changedAt: null,
  changedBy: null,
  ...over,
});
const STEP_UP = control("admin-step-up", { mode: "report", version: 1, changedAt: "2026-11-01T00:00:00.000Z", changedBy: { id: "idn_ada", name: "Ada" } });
const CONTROLS = [control("requirement-protection"), STEP_UP, control("passkey-verification"), control("credential-lifetime")];
const PEOPLE = [
  { id: "idn_ada", name: "Ada", kind: "human", orgRole: "admin", removedAt: null },
  { id: "idn_eve", name: "Eve", kind: "human", orgRole: "member", removedAt: null },
];
const entry = (operation: string, count: number) => ({
  configVersion: 1,
  operation,
  reason: "no-approval" as const,
  actor: { id: "idn_ada", name: "Ada", kind: "human" },
  count,
  firstSeen: "2026-11-05T10:00:00.000Z",
  lastSeen: "2026-11-09T10:00:00.000Z",
});

function report(stepUp: Partial<SecurityControlReport["controls"][number]> = {}): SecurityControlReport {
  const counts = (c: SecurityControl) => ({ control: c.control, mode: c.mode, version: c.version, total: 0, currentHour: 0, pending: 0, entries: [] });
  return {
    organizationId: "org_acme",
    days: 30,
    since: "2026-10-11T23:00:00.000Z",
    generatedAt: "2026-11-10T23:00:00.000Z",
    summaryDelayMinutes: 10,
    controls: CONTROLS.map((c) =>
      c.control === "admin-step-up"
        ? {
            ...counts(c),
            total: 21,
            currentHour: 2,
            pending: 2,
            entries: ["grant.create", "identity.create", "credential.issue", "role.create", "team.create", "webhook.update"].map((op, i) => entry(op, 6 - i)),
            ...stepUp,
          }
        : counts(c),
    ),
  };
}

const KEYS: ApprovalKeys = {
  generatedAt: "2026-11-10T23:00:00.000Z",
  summary: { admins: 2, withTrustedKey: 1, withoutTrustedKey: 1 },
  items: [
    {
      identity: { id: "idn_ada", name: "Ada" },
      trusted: 1,
      unconfirmed: 1,
      lastConfirmedAt: null,
      passkeys: [
        { name: "Laptop", trust: "trusted", trustedVia: "existing-at-upgrade", createdAt: "2026-09-01T00:00:00.000Z", trustedAt: "2026-11-01T00:00:00.000Z" },
        { name: "Phone", trust: "unconfirmed", trustedVia: null, createdAt: "2026-11-03T00:00:00.000Z", trustedAt: null },
      ],
    },
    { identity: { id: "idn_zoe", name: "Zoe" }, trusted: 0, unconfirmed: 0, lastConfirmedAt: null, passkeys: [] },
  ],
};

const identity = { id: "idn_deploy", name: "deployer", kind: "service" as const, state: "live" as const, disabledReason: null };
function review(): CredentialReview {
  return {
    generatedAt: "2026-11-10T23:00:00.000Z",
    idleDays: 30,
    summary: { reviewed: 3, listed: 1, neverUsed: 1, idle: 0, noExpiry: 1 },
    items: [
      {
        id: "crd_never",
        name: "spare",
        kind: "service",
        createdAt: "2026-10-01T00:00:00.000Z",
        expiresAt: null,
        lastUsedAt: null,
        issuedBy: null,
        identity,
        reasons: ["never-used", "no-expiry"],
      },
    ],
    expiry: {
      warningDays: 7,
      summary: { soon: 1, expired: 1 },
      items: [
        {
          id: "crd_gone",
          name: "old deploy",
          kind: "service",
          createdAt: "2026-09-01T00:00:00.000Z",
          expiresAt: new Date(Date.now() - 2 * 86400_000).toISOString(),
          lastUsedAt: null,
          issuedBy: null,
          identity,
          state: "expired",
        },
        {
          id: "crd_soon",
          name: "deploy",
          kind: "service",
          createdAt: "2026-10-01T00:00:00.000Z",
          expiresAt: new Date(Date.now() + 3 * 86400_000).toISOString(),
          lastUsedAt: "2026-11-09T00:00:00.000Z",
          issuedBy: null,
          identity,
          state: "soon",
        },
      ],
    },
  };
}
const EMPTY_REVIEW: CredentialReview = {
  generatedAt: "2026-11-10T23:00:00.000Z",
  idleDays: 30,
  summary: { reviewed: 2, listed: 0, neverUsed: 0, idle: 0, noExpiry: 0 },
  items: [],
  expiry: { warningDays: 7, summary: { soon: 0, expired: 0 }, items: [] },
};
const REQUIREMENTS = [{ id: "req_1", kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net" }, version: 1, updatedAt: null }];

let root: ReactTestRenderer;
let client: QueryClient;
async function mount(wrap: (page: React.ReactElement) => React.ReactElement = (p) => p) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/o/acme/security"]}>
          <Routes>
            <Route path="/o/:org/security" element={wrap(<OrgSecurityPage />)} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
const settle = async () => {
  for (let i = 0; i < 10; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
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
const links = () => root.root.findAll((n) => n.type === "a").map((a) => a.props.href as string);

beforeEach(() => {
  fake.me = "idn_ada";
  fake.actions = ADMIN;
  fake.refused = [];
  fake.toasts = [];
  fake.setStepUpHandler.mockReset();
  fake.startAuthentication.mockReset();
  fake.startAuthentication.mockResolvedValue({ id: "cred" });
  fake.api = {
    meta: async () => ({ apiMajor: 1, capabilities: CAPABILITIES }),
    listOrganizations: async () => ({ items: [{ id: "org_acme", slug: "acme", name: "Acme" }] }),
    // Needs identity.read: the page must not use it to find the caller's role.
    listIdentities: gated("listIdentities", "identity.read", async () => ({ items: PEOPLE, nextCursor: null })),
    myOrganizationPermissions: vi.fn(async () => ({
      organizationId: "org_acme",
      role: fake.actions.includes("organization.manage") ? "admin" : "member",
      actions: fake.actions,
    })),
    listSecurityControls: gated("listSecurityControls", "organization.read", async () => ({ items: CONTROLS, availableModes: ["off", "report"] })),
    securityControlReport: gated("securityControlReport", "organization.manage", async () => report()),
    securityApprovalKeys: gated("securityApprovalKeys", "organization.manage", async () => KEYS),
    credentialReview: gated("credentialReview", "identity.manage", async () => review()),
    listRequirements: gated("listRequirements", "policy.read", async () => ({ items: REQUIREMENTS, nextCursor: null })),
    changeSecurityControl: vi.fn(async (_org: string, name: SecurityControl["control"]) => ({
      control: control(name, { mode: "report", version: 1 }),
      changed: true,
      loosened: false,
    })),
  };
});

describe("the Security page for an admin", () => {
  it("shows every section from the API", async () => {
    await mount();
    expect(one("security-page").props["data-manage"]).toBe("true");
    expect(fake.refused).toEqual([]);
    expect(byTestId("security-member-note")).toHaveLength(0);
    expect(text(one("security-report-status"))).toContain("Counts of the last 30 days, as of");
    for (const id of ["security-overview", "security-controls-section", "security-approval-keys", "security-credentials", "security-requirements", "security-checklist"]) {
      expect(byTestId(id), id).toHaveLength(1);
    }
    expect(text(one("security-overview"))).toContain("Admin step-up: report");
    expect(fake.api.securityControlReport).toHaveBeenCalledWith("acme", { days: 30 });

    // Counts: total, the live hour, the first five entries, then all of them.
    const counts = one("security-control-counts-admin-step-up");
    expect(text(counts)).toContain("21 counted in the last 30 days");
    expect(text(one("security-control-current-hour-admin-step-up"))).toBe("2 this hour");
    expect(byTestId("security-control-entry")).toHaveLength(5);
    expect(text(byTestId("security-control-entry")[0]!)).toContain("grant.create");
    expect(text(byTestId("security-control-entry")[0]!)).toContain("no approval");
    await click("security-control-entries-toggle-admin-step-up");
    expect(byTestId("security-control-entry")).toHaveLength(6);
    // An off control with nothing counted says how to see what it would do.
    expect(text(one("security-control-counts-passkey-verification"))).toContain("Set it to report to see what it would do");

    // Approval keys: counts by name, a warning for an admin who cannot approve, no key material.
    expect(one("approval-keys-idn_ada").props["data-trusted"]).toBe(1);
    expect(text(one("approval-keys-idn_ada"))).toContain("Laptop");
    expect(text(one("approval-keys-idn_ada"))).toContain("1 trusted, 1 unconfirmed");
    expect(text(one("approval-keys-idn_zoe"))).toContain("Cannot approve yet");
    expect(text(one("approval-keys-warning"))).toContain("One admin has no trusted passkey");
    expect(text(one("approval-keys-warning"))).toContain("varlatch admin reenroll");

    // Credentials: the summary, expiry warnings first, then the review, linking to Access, Machines.
    expect(one("credentials-tile-never-used").props["data-value"]).toBe(1);
    expect(one("credentials-tile-expiring").props["data-value"]).toBe(1);
    expect(one("credentials-tile-expired").props["data-value"]).toBe(1);
    expect(text(one("security-credential-expiry-crd_gone"))).toContain("Credential expired");
    expect(text(one("security-credential-expiry-crd_soon"))).toMatch(/Credential expires in 3 days/);
    expect(text(one("security-credential-review-crd_never"))).toContain("Never used");
    expect(links()).toContain("/o/acme/access?tab=machines");

    // Requirements: the count and the editor.
    expect(one("security-requirements-count").props["data-count"]).toBe(1);
    expect(links()).toContain("/o/acme/access?tab=advanced");

    // Checklist: each item links to its docs page.
    for (const item of CHECKLIST) expect(links()).toContain(item.url);
    expect(links()).toContain("/account/security");
  });

  it("shows enforce as coming in a later release, never as a choice", async () => {
    await mount();
    const enforce = one("security-control-select-admin-step-up-enforce");
    expect(enforce.props.disabled).toBe(true);
    expect(enforce.props.title).toBe("Coming in a later release");
    expect(text(one("security-controls-enforce-note"))).toContain("Coming in a later release");
    expect(text(one("security-control-admin-step-up"))).toContain("(coming in a later release)");
  });

  it("says so when nothing was counted and nothing needs a look", async () => {
    fake.api.securityControlReport = vi.fn(async () => ({
      ...report({ total: 0, currentHour: 0, pending: 0, entries: [] }),
      controls: report({ total: 0, currentHour: 0, pending: 0, entries: [] }).controls.map((c) =>
        c.control === "passkey-verification" ? { ...c, mode: "report" as const } : c,
      ),
    }));
    fake.api.listSecurityControls = vi.fn(async () => ({
      items: CONTROLS.map((c) => (c.control === "passkey-verification" ? { ...c, mode: "report" as const } : c)),
      availableModes: ["off", "report"],
    }));
    fake.api.credentialReview = vi.fn(async () => EMPTY_REVIEW);
    fake.api.listRequirements = vi.fn(async () => ({ items: [], nextCursor: null }));
    await mount();
    expect(text(one("security-control-counts-admin-step-up"))).toBe("Nothing counted in the last 30 days.");
    // Zero access counts are not a promise: they can be dropped.
    expect(text(one("security-control-counts-passkey-verification"))).toContain("Access counts are best-effort: a busy server can drop some");
    expect(text(one("security-control-report-text-passkey-verification"))).toContain("Only requests that were allowed and succeeded count");
    expect(byTestId("security-control-entry")).toHaveLength(0);
    expect(text(one("security-credentials-empty"))).toContain("Nothing to review");
    expect(text(one("security-requirements-count"))).toBe("No Tailnet Requirements yet.");
  });

  it("says every control is off when none is on", async () => {
    fake.api.listSecurityControls = vi.fn(async () => ({ items: CONTROLS.map((c) => control(c.control)), availableModes: ["off", "report"] }));
    await mount();
    expect(text(one("security-overview"))).toContain("Every control is off, as it is by default");
  });

  it("hides a section the server refuses, and shows another error in its place", async () => {
    fake.api.securityApprovalKeys = vi.fn(async () => {
      throw new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "no", requestId: "req_1" });
    });
    fake.api.credentialReview = vi.fn(async () => {
      throw new VarlatchApiError(500, { code: "INTERNAL", message: "Something broke", requestId: "req_2" });
    });
    await mount();
    expect(byTestId("security-approval-keys")).toHaveLength(0);
    expect(text(one("security-credentials-error"))).toContain("Something broke");
    expect(byTestId("security-controls-section")).toHaveLength(1);
  });
});

describe("the Security page for a member", () => {
  it("shows a plain member the controls and a note, and makes no request the server refuses", async () => {
    fake.me = "idn_eve";
    fake.actions = MEMBER;
    await mount();
    expect(fake.refused).toEqual([]);
    expect(one("security-page").props["data-manage"]).toBe("false");
    expect(byTestId("security-controls-section")).toHaveLength(1);
    expect(byTestId("security-control-select-admin-step-up")).toHaveLength(0);
    expect(byTestId("security-report-status")).toHaveLength(0);
    const note = text(one("security-member-note"));
    expect(note).toContain("An admin of this organization manages its security");
    expect(note).toContain("what each control counted (needs organization.manage)");
    expect(note).toContain("machine credentials to review (needs identity.manage)");
    expect(note).toContain("Tailnet Requirements (needs policy.read)");
    for (const id of ["security-approval-keys", "security-credentials", "security-requirements", "security-control-counts-admin-step-up"]) {
      expect(byTestId(id), id).toHaveLength(0);
    }
    expect(byTestId("security-checklist")).toHaveLength(1);
    expect(fake.api.listIdentities).not.toHaveBeenCalled();
    expect(fake.api.securityControlReport).not.toHaveBeenCalled();
    expect(fake.api.securityApprovalKeys).not.toHaveBeenCalled();
    expect(fake.api.credentialReview).not.toHaveBeenCalled();
    expect(fake.api.listRequirements).not.toHaveBeenCalled();
  });

  it("shows a member with custom Grants exactly what they allow", async () => {
    fake.me = "idn_eve";
    fake.actions = [...MEMBER, "identity.manage", "policy.read"];
    await mount();
    expect(fake.refused).toEqual([]);
    expect(byTestId("security-credentials")).toHaveLength(1);
    expect(byTestId("security-requirements")).toHaveLength(1);
    expect(byTestId("security-approval-keys")).toHaveLength(0);
    expect(byTestId("security-control-counts-admin-step-up")).toHaveLength(0);
    expect(byTestId("security-control-select-admin-step-up")).toHaveLength(0);
    const note = text(one("security-member-note"));
    expect(note).toContain("needs organization.manage");
    expect(note).not.toContain("identity.manage");
    expect(note).not.toContain("policy.read");
  });

  it("says so when the permission lookup fails, shows nothing it would have to guess, and recovers on retry", async () => {
    let fail = true;
    fake.api.myOrganizationPermissions = vi.fn(async () => {
      if (fail) throw new VarlatchApiError(503, { code: "UNAVAILABLE", message: "The server is busy.", requestId: "req_3" });
      return { organizationId: "org_acme", role: "admin", actions: ADMIN };
    });
    await mount();
    expect(text(one("security-permissions-error"))).toContain("Could not find out what you may see here");
    expect(text(one("security-permissions-error"))).toContain("The server is busy.");
    expect(byTestId("security-controls-section")).toHaveLength(0);
    expect(byTestId("security-member-note")).toHaveLength(0);
    expect(fake.api.securityControlReport).not.toHaveBeenCalled();
    fail = false;
    await click("security-permissions-retry");
    expect(byTestId("security-permissions-error")).toHaveLength(0);
    expect(byTestId("security-approval-keys")).toHaveLength(1);
  });
});

describe("the counts of the controls", () => {
  it("say when they could not be loaded, and load on retry", async () => {
    let fail = true;
    fake.api.securityControlReport = vi.fn(async () => {
      if (fail) throw new VarlatchApiError(500, { code: "INTERNAL", message: "Counting is down.", requestId: "req_4" });
      return report();
    });
    await mount();
    const status = one("security-report-status");
    expect(status.props["data-state"]).toBe("failed");
    expect(text(status)).toContain("Could not load what each control counted");
    expect(text(status)).toContain("Counting is down.");
    expect(byTestId("security-control-counts-admin-step-up")).toHaveLength(0);
    fail = false;
    await click("security-report-retry");
    expect(one("security-report-status").props["data-state"]).toBe("current");
    expect(text(one("security-control-counts-admin-step-up"))).toContain("21 counted");
  });

  it("say they are not current when a refresh fails, and keep the last counts with their time", async () => {
    await mount();
    expect(one("security-report-status").props["data-state"]).toBe("current");
    fake.api.securityControlReport = vi.fn(async () => {
      throw new VarlatchApiError(500, { code: "INTERNAL", message: "Counting is down.", requestId: "req_5" });
    });
    await act(async () => void (await client.refetchQueries({ queryKey: ["security-control-report", "acme"] })));
    await settle();
    const status = one("security-report-status");
    expect(status.props["data-state"]).toBe("stale");
    expect(text(status)).toMatch(/Counts as of .+; refreshing them failed/);
    expect(text(status)).toContain("not current");
    expect(text(one("security-control-counts-admin-step-up"))).toContain("21 counted");
  });

  it("show a placeholder while they load, without moving the page", async () => {
    let release: (r: SecurityControlReport) => void = () => undefined;
    fake.api.securityControlReport = vi.fn(() => new Promise<SecurityControlReport>((resolve) => (release = resolve)));
    await mount();
    expect(one("security-report-status").props["data-state"]).toBe("loading");
    await act(async () => release(report()));
    await settle();
    expect(one("security-report-status").props["data-state"]).toBe("current");
  });
});

describe("a server without security controls", () => {
  it("says so and asks for nothing", async () => {
    fake.api.meta = async () => ({ apiMajor: 1, capabilities: [] });
    await mount();
    expect(byTestId("security-unsupported")).toHaveLength(1);
    expect(fake.api.listSecurityControls).not.toHaveBeenCalled();
  });
});

describe("loosening on the Security page", () => {
  it("goes through the approval dialog, then saves the same change with the approval and reloads the counts", async () => {
    const calls: { method: string; path: string; approval: string | null; body: unknown }[] = [];
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const pending: Approval = {
      id: "apr_9",
      operation: "security_control.change",
      organization: { id: "org_acme", slug: "acme", name: "Acme" },
      summary: { title: "Turn admin-step-up off in Acme", changes: [{ field: "mode", from: "report", to: "off", loosens: true }] },
      state: "pending",
      closeReason: null,
      requestedBy: { credentialKind: "browser", client: "Firefox on Linux" },
      url: "https://varlatch.test/approve/apr_9",
      interval: 5,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 120_000).toISOString(),
      approvedAt: null,
      consumedAt: null,
      closedAt: null,
    };
    const fetchImpl = (async (url: string, init: RequestInit = {}) => {
      const parsed = new URL(url);
      const path = parsed.pathname;
      const method = init.method ?? "GET";
      const headers = (init.headers ?? {}) as Record<string, string>;
      calls.push({ method, path, approval: headers[APPROVAL_HEADER] ?? null, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "test", semanticsVersions: [], capabilities: CAPABILITIES });
      if (path === "/v1/organizations") return json(200, { items: [{ id: "org_acme", slug: "acme", name: "Acme" }], nextCursor: null });
      if (path === "/v1/organizations/acme/me/permissions") return json(200, { organizationId: "org_acme", role: "admin", actions: ADMIN });
      if (path === "/v1/organizations/acme/security/controls") return json(200, { items: CONTROLS, availableModes: ["off", "report"] });
      if (path === "/v1/organizations/acme/security/control-report") return json(200, report());
      if (path === "/v1/organizations/acme/security/approval-keys") return json(200, KEYS);
      if (path === "/v1/organizations/acme/security/credential-review") return json(200, review());
      if (path === "/v1/organizations/acme/requirements") return json(200, { items: REQUIREMENTS, nextCursor: null });
      if (path === "/v1/organizations/acme/security/controls/admin-step-up" && method === "PATCH") {
        if (headers[APPROVAL_HEADER] === "apr_9") return json(200, { control: { ...STEP_UP, mode: "off", version: 2 }, changed: true, loosened: true });
        return json(403, { error: { code: "STEP_UP_REQUIRED", message: "approval needed", requestId: "req_1", details: { approval: pending } } });
      }
      if (path === "/v1/me/approvals/apr_9/options") return json(200, { publicKey: { challenge: "c9" } });
      if (path === "/v1/me/approvals/apr_9/approve") return json(200, { ...pending, state: "approved" });
      return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "no route", requestId: "req_1" } });
    }) as unknown as typeof fetch;
    fake.api = new VarlatchClient({
      server: "https://varlatch.test",
      fetch: fetchImpl,
      onStepUp: (a) => (fake.setStepUpHandler.mock.calls.at(-1)?.[0] as (a: Approval) => Promise<boolean>)(a),
    }) as unknown as Record<string, unknown>;

    await mount((page) => <ApprovalDialogProvider>{page}</ApprovalDialogProvider>);
    await click("security-control-select-admin-step-up-off");
    expect(text(one("security-control-save-admin-step-up"))).toBe("Approve and save");
    const reportsBefore = calls.filter((c) => c.path.endsWith("/control-report")).length;
    await act(async () => void one("security-control-save-admin-step-up").props.onClick());
    await settle();
    expect(text(one("approval-dialog"))).toContain("Turn admin-step-up off in Acme");
    await click("approval-approve");
    await settle();
    const patches = calls.filter((c) => c.method === "PATCH");
    expect(patches.map((c) => c.approval)).toEqual([null, "apr_9"]);
    expect(patches[1]!.body).toEqual({ mode: "off", expectedVersion: 1 });
    expect(byTestId("approval-dialog")).toHaveLength(0);
    expect(fake.toasts).toEqual(["Admin step-up saved"]);
    expect(calls.filter((c) => c.path.endsWith("/control-report")).length).toBeGreaterThan(reportsBefore);
  });
});
