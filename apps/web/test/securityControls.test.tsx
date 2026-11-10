// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { APPROVAL_HEADER, VarlatchApiError, VarlatchClient, type Approval, type SecurityControl } from "@varlatch/sdk";

/**
 * Security Controls in Settings (ADR-0054 Decisions 1 and 2): every control
 * listed with its mode and version, tightening saved at once, loosening
 * approved first in the inline dialog, enforce not offered yet, a stale
 * version reloaded, and nothing editable for a member.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, unknown>,
  me: "idn_ada",
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
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: fake.startAuthentication }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("../src/components/Select", () => ({
  Menu: () => null,
  Select: ({ options, onChange, "data-testid": id }: { options: { value: string; disabled?: boolean }[]; onChange: (v: string) => void; "data-testid": string }) => (
    <div data-testid={id}>
      {options.map((o) => (
        <button key={o.value} data-testid={`${id}-${o.value}`} disabled={o.disabled} onClick={() => onChange(o.value)}>
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

import { SecurityControlsCard, changeInput, loosens, parseLifetimes } from "../src/features/security-controls/SecurityControlsCard";
import { ApprovalDialogProvider } from "../src/features/security-controls/approval";

const control = (name: SecurityControl["control"], over: Partial<SecurityControl> = {}): SecurityControl => ({
  control: name,
  mode: "off",
  config: null,
  version: 0,
  changedAt: null,
  changedBy: null,
  ...over,
});
const LIFETIME = control("credential-lifetime", {
  mode: "report",
  config: { defaultTtlSeconds: 3600, maxTtlSeconds: 86400 },
  version: 2,
  changedAt: "2026-11-10T10:00:00.000Z",
  changedBy: { id: "idn_ada", name: "Ada" },
});
const CONTROLS = [control("requirement-protection"), control("admin-step-up"), control("passkey-verification"), LIFETIME];
const PEOPLE = [
  { id: "idn_ada", name: "Ada", kind: "human", orgRole: "admin", removedAt: null },
  { id: "idn_eve", name: "Eve", kind: "human", orgRole: "member", removedAt: null },
];

let root: ReactTestRenderer;
async function mount(element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
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
const type = (id: string, value: string) => act(() => one(id).props.onChange({ target: { value } }));

beforeEach(() => {
  fake.me = "idn_ada";
  fake.toasts = [];
  fake.setStepUpHandler.mockReset();
  fake.startAuthentication.mockReset();
  fake.startAuthentication.mockResolvedValue({ id: "cred" });
  fake.api = {
    meta: async () => ({ apiMajor: 1, capabilities: ["security.controls"] }),
    listIdentities: async () => ({ items: PEOPLE, nextCursor: null }),
    listSecurityControls: vi.fn(async () => ({ items: CONTROLS, availableModes: ["off", "report"] })),
    changeSecurityControl: vi.fn(async (_org: string, name: SecurityControl["control"]) => ({
      control: control(name, { mode: "report", version: 1 }),
      changed: true,
      loosened: false,
    })),
  };
});

describe("the classification the card shows", () => {
  it("calls a change loosening when the mode moves towards off, a lifetime grows, or lifetimes are cleared", () => {
    expect(loosens(LIFETIME, { mode: "off", config: LIFETIME.config })).toBe(true);
    expect(loosens(LIFETIME, { mode: "report", config: { defaultTtlSeconds: 3600, maxTtlSeconds: 172800 } })).toBe(true);
    expect(loosens(LIFETIME, { mode: "report", config: null })).toBe(true);
    // Mixed: a shorter default with a longer maximum is still loosening.
    expect(loosens(LIFETIME, { mode: "report", config: { defaultTtlSeconds: 60, maxTtlSeconds: 172800 } })).toBe(true);
    expect(loosens(LIFETIME, { mode: "report", config: { defaultTtlSeconds: 60, maxTtlSeconds: 3600 } })).toBe(false);
    expect(loosens(control("admin-step-up"), { mode: "report", config: null })).toBe(false);
  });

  it("checks the lifetimes and sends only what changed with the version it read", () => {
    expect(parseLifetimes("", "")).toEqual({ config: null });
    expect(parseLifetimes("0", "10")).toEqual({ error: "The default lifetime must be more than 0 seconds." });
    expect(parseLifetimes("20", "10")).toEqual({ error: "The default lifetime cannot be longer than the maximum." });
    expect(parseLifetimes("1h", "10")).toHaveProperty("error");
    expect(changeInput(LIFETIME, { mode: "report", config: LIFETIME.config })).toBeNull();
    expect(changeInput(LIFETIME, { mode: "off", config: LIFETIME.config })).toEqual({ expectedVersion: 2, mode: "off" });
    expect(changeInput(LIFETIME, { mode: "report", config: null })).toEqual({ expectedVersion: 2, config: null });
  });
});

describe("the Security controls section", () => {
  it("lists every control with its mode, version and last change, and explains the modes", async () => {
    await mount(<SecurityControlsCard org="acme" />);
    for (const c of CONTROLS) expect(byTestId(`security-control-${c.control}`)).toHaveLength(1);
    expect(text(one("security-control-mode-credential-lifetime"))).toContain("Report");
    expect(text(one("security-control-lifetimes"))).toBe("Default 1 hour, at most 1 day.");
    expect(text(one("security-control-credential-lifetime"))).toContain("Version 2, changed");
    expect(text(one("security-control-credential-lifetime"))).toContain("by Ada");
    expect(text(one("security-control-requirement-protection"))).toContain("Version 0, never changed");
    const explainer = text(one("security-controls-explainer"));
    expect(explainer).toContain("without refusing or changing anything");
    expect(explainer).toContain("Enforce, which applies a control, is not available yet");
    expect(explainer).toContain("needs your approval with a trusted passkey");
  });

  it("offers enforce as not available yet", async () => {
    await mount(<SecurityControlsCard org="acme" />);
    expect(one("security-control-select-admin-step-up-enforce").props.disabled).toBe(true);
    expect(one("security-control-select-admin-step-up-report").props.disabled).toBe(false);
  });

  it("saves a tightening at once, with the version it read", async () => {
    await mount(<SecurityControlsCard org="acme" />);
    await click("security-control-select-admin-step-up-report");
    expect(text(one("security-control-save-admin-step-up"))).toBe("Save");
    await click("security-control-save-admin-step-up");
    expect(fake.api.changeSecurityControl).toHaveBeenCalledWith("acme", "admin-step-up", { mode: "report", expectedVersion: 0 });
    expect(fake.toasts).toEqual(["Admin step-up saved"]);
  });

  it("marks a loosening as needing approval, and refuses lifetimes that do not fit", async () => {
    await mount(<SecurityControlsCard org="acme" />);
    await type("security-control-max-ttl", "172800");
    expect(text(one("security-control-save-credential-lifetime"))).toBe("Approve and save");
    await type("security-control-default-ttl", "999999");
    expect(text(one("security-control-input-error"))).toContain("cannot be longer than the maximum");
    expect(byTestId("security-control-save-credential-lifetime")).toHaveLength(0);
  });

  it("reloads after a version conflict and says so", async () => {
    fake.api.changeSecurityControl = vi.fn(async () => {
      throw new VarlatchApiError(409, { code: "VERSION_CONFLICT", message: "stale", requestId: "req_1" });
    });
    await mount(<SecurityControlsCard org="acme" />);
    const loads = (fake.api.listSecurityControls as ReturnType<typeof vi.fn>).mock.calls.length;
    await click("security-control-select-passkey-verification-report");
    await click("security-control-save-passkey-verification");
    expect(fake.toasts).toEqual(["Passkey verification not saved"]);
    expect((fake.api.listSecurityControls as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(loads);
  });

  it("explains a refused enforce", async () => {
    fake.api.changeSecurityControl = vi.fn(async () => {
      throw new VarlatchApiError(422, { code: "CONTROL_MODE_UNAVAILABLE", message: "no", requestId: "req_1" });
    });
    await mount(<SecurityControlsCard org="acme" />);
    await click("security-control-select-admin-step-up-report");
    await click("security-control-save-admin-step-up");
    expect(text(one("security-control-error-admin-step-up"))).toContain("Enforce is not available yet");
  });

  it("shows a member the controls without anything to change", async () => {
    fake.me = "idn_eve";
    await mount(<SecurityControlsCard org="acme" />);
    expect(byTestId("security-control-admin-step-up")).toHaveLength(1);
    expect(byTestId("security-control-select-admin-step-up")).toHaveLength(0);
    expect(byTestId("security-control-default-ttl")).toHaveLength(0);
  });

  it("is hidden when the server has no Security Controls", async () => {
    fake.api.meta = async () => ({ apiMajor: 1, capabilities: [] });
    await mount(<SecurityControlsCard org="acme" />);
    expect(byTestId("settings-security-controls")).toHaveLength(0);
    expect(fake.api.listSecurityControls).not.toHaveBeenCalled();
  });
});

describe("loosening through the dashboard", () => {
  it("opens the approval dialog, then saves the same change with the approval", async () => {
    const calls: { method: string; path: string; approval: string | null; body: unknown }[] = [];
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const pending: Approval = {
      id: "apr_7",
      operation: "security_control.change",
      organization: { id: "org_1", slug: "acme", name: "Acme" },
      summary: { title: "Turn credential-lifetime off in Acme", changes: [{ field: "mode", from: "report", to: "off", loosens: true }] },
      state: "pending",
      closeReason: null,
      requestedBy: { credentialKind: "browser", client: "Firefox on Linux" },
      url: "https://varlatch.test/approve/apr_7",
      interval: 5,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 120_000).toISOString(),
      approvedAt: null,
      consumedAt: null,
      closedAt: null,
    };
    const fetchImpl = (async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      const method = init.method ?? "GET";
      const headers = (init.headers ?? {}) as Record<string, string>;
      calls.push({ method, path, approval: headers[APPROVAL_HEADER] ?? null, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "test", semanticsVersions: [], capabilities: ["security.controls"] });
      if (path === "/v1/organizations/acme/identities") return json(200, { items: PEOPLE, nextCursor: null });
      if (path === "/v1/organizations/acme/security/controls") return json(200, { items: CONTROLS, availableModes: ["off", "report"] });
      if (path === "/v1/organizations/acme/security/controls/credential-lifetime" && method === "PATCH") {
        if (headers[APPROVAL_HEADER] === "apr_7") return json(200, { control: { ...LIFETIME, mode: "off", version: 3 }, changed: true, loosened: true });
        return json(403, { error: { code: "STEP_UP_REQUIRED", message: "approval needed", requestId: "req_1", details: { approval: pending } } });
      }
      if (path === "/v1/me/approvals/apr_7/options") return json(200, { publicKey: { challenge: "c7" } });
      if (path === "/v1/me/approvals/apr_7/approve") return json(200, { ...pending, state: "approved" });
      return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "no route", requestId: "req_1" } });
    }) as unknown as typeof fetch;
    fake.api = new VarlatchClient({
      server: "https://varlatch.test",
      fetch: fetchImpl,
      onStepUp: (a) => (fake.setStepUpHandler.mock.calls.at(-1)?.[0] as (a: Approval) => Promise<boolean>)(a),
    }) as unknown as Record<string, unknown>;

    await mount(
      <ApprovalDialogProvider>
        <SecurityControlsCard org="acme" />
      </ApprovalDialogProvider>,
    );
    await click("security-control-select-credential-lifetime-off");
    expect(text(one("security-control-save-credential-lifetime"))).toBe("Approve and save");
    await act(async () => void one("security-control-save-credential-lifetime").props.onClick());
    await settle();
    expect(text(one("approval-dialog"))).toContain("Turn credential-lifetime off in Acme");
    await click("approval-approve");
    await settle();
    const patches = calls.filter((c) => c.method === "PATCH");
    expect(patches.map((c) => c.approval)).toEqual([null, "apr_7"]);
    expect(patches[1]!.body).toEqual({ mode: "off", expectedVersion: 2 });
    expect(byTestId("approval-dialog")).toHaveLength(0);
    expect(fake.toasts).toEqual(["Credential lifetime saved"]);
  });
});
