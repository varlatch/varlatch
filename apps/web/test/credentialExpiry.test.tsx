// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessCheck, PlatformConnection, SyncTarget } from "@varlatch/protocol";

/**
 * GitHub says when a personal access token expires. Varlatch warns two
 * weeks ahead on the connection and on every integration that uses it, and
 * a dialog stops before saving a token that is about to expire.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  // useNow ticks with window timers; the cards need nothing else from a browser.
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ children, footer }: { children: React.ReactNode; footer?: React.ReactNode }) => (
    <div>
      {children}
      {footer}
    </div>
  ),
  useConfirm: () => async () => true,
}));

import { EXPIRY_WARNING_DAYS, credentialExpiry, expiryText, expiryTone } from "../src/features/sync/credentialExpiry";
import { checkPasses } from "../src/features/sync/accessCheck";
import { ConnectionCard, NewConnectionDialog } from "../src/features/sync/ConnectionsPage";
import { TargetCard } from "../src/features/sync/TargetCard";
import { AddIntegrationDialog } from "../src/features/sync/AddIntegrationDialog";

const DAY = 86_400_000;
const NOW = Date.parse("2026-10-09T12:00:00Z");
const inDays = (days: number, from = Date.now()) => new Date(from + days * DAY).toISOString();

describe("credentialExpiry", () => {
  it("is unknown when the platform has not said, never 'does not expire'", () => {
    expect(credentialExpiry(null, NOW)).toBeNull();
    expect(credentialExpiry(undefined, NOW)).toBeNull();
    expect(credentialExpiry("not a date", NOW)).toBeNull();
  });

  it(`warns from ${EXPIRY_WARNING_DAYS} days ahead, and says when it expired`, () => {
    expect(credentialExpiry(inDays(30, NOW), NOW)).toMatchObject({ state: "later", days: 30 });
    expect(credentialExpiry(inDays(EXPIRY_WARNING_DAYS, NOW), NOW)).toMatchObject({ state: "soon", days: EXPIRY_WARNING_DAYS });
    expect(credentialExpiry(inDays(0.25, NOW), NOW)).toMatchObject({ state: "soon", days: 1 });
    expect(credentialExpiry(inDays(-1, NOW), NOW)).toMatchObject({ state: "expired", days: 0 });
  });

  it("reads as a sentence with the caller's date, and a tone", () => {
    const soon = credentialExpiry(inDays(5, NOW), NOW)!;
    expect(expiryText(soon, "Oct 14")).toBe("Token expires in 5 days (Oct 14)");
    expect(expiryText(credentialExpiry(inDays(0.5, NOW), NOW)!, "Oct 9")).toBe("Token expires within a day (Oct 9)");
    expect(expiryText(credentialExpiry(inDays(-2, NOW), NOW)!, "Oct 7")).toBe("Token expired Oct 7");
    expect(expiryText(credentialExpiry(inDays(90, NOW), NOW)!, "Jan 7")).toBe("Token expires Jan 7");
    expect([soon, credentialExpiry(inDays(-2, NOW), NOW)!, credentialExpiry(inDays(90, NOW), NOW)!].map(expiryTone)).toEqual([
      "warn",
      "error",
      "muted",
    ]);
  });

  it("lets a dialog save without asking only for a token not about to expire", () => {
    const ok: AccessCheck = { status: "ok", where: "connection", message: "ok" };
    expect(checkPasses(ok, NOW)).toBe(true);
    expect(checkPasses({ ...ok, credentialExpiresAt: inDays(60, NOW) }, NOW)).toBe(true);
    expect(checkPasses({ ...ok, credentialExpiresAt: inDays(3, NOW) }, NOW)).toBe(false);
    expect(checkPasses({ ...ok, status: "credential-rejected" }, NOW)).toBe(false);
  });
});

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
}
afterEach(async () => {
  await act(async () => root?.unmount());
});
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const byTestId = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

const connection = (credentialExpiresAt: string | null): PlatformConnection => ({
  id: "pcn_1",
  organizationId: "org_1",
  platform: "github-actions",
  baseIdentity: "acme",
  name: "GitHub acme",
  createdAt: "2026-09-01T00:00:00Z",
  version: 1,
  updatedAt: null,
  credentialExpiresAt,
  credentialExpirySeenAt: credentialExpiresAt ? "2026-10-09T08:00:00Z" : null,
});

describe("Connections card", () => {
  const card = (expiresAt: string | null) => (
    <ConnectionCard org="acme" connection={connection(expiresAt)} targets={[]} envs={new Map()} onReplace={() => {}} onChanged={() => {}} />
  );

  it("warns ahead of the expiry and offers to replace the credential", async () => {
    await mount(card(inDays(5)));
    expect(text(byTestId("credential-expiry-pcn_1"))).toMatch(/^Token expires in 5 days \(/);
    expect(all("fix-connection-pcn_1")).toHaveLength(1);
  });

  it("says when the token expired", async () => {
    await mount(card(inDays(-1)));
    expect(text(byTestId("credential-expiry-pcn_1"))).toMatch(/^Token expired /);
    expect(all("fix-connection-pcn_1")).toHaveLength(1);
  });

  it("shows a distant date quietly, and nothing when GitHub has not said", async () => {
    await mount(card(inDays(90)));
    expect(text(byTestId("credential-expiry-pcn_1"))).toMatch(/^Token expires /);
    expect(all("fix-connection-pcn_1")).toHaveLength(0);
    await act(async () => root.update(<QueryClientProvider client={new QueryClient()}><MemoryRouter>{card(null)}</MemoryRouter></QueryClientProvider>));
    expect(all("credential-expiry-pcn_1")).toHaveLength(0);
  });
});

describe("Integration card", () => {
  const target: SyncTarget = {
    id: "snt_1",
    organizationId: "org_1",
    projectId: "prj_1",
    environmentId: "env_1",
    connectionId: "pcn_1",
    destination: { repo: "api" },
    mapping: { kind: "wildcard" },
    removeOrphans: false,
    redeploy: false,
    state: "active",
    disabledReason: null,
    failureCount: 0,
    needsSync: false,
    lastAttemptAt: "2026-10-09T09:00:00Z",
    lastResult: "ok",
    createdAt: "2026-10-01T09:00:00Z",
    version: 1,
    updatedAt: null,
  } as SyncTarget;

  it("warns when its connection's token expires soon, and links to replacing it", async () => {
    await mount(<TargetCard org="acme" project="api" envName="production" target={target} connection={connection(inDays(3))} onChanged={() => {}} />);
    const line = byTestId("credential-expiry-snt_1");
    expect(text(line)).toContain("Token expires in 3 days");
    const link = line.findByType("a");
    expect(link.props.href).toBe("/o/acme/connections?replace=pcn_1");
  });

  it("stays quiet for a distant or unknown expiry", async () => {
    await mount(<TargetCard org="acme" project="api" envName="production" target={target} connection={connection(inDays(90))} onChanged={() => {}} />);
    expect(all("credential-expiry-snt_1")).toHaveLength(0);
  });
});

describe("New connection", () => {
  let created: unknown[];
  let answer: AccessCheck;
  beforeEach(() => {
    created = [];
    fake.api = {
      checkPlatformAccess: (async () => answer) as never,
      createPlatformConnection: (async (_org: string, input: unknown) => {
        created.push(input);
        return { name: "x" };
      }) as never,
    };
  });
  const fill = async () => {
    for (const [id, value] of [
      ["connection-base-identity", "acme"],
      ["connection-display-name", "GitHub"],
      ["connection-new-credential", "github_pat_short"],
    ]) {
      await act(async () => byTestId(id!).props.onChange({ target: { value } }));
    }
  };

  it("stops before saving a token that expires within two weeks, then saves anyway", async () => {
    answer = { status: "ok", where: "connection", message: "GitHub accepted the token.", credentialExpiresAt: inDays(3) };
    await mount(<NewConnectionDialog org="acme" adapters={["github-actions"]} initial="github-actions" onClose={() => {}} onCreated={() => {}} />);
    await fill();
    await act(async () => byTestId("save-connection").props.onClick());
    expect(created).toEqual([]);
    expect(text(byTestId("access-check-expiry"))).toContain("Token expires in 3 days");
    expect(text(byTestId("save-connection"))).toBe("Save anyway");
    await act(async () => byTestId("save-connection").props.onClick());
    expect(created).toHaveLength(1);
  });

  it("saves at once when the token expires later", async () => {
    answer = { status: "ok", where: "connection", message: "GitHub accepted the token.", credentialExpiresAt: inDays(60) };
    await mount(<NewConnectionDialog org="acme" adapters={["github-actions"]} initial="github-actions" onClose={() => {}} onCreated={() => {}} />);
    await fill();
    await act(async () => byTestId("save-connection").props.onClick());
    expect(created).toHaveLength(1);
  });
});

describe("Add integration Review", () => {
  let answer: AccessCheck;
  beforeEach(() => {
    fake.api = {
      checkPlatformAccess: (async () => answer) as never,
      listPlatformDestinations: (async () => ({ check: { status: "ok", where: "connection", message: "ok" }, items: [], truncated: false })) as never,
      effectiveConfiguration: (async () => ({ items: [] })) as never,
      getActiveContract: (async () => ({ contract: { items: [] } })) as never,
    };
  });
  const review = async (known: string | null) => {
    await mount(
      <AddIntegrationDialog
        open
        onClose={() => {}}
        onCreated={() => {}}
        org="acme"
        project="api"
        envName="production"
        adapters={["github-actions"]}
        connections={[connection(known)]}
      />,
    );
    await act(async () => byTestId("connection-option-pcn_1").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
    await act(async () => byTestId("dest-repo").props.onChange({ target: { value: "api" } }));
    await act(async () => byTestId("wizard-next").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
  };

  it("asks before attaching a connection already known to expire soon, when GitHub does not repeat the date", async () => {
    answer = { status: "ok", where: "destination", message: "The token can read the secrets of acme/api." };
    await review(inDays(3));
    expect(text(byTestId("confirm-integration"))).toBe("Create anyway");
    expect(text(byTestId("access-check-expiry"))).toContain("Token expires in 3 days");
  });

  it("goes by the date GitHub reports now over the one known before", async () => {
    answer = { status: "ok", where: "destination", message: "ok", credentialExpiresAt: inDays(60) };
    await review(inDays(3));
    expect(text(byTestId("confirm-integration"))).toBe("Create integration");
  });
});
