// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PlatformConnection, SyncTarget } from "@varlatch/protocol";

/**
 * Names Coolify resolves, and held names (ADR-0031 amendment 2026-10-22):
 * a held name is no failure, shows as held with its reason, and offers the
 * fix the note names; an application integration can list the names
 * Coolify resolves itself.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  useConfirm: () => async () => true,
}));

import { AddIntegrationDialog } from "../src/features/sync/AddIntegrationDialog";
import { TargetCard } from "../src/features/sync/TargetCard";
import { connectionHealth, noteText, noteWarns, targetOptions, targetStatus } from "../src/features/sync/status";

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

const coolify: PlatformConnection = {
  id: "pcn_1",
  organizationId: "org_1",
  platform: "coolify",
  baseIdentity: "https://coolify.example.com",
  name: "Coolify",
  createdAt: "2026-09-01T00:00:00Z",
  version: 1,
  updatedAt: null,
};

const target = (over: Partial<SyncTarget>): SyncTarget => ({
  id: "snt_1",
  organizationId: "org_1",
  projectId: "prj_1",
  environmentId: "env_1",
  connectionId: "pcn_1",
  destination: { applicationUuid: "app1", buildTime: "true" },
  mapping: { kind: "wildcard" },
  removeOrphans: false,
  redeploy: false,
  state: "active",
  disabledReason: null,
  failureCount: 0,
  needsSync: false,
  lastAttemptAt: "2026-10-22T09:00:00Z",
  lastResult: "converged",
  lastNotes: [],
  createdAt: "2026-10-01T09:00:00Z",
  version: 3,
  updatedAt: null,
  ...over,
});

const heldToken = { code: "held" as const, name: "GITHUB_TOKEN", reason: "Coolify replaces {{team.…}} with one of its shared variables, so it would deliver a different value", fix: "platform-expands" as const };
const heldQuote = { code: "held" as const, name: "QUOTED", reason: "Coolify writes values in single quotes without escaping" };

describe("held names in the status words", () => {
  it("never reads as in sync, and never as failing", () => {
    const s = targetStatus(target({ lastResult: "converged; held: GITHUB_TOKEN: Coolify replaces", lastNotes: [heldToken, heldQuote] }));
    expect(s).toMatchObject({ tone: "warn", label: "Values held", detail: "2 names not pushed", error: "GITHUB_TOKEN, QUOTED" });
    expect(targetStatus(target({ lastNotes: [heldToken, { code: "held-more", count: 3 }] })).error).toBe("GITHUB_TOKEN and 3 more");
    // Before 0.18.1's notes, the result alone still says so.
    expect(targetStatus(target({ lastNotes: null, lastResult: "ok; held: A: why" }))).toMatchObject({ label: "Values held", error: "A: why" });
    expect(targetStatus(target({ lastNotes: null, lastResult: "ok; held: A: why; redeploy failed (HTTP 500)" })).label).toBe("Redeploy failed");
  });

  it("keeps a connection whose targets hold names from looking healthy", () => {
    expect(connectionHealth([target({}), target({ id: "snt_2", lastNotes: [heldToken] })])).toMatchObject({ tone: "warn", label: "1 target holding values" });
    expect(connectionHealth([target({})]).label).toBe("Healthy");
  });

  it("puts held notes in words, as warnings", () => {
    expect(noteText(heldQuote)).toBe("QUOTED: not pushed. Coolify writes values in single quotes without escaping");
    expect(noteText({ code: "held-more", count: 4 })).toBe("4 more names not pushed");
    expect(noteText({ code: "held-more", count: 1 })).toBe("1 more name not pushed");
    expect(noteWarns(heldToken)).toBe(true);
  });

  it("lists the names Coolify resolves among the options", () => {
    expect(targetOptions(target({ destination: { applicationUuid: "app1", platformExpands: "GITHUB_TOKEN,VITE_BUILD_SHA" } }))).toEqual([
      "Coolify resolves GITHUB_TOKEN, VITE_BUILD_SHA",
    ]);
  });
});

describe("Integration card: a held name", () => {
  let updates: unknown[];
  beforeEach(() => {
    updates = [];
    fake.api = {
      updateSyncTarget: (async (...args: unknown[]) => {
        updates.push(args);
        return {};
      }) as never,
      getSyncTarget: (async () => ({ names: [] })) as never,
    };
  });

  it("offers to let Coolify resolve it only where that is the fix, keeping the other options", async () => {
    const t = target({ destination: { applicationUuid: "app1", buildTime: "true", platformExpands: "VITE_BUILD_SHA" }, lastNotes: [heldToken, heldQuote] });
    await mount(<TargetCard org="acme" project="api" envName="production" target={t} connection={coolify} onChanged={() => {}} />);
    const notes = text(byTestId("target-notes-snt_1"));
    expect(notes).toContain("GITHUB_TOKEN: not pushed.");
    expect(notes).toContain("QUOTED: not pushed.");
    expect(all("resolve-snt_1-QUOTED")).toHaveLength(0);
    await act(async () => byTestId("resolve-snt_1-GITHUB_TOKEN").props.onClick());
    expect(updates).toEqual([
      [
        "acme",
        "api",
        "production",
        "snt_1",
        { expectedVersion: 3, destination: { applicationUuid: "app1", buildTime: "true", platformExpands: "VITE_BUILD_SHA,GITHUB_TOKEN" } },
      ],
    ]);
  });
});

describe("Add integration: names Coolify resolves", () => {
  let created: { destination: Record<string, unknown> }[];
  beforeEach(() => {
    created = [];
    fake.api = {
      checkPlatformAccess: (async () => ({ status: "ok", where: "destination", message: "The token can read application web123." })) as never,
      listPlatformDestinations: (async () => ({
        check: { status: "ok", where: "connection", message: "The token's team has 1 applications." },
        items: [{ destination: { applicationUuid: "web123" }, label: "web", detail: "web.example.com" }],
        truncated: false,
      })) as never,
      effectiveConfiguration: (async () => ({ items: [{ name: "GITHUB_TOKEN", sensitive: true }] })) as never,
      getActiveContract: (async () => ({ contract: { items: [] } })) as never,
      createSyncTarget: (async (_o: string, _p: string, _e: string, input: { destination: Record<string, unknown> }) => {
        created.push(input);
        return {};
      }) as never,
    };
  });

  it("validates the names, says so in the review, and sends them", async () => {
    await mount(
      <AddIntegrationDialog open onClose={() => {}} onCreated={() => {}} org="acme" project="api" envName="production" adapters={["coolify"]} connections={[coolify]} />,
    );
    await act(async () => byTestId("connection-option-pcn_1").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
    await act(async () => byTestId("destination-option-web123").props.onClick());
    await act(async () => byTestId("dest-platform-expands").props.onChange({ target: { value: "GITHUB_TOKEN, 1BAD" } }));
    expect(byTestId("wizard-next").props.disabled).toBe(true);
    await act(async () => byTestId("dest-platform-expands").props.onChange({ target: { value: "GITHUB_TOKEN, VITE_BUILD_SHA GITHUB_TOKEN" } }));
    expect(byTestId("wizard-next").props.disabled).toBe(false);
    await act(async () => byTestId("wizard-next").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
    const review = text(byTestId("integration-review"));
    expect(review).toContain("Coolify resolves GITHUB_TOKEN, VITE_BUILD_SHA itself; every other value is stored as text.");
    await act(async () => byTestId("confirm-integration").props.onClick());
    expect(created).toEqual([expect.objectContaining({ destination: { applicationUuid: "web123", platformExpands: ["GITHUB_TOKEN", "VITE_BUILD_SHA"] } })]);
  });
});
