// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PlatformConnection, SyncTarget } from "@varlatch/protocol";

/**
 * Coolify services (ADR-0031 amendment 2026-10-21): a destination is an
 * application or a service, whose variables reach all of its containers;
 * an integration card shows how the service's compose file uses the pushed
 * names.
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
import { noteText, targetDestination, targetOptions } from "../src/features/sync/status";

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
  destination: { serviceUuid: "svc123" },
  mapping: { kind: "wildcard" },
  removeOrphans: false,
  redeploy: false,
  state: "active",
  disabledReason: null,
  failureCount: 0,
  needsSync: false,
  lastAttemptAt: "2026-10-21T09:00:00Z",
  lastResult: "ok",
  lastNotes: null,
  createdAt: "2026-10-01T09:00:00Z",
  version: 1,
  updatedAt: null,
  ...over,
});

describe("Add integration: a Coolify service", () => {
  let created: { destination: Record<string, string>; redeploy: boolean }[];
  beforeEach(() => {
    created = [];
    fake.api = {
      checkPlatformAccess: (async () => ({
        status: "ok",
        where: "destination",
        message: "The token can manage the variables of service convex. Every variable reaches all of its containers (backend, postgres), and any added later.",
      })) as never,
      listPlatformDestinations: (async () => ({
        check: { status: "ok", where: "connection", message: "The token's team has 1 applications and 1 services." },
        items: [
          { destination: { serviceUuid: "svc123" }, label: "convex", detail: "service" },
          { destination: { applicationUuid: "web123" }, label: "web", detail: "web.example.com" },
        ],
        truncated: false,
      })) as never,
      effectiveConfiguration: (async () => ({ items: [{ name: "INSTANCE_SECRET", sensitive: true }] })) as never,
      getActiveContract: (async () => ({ contract: { items: [] } })) as never,
      createSyncTarget: (async (_org: string, _project: string, _env: string, input: { destination: Record<string, string>; redeploy: boolean }) => {
        created.push(input);
        return {};
      }) as never,
    };
  });

  it("takes a service from the picker, with no application options, says what a restart restarts, and creates it", async () => {
    await mount(
      <AddIntegrationDialog open onClose={() => {}} onCreated={() => {}} org="acme" project="api" envName="production" adapters={["coolify"]} connections={[coolify]} />,
    );
    await act(async () => byTestId("connection-option-pcn_1").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
    // An application by default; the service choice swaps the fields.
    expect(all("dest-app")).toHaveLength(1);
    await act(async () => byTestId("dest-kind-service").props.onClick());
    expect(all("dest-app")).toHaveLength(0);
    expect(all("dest-build-time")).toHaveLength(0);
    expect(text(byTestId("dest-service-scope"))).toContain("reach all of its containers");
    // The picker lists services only.
    expect(all("destination-option-web123")).toHaveLength(0);
    await act(async () => byTestId("destination-option-svc123").props.onClick());
    expect(byTestId("dest-service").props.value).toBe("svc123");
    // The checkbox's label is its parent's text.
    const redeployLabel = text(byTestId("redeploy").parent!);
    expect(redeployLabel).toContain("Restart the service after changes");
    expect(redeployLabel).toContain("its databases included");
    expect(all("dest-deploy-action")).toHaveLength(0);
    await act(async () => byTestId("redeploy").props.onChange({ target: { checked: true } }));
    // Still no deploy-or-restart choice: a service only restarts.
    expect(all("dest-deploy-action")).toHaveLength(0);

    await act(async () => byTestId("wizard-next").props.onClick());
    await act(async () => byTestId("wizard-next").props.onClick());
    const review = text(byTestId("integration-review"));
    expect(review).toContain("convex (svc123)");
    expect(review).toContain("Each value reaches every container of the service");
    expect(review).toContain("(backend, postgres)");
    await act(async () => byTestId("confirm-integration").props.onClick());
    expect(created).toEqual([expect.objectContaining({ destination: { serviceUuid: "svc123" }, redeploy: true })]);
  });
});

describe("Integration card: a Coolify service", () => {
  it("names the service, its restart, and the compose file's notes", async () => {
    const t = target({
      redeploy: true,
      lastNotes: [
        { code: "shadowed", name: "DATABASE_URL", containers: ["backend"] },
        { code: "usage-unchecked", reason: "Coolify did not return the service's compose file to this token (reading it takes its read:sensitive permission)" },
      ],
    });
    await mount(<TargetCard org="acme" project="api" envName="production" target={t} connection={coolify} onChanged={() => {}} />);
    const notes = text(byTestId("target-notes-snt_1"));
    expect(notes).toContain("DATABASE_URL: the compose file sets it in backend, which wins over the pushed value");
    expect(notes).toContain("Usage not checked: Coolify did not return the service's compose file");
    expect(text(root.root)).toContain("restarts the service after changes");
  });

  it("shows no notes block without notes", async () => {
    await mount(<TargetCard org="acme" project="api" envName="production" target={target({ lastNotes: [] })} connection={coolify} onChanged={() => {}} />);
    expect(all("target-notes-snt_1")).toHaveLength(0);
  });
});

describe("status words for services", () => {
  it("labels the destination and the restart", () => {
    expect(targetDestination(target({}), coolify)).toEqual({ primary: "svc123", qualifier: "service" });
    expect(targetOptions(target({ redeploy: true }))).toEqual(["restarts the service after changes"]);
    expect(targetOptions(target({ destination: { applicationUuid: "app1", deployAction: "restart" }, redeploy: true }))).toEqual(["restarts after changes"]);
  });

  it("puts every note code in words", () => {
    const cases: [Parameters<typeof noteText>[0], string][] = [
      [{ code: "shadowed", name: "A", containers: ["web", "db"] }, "A: the compose file sets it in web, db, which wins over the pushed value"],
      [{ code: "not-delivered", name: "A" }, "A: no container uses it"],
      [{ code: "unknown-form", name: "A", containers: ["web"] }, "A: used in web in a form Varlatch does not read"],
      [{ code: "generated-once", name: "SERVICE_PASSWORD_DB" }, "SERVICE_PASSWORD_DB: Coolify generated it once; a database may read it only on first start, so change it with care"],
      [{ code: "kept-by-platform", name: "PORT" }, "PORT: removed; Coolify may keep or re-create the name, and Varlatch does not delete it again"],
      [{ code: "usage-unchecked", reason: "why" }, "Usage not checked: why"],
    ];
    for (const [note, words] of cases) expect(noteText(note)).toBe(words);
  });
});
