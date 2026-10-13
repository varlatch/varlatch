// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Environment, Project, Requirement } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * The requirement editor saves every field, only after a review that names
 * the scope and what may loosen, and a newer version (refused by the server
 * or seen live) discards that review and its confirmation.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", { setInterval: g.setInterval.bind(g), clearInterval: g.clearInterval.bind(g), setTimeout: g.setTimeout.bind(g), clearTimeout: g.clearTimeout.bind(g) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
// Rendered only while open, so a test sees the review close.
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

import { RequirementEditor } from "../src/features/access/RequirementEditor";
import type { Names } from "../src/features/access/model";

const project = { id: "prj_api", slug: "api", name: "API" } as Project;
const environments = [
  { id: "env_prod", projectId: "prj_api", name: "production", kind: "standard", tier: "production", parentEnvironmentId: null, createdAt: "2026-10-01T00:00:00Z" },
] as Environment[];
const names: Names = { project: (id) => (id === project.id ? project : undefined), environment: (id) => environments.find((e) => e.id === id), team: () => undefined };
const base: Requirement = {
  id: "req_1",
  kind: "tailnet",
  target: { kind: "environments", environmentIds: ["env_prod", "env_gone"] },
  selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL"], tags: ["tag:prod"], users: ["alice@example.com"] },
  version: 7,
  updatedAt: null,
};

const list = (req: Requirement) => vi.fn().mockResolvedValue({ items: [req], nextCursor: null });
const conflict = () => new VarlatchApiError(409, { code: "VERSION_CONFLICT", message: "Requirement was modified concurrently; reload and retry", requestId: "r1" });

let root: ReactTestRenderer;
const client = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });
let qc: QueryClient;
const ui = (current: Requirement | undefined, onDone = () => {}) => (
  <QueryClientProvider client={qc}>
    <MemoryRouter>
      <RequirementEditor org="acme" base={base} current={current} environments={environments} names={names} onDone={onDone} onCancel={() => {}} />
    </MemoryRouter>
  </QueryClientProvider>
);
async function mount(current: Requirement | undefined = base, onDone = () => {}) {
  qc = client();
  await act(async () => {
    root = create(ui(current, onDone));
  });
}
afterEach(async () => {
  await act(async () => root?.unmount());
});
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const form = () => root.root.find((n) => n.type === "form");
const flush = async () => {
  for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
};
async function addEntry(kind: "tags" | "nodes" | "users", value: string) {
  await act(async () => one(`req-${kind}-input`).props.onChange({ target: { value } }));
  await act(async () => one(`req-${kind}-input`).props.onKeyDown({ key: "Enter", preventDefault() {} }));
}
async function review() {
  await act(async () => form().props.onSubmit({ preventDefault() {} }));
}
async function confirm() {
  await act(async () => one("save-requirement-req_1").props.onClick());
  await flush();
}

describe("requirement editor", () => {
  it("offers no review before anything changes", async () => {
    fake.api = { updateRequirement: vi.fn(), listRequirements: list(base) };
    await mount();
    expect(one("review-requirement-req_1").props.disabled).toBe(true);
  });

  it("saves every field, only after a review naming the scope and what may loosen", async () => {
    const done = vi.fn();
    fake.api = { updateRequirement: vi.fn().mockResolvedValue({}), listRequirements: list(base) };
    await mount(base, done);
    await addEntry("tags", "tag:ci");
    await review();
    const dialog = text(one("requirement-review"));
    expect(dialog).toContain("This change may let more devices read values");
    expect(dialog).toContain("Applies to api / production (and environments derived from it), environment env_gone.");
    expect(text(one("review-loosens"))).toContain("Devices tagged tag:ci on example.ts.net can now read values in");
    expect(text(one("review-before"))).not.toContain("tag:ci");
    expect(text(one("review-after"))).toContain("tag tag:ci");
    expect(text(one("save-requirement-req_1"))).toBe("Loosen and save");
    expect(fake.api.updateRequirement).not.toHaveBeenCalled();
    await confirm();
    expect(fake.api.updateRequirement).toHaveBeenCalledWith("acme", "req_1", {
      expectedVersion: 7,
      target: { kind: "environments", environmentIds: ["env_prod", "env_gone"] },
      selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL"], tags: ["tag:prod", "tag:ci"], users: ["alice@example.com"] },
    });
    expect(done).toHaveBeenCalledOnce();
  });

  it("a tightening-only change is reviewed too, with a plain Save and the lockout warning", async () => {
    fake.api = { updateRequirement: vi.fn().mockResolvedValue({}), listRequirements: list(base) };
    await mount();
    await act(async () => one("remove-nodes-nAbc123CNTRL").props.onClick());
    await review();
    expect(text(one("requirement-review"))).toContain("Review this change");
    expect(all("review-loosens")).toHaveLength(0);
    expect(text(one("review-tightens"))).toContain("may be locked out");
    expect(text(one("save-requirement-req_1"))).toBe("Save");
  });

  it("VERSION_CONFLICT discards the review and its confirmation, and starting over loads the current version", async () => {
    fake.api = { updateRequirement: vi.fn().mockRejectedValue(conflict()), listRequirements: list(base) };
    await mount();
    await addEntry("tags", "tag:ci");
    await review();
    await confirm();
    expect(fake.api.updateRequirement).toHaveBeenCalledOnce();
    expect(all("requirement-review")).toHaveLength(0);
    expect(text(one("requirement-conflict"))).toContain("changed while you were editing");
    expect(one("review-requirement-req_1").props.disabled).toBe(true);
    // Submitting again does not reopen the old review.
    await review();
    expect(all("requirement-review")).toHaveLength(0);

    const newer: Requirement = { ...base, version: 8, selector: { ...base.selector, tags: ["tag:prod", "tag:other"] } };
    await flush();
    await act(async () => root.update(ui(newer)));
    await act(async () => one("requirement-start-over").props.onClick());
    expect(all("requirement-conflict")).toHaveLength(0);
    expect(one("req-tags").findAll((n) => n.props["data-entry"] !== undefined).map((n) => n.props["data-entry"])).toEqual(["tag:prod", "tag:other"]);
    // The next save is checked against the new version.
    fake.api.updateRequirement = vi.fn().mockResolvedValue({});
    await addEntry("tags", "tag:ci");
    await review();
    await confirm();
    expect(fake.api.updateRequirement.mock.calls[0]![2].expectedVersion).toBe(8);
  });

  it("review: after VERSION_CONFLICT, starting over needs an actually newer version, with a retry while it has not loaded", async () => {
    fake.api = { updateRequirement: vi.fn().mockRejectedValue(conflict()), listRequirements: list(base) };
    await mount();
    await addEntry("tags", "tag:ci");
    await review();
    await confirm();
    // The reload brought back the refused version: no way to start over from it.
    await flush();
    expect(all("requirement-start-over")).toHaveLength(0);
    expect(text(one("requirement-not-loaded"))).toContain("has not loaded yet");
    const calls = fake.api.listRequirements.mock.calls.length;
    await act(async () => one("requirement-retry-load").props.onClick());
    await flush();
    expect(fake.api.listRequirements.mock.calls.length).toBe(calls + 1);
    expect(all("requirement-conflict")).toHaveLength(1);
    // Once a newer version is there, starting over is offered and works.
    await act(async () => root.update(ui({ ...base, version: 8 })));
    await act(async () => one("requirement-start-over").props.onClick());
    expect(all("requirement-conflict")).toHaveLength(0);
  });

  it("review: a failed reload after VERSION_CONFLICT says so and offers a retry, never the old version", async () => {
    fake.api = { updateRequirement: vi.fn().mockRejectedValue(conflict()), listRequirements: list(base) };
    await mount();
    await flush();
    fake.api.listRequirements = vi.fn().mockRejectedValue(new Error("network down"));
    await addEntry("tags", "tag:ci");
    await review();
    await confirm();
    await flush();
    expect(text(one("requirement-not-loaded"))).toContain("network down");
    expect(all("requirement-start-over")).toHaveLength(0);
    expect(all("requirement-retry-load")).toHaveLength(1);
  });

  it("review: a tailnet changed only in case is reviewed as a change that may loosen, and sent exactly", async () => {
    fake.api = { updateRequirement: vi.fn().mockResolvedValue({}), listRequirements: list(base) };
    await mount();
    await act(async () => one("req-tailnet").props.onChange({ target: { value: "EXAMPLE.TS.NET" } }));
    expect(one("review-requirement-req_1").props.disabled).toBe(false);
    await review();
    expect(text(one("review-loosens"))).toContain("Tailscale compares tailnet names exactly");
    expect(text(one("save-requirement-req_1"))).toBe("Loosen and save");
    await confirm();
    expect(fake.api.updateRequirement.mock.calls[0]![2].selector.tailnet).toBe("EXAMPLE.TS.NET");
  });

  it("a newer version seen live closes an open review before anything is saved", async () => {
    fake.api = { updateRequirement: vi.fn().mockResolvedValue({}), listRequirements: list(base) };
    await mount();
    await addEntry("users", "bob@example.com");
    await review();
    expect(all("requirement-review")).toHaveLength(1);
    await act(async () => root.update(ui({ ...base, version: 8 })));
    expect(all("requirement-review")).toHaveLength(0);
    expect(all("requirement-conflict")).toHaveLength(1);
    expect(fake.api.updateRequirement).not.toHaveBeenCalled();
  });

  it("says so when the requirement is removed while editing, and saves nothing", async () => {
    fake.api = { updateRequirement: vi.fn(), listRequirements: list(base) };
    await mount();
    await act(async () => root.update(ui(undefined)));
    expect(text(one("requirement-removed"))).toContain("Nothing was saved");
    expect(one("review-requirement-req_1").props.disabled).toBe(true);
  });
});
