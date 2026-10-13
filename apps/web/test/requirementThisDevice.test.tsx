// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Environment, Project, Requirement } from "@varlatch/protocol";
import type { TailnetConnection } from "../src/lib/tailnetConnection";

/**
 * "This device" in the requirement editor adds only the node ID of a device
 * verified by a Connect answer newer than the click; a device on another
 * tailnet is not added, and the tailnet changes only through its own,
 * reviewed change. A new requirement's tailnet is a suggestion that never
 * replaces what the person typed.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  connection: { status: "unavailable" } as TailnetConnection,
  connect: (() => {}) as () => void,
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", { setInterval: g.setInterval.bind(g), clearInterval: g.clearInterval.bind(g), setTimeout: g.setTimeout.bind(g), clearTimeout: g.clearTimeout.bind(g) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/lib/tailnetConnection", async (original) => ({
  ...(await original<typeof import("../src/lib/tailnetConnection")>()),
  // Short, so the "no current answer" case runs in a test.
  PROBE_TIMEOUT_MS: 20,
  useTailnetConnection: () => ({ connection: fake.connection, connect: () => fake.connect(), client: null }),
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, children, footer, "data-testid": id }: Record<string, React.ReactNode> & { open: boolean; "data-testid"?: string }) =>
    open ? (
      <div data-testid={id}>
        <h2>{title}</h2>
        {children}
        {footer}
      </div>
    ) : null,
}));

import { RequirementEditor } from "../src/features/access/RequirementEditor";
import type { Names } from "../src/features/access/model";

const ENDPOINT = "https://varlatch.example.ts.net:8688";
const project = { id: "prj_api", slug: "api", name: "API" } as Project;
const environments = [
  { id: "env_prod", projectId: "prj_api", name: "production", kind: "standard", tier: "production", parentEnvironmentId: null, createdAt: "2026-10-01T00:00:00Z" },
] as Environment[];
const names: Names = { project: (id) => (id === project.id ? project : undefined), environment: (id) => environments.find((e) => e.id === id), team: () => undefined };
const base: Requirement = {
  id: "req_1",
  kind: "tailnet",
  target: { kind: "environments", environmentIds: ["env_prod"] },
  selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL"], tags: ["tag:runner"], users: ["alice@example.com"] },
  version: 3,
  updatedAt: null,
};
const device = { recognized: true, tailnet: "example.ts.net", nodeId: "nDev42CNTRL", nodeName: "laptop", tags: ["tag:x"], userLogin: "bob@example.com" };
const connectedAt = (checkedAt: number, d: Partial<typeof device> = {}): TailnetConnection => ({ status: "connected", endpoint: ENDPOINT, device: { ...device, ...d }, checkedAt });

let root: ReactTestRenderer;
let qc: QueryClient;
const ui = (props: { base?: Requirement }) => (
  <QueryClientProvider client={qc}>
    <MemoryRouter>
      <RequirementEditor org="acme" base={props.base} current={props.base} environments={environments} names={names} onDone={() => {}} onCancel={() => {}} />
    </MemoryRouter>
  </QueryClientProvider>
);
let props: { base?: Requirement } = {};
async function mount(p: { base?: Requirement }) {
  props = p;
  qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(ui(props));
  });
}
/** The connection changes, as the provider would publish it. */
async function connection(next: TailnetConnection) {
  fake.connection = next;
  await act(async () => root.update(ui(props)));
}
afterEach(async () => {
  await act(async () => root?.unmount());
  fake.connection = { status: "unavailable" };
});
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const entries = (kind: string) => one(`req-${kind}`).findAll((n) => n.props["data-entry"] !== undefined).map((n) => n.props["data-entry"] as string);
const tailnetInput = () => one("req-tailnet");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function clickThisDevice() {
  await act(async () => one("req-this-device").props.onClick());
}

describe('"This device"', () => {
  it("is not offered without a tailnet browser endpoint", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }) };
    await mount({ base });
    expect(all("req-this-device")).toHaveLength(0);
  });

  it("review: never uses an older answer; a current one adds only the verified node ID", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }), updateRequirement: vi.fn().mockResolvedValue({}) };
    fake.connect = vi.fn();
    fake.connection = connectedAt(Date.now() - 60_000);
    await mount({ base });
    await clickThisDevice();
    expect(fake.connect).toHaveBeenCalledOnce();
    // The connection is still the one from a minute ago: nothing is added from it.
    await connection(connectedAt(Date.now() - 60_000));
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    await connection({ status: "connecting", endpoint: ENDPOINT });
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    await connection(connectedAt(Date.now() + 1));
    expect(entries("nodes")).toEqual(["nAbc123CNTRL", "nDev42CNTRL"]);
    // Only the node ID: not the device's tags, not its user.
    expect(entries("tags")).toEqual(["tag:runner"]);
    expect(entries("users")).toEqual(["alice@example.com"]);
    expect(text(one("req-this-device-notice"))).toContain("Added this device, laptop (nDev42CNTRL)");
    // Adding a device loosens: it goes through the review and its confirmation.
    await act(async () => root.root.find((n) => n.type === "form").props.onSubmit({ preventDefault() {} }));
    expect(text(one("review-loosens"))).toContain("The device with node ID nDev42CNTRL");
    expect(text(one("save-requirement-req_1"))).toBe("Loosen and save");
  });

  it("review: a failed Connect adds nothing and says why", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }) };
    fake.connect = vi.fn();
    fake.connection = { status: "idle", endpoint: ENDPOINT };
    await mount({ base });
    await clickThisDevice();
    await connection({ status: "unreachable", endpoint: ENDPOINT, blockedByPolicy: false, checkedAt: Date.now() + 1 });
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    expect(text(one("req-this-device-notice"))).toContain("did not answer from this browser. Nothing was added.");
    await clickThisDevice();
    await connection({ status: "unrecognized", endpoint: ENDPOINT, reason: "shared", checkedAt: Date.now() + 1 });
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    expect(text(one("req-this-device-notice"))).toContain("shared devices are refused");
  });

  it("review: with no current answer in time, nothing is added, not even by a later answer", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }) };
    fake.connect = vi.fn();
    fake.connection = connectedAt(Date.now() - 60_000);
    await mount({ base });
    await clickThisDevice();
    await act(async () => sleep(1_100));
    expect(text(one("req-this-device-notice"))).toContain("No current answer");
    await connection(connectedAt(Date.now() + 1));
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
  });

  it("review: a device on another tailnet is not added, and the tailnet changes only by its own, reviewed change", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }) };
    fake.connect = vi.fn();
    fake.connection = { status: "idle", endpoint: ENDPOINT };
    await mount({ base });
    await clickThisDevice();
    await connection(connectedAt(Date.now() + 1, { tailnet: "other.ts.net" }));
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    expect(tailnetInput().props.value).toBe("example.ts.net");
    expect(text(one("req-this-device-notice"))).toContain("is on other.ts.net, but the requirement is for example.ts.net. Nothing was added.");
    // The explicit, separate change of the tailnet.
    await act(async () => one("req-use-device-tailnet").props.onClick());
    expect(tailnetInput().props.value).toBe("other.ts.net");
    expect(entries("nodes")).toEqual(["nAbc123CNTRL"]);
    await act(async () => root.root.find((n) => n.type === "form").props.onSubmit({ preventDefault() {} }));
    expect(text(one("review-loosens"))).toContain("Devices on other.ts.net that match it can now read values");
    expect(text(one("save-requirement-req_1"))).toBe("Loosen and save");
  });
});

describe("tailnet suggestion for a new requirement", () => {
  it("review: prefers the verified device, falls back to the endpoint host, and never replaces what was typed", async () => {
    fake.api = {};
    fake.connection = { status: "idle", endpoint: "https://varlatch.corp.ts.net:8688" };
    await mount({});
    expect(tailnetInput().props.value).toBe("corp.ts.net");
    expect(tailnetInput().props["data-suggested"]).toBe("endpoint");
    // A verified device replaces the endpoint's suggestion while nothing was typed.
    await connection(connectedAt(Date.now(), { tailnet: "example.ts.net" }));
    expect(tailnetInput().props.value).toBe("example.ts.net");
    expect(tailnetInput().props["data-suggested"]).toBe("device");
    // Once typed in, the field is the person's.
    await act(async () => tailnetInput().props.onChange({ target: { value: "mine.ts.net" } }));
    await connection(connectedAt(Date.now(), { tailnet: "elsewhere.ts.net" }));
    expect(tailnetInput().props.value).toBe("mine.ts.net");
    expect(tailnetInput().props["data-suggested"]).toBeUndefined();
    // Clearing it is input too.
    await act(async () => tailnetInput().props.onChange({ target: { value: "" } }));
    await connection({ status: "idle", endpoint: "https://varlatch.corp.ts.net:8688" });
    expect(tailnetInput().props.value).toBe("");
  });

  it("is never applied to an existing requirement", async () => {
    fake.api = { listRequirements: vi.fn().mockResolvedValue({ items: [base], nextCursor: null }) };
    fake.connection = connectedAt(Date.now(), { tailnet: "other.ts.net" });
    await mount({ base });
    expect(tailnetInput().props.value).toBe("example.ts.net");
    expect(tailnetInput().props["data-suggested"]).toBeUndefined();
  });
});
