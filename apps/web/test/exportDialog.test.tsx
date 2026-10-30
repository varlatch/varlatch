// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EffectiveConfiguration, Environment } from "@varlatch/protocol";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", { setTimeout: g.setTimeout.bind(g), clearTimeout: g.clearTimeout.bind(g) });
});
const effectiveConfiguration = vi.fn();
const discloseSecrets = vi.fn();
const api = { effectiveConfiguration, discloseSecrets };
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => String(err) }));
// A server that accepts the export purpose (ADR-0053).
vi.mock("../src/features/projects/hooks", () => ({ useCapability: (c: string) => c === "disclosure.purpose.export" }));
// Rendered only while open.
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
import { ExportDialog } from "../src/features/values/TransferDialogs";

/**
 * A value no `.env` line carries safely to every loader is left out of the
 * downloaded file, and the dialog names it: before the download for plain
 * values, after it for secrets, whose values it only learns by disclosing.
 */

const env = { id: "env_dev", projectId: "prj_api", name: "development", kind: "shared", tier: "development", createdAt: "2026-10-01T00:00:00Z" } as Environment;
const config = (items: EffectiveConfiguration["items"]) => ({ environmentId: "env_dev", items }) as EffectiveConfiguration;
const plain = (name: string, value: string) => ({ name, sensitive: false, source: "self", versionId: `v_${name}`, value });
const secret = (name: string) => ({ name, sensitive: true, source: "self", versionId: `v_${name}`, value: null });

let root: ReactTestRenderer | undefined;
let onClose: ReturnType<typeof vi.fn>;
const blobs: Blob[] = [];
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string) => {
  const found = all(id);
  expect(found).toHaveLength(1);
  return found[0] as ReactTestInstance;
};
const text = (node: ReactTestInstance): string =>
  node.children.map((c) => (typeof c === "string" ? c : text(c))).join("");

async function open() {
  onClose = vi.fn();
  await act(async () => {
    root = create(<ExportDialog org="acme" project="api" env={env} onClose={onClose} />);
  });
}
async function download() {
  await act(async () => one("export-download").props.onClick());
  return blobs.length ? await (blobs.at(-1) as Blob).text() : "";
}

beforeEach(() => {
  effectiveConfiguration.mockReset();
  discloseSecrets.mockReset();
  blobs.length = 0;
  vi.stubGlobal("document", { createElement: () => ({ click() {}, remove() {} }), body: { append() {} } });
  vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
    blobs.push(blob as Blob);
    return "blob:export";
  });
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
  vi.restoreAllMocks();
});

describe("export of values no .env line carries safely", () => {
  it("names plain values before the download, leaves them out, and stays open to say so", async () => {
    effectiveConfiguration.mockResolvedValue(config([plain("API_URL", "https://api"), plain("GREETING", "it's $HOME")]));
    await open();
    expect(text(one("export-copy-notice"))).toContain("copy outside Varlatch");
    expect(text(one("export-unwritable"))).toContain("GREETING");
    const file = await download();
    expect(file).toContain("API_URL=https://api");
    expect(file).toContain("# GREETING: not written");
    expect(file).not.toContain("$HOME");
    expect(onClose).not.toHaveBeenCalled();
    expect(text(one("export-not-written"))).toContain("GREETING");
    expect(all("export-download")).toHaveLength(0);
    await act(async () => one("export-close").props.onClick());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("names a disclosed secret it left out only after the download", async () => {
    effectiveConfiguration.mockResolvedValue(config([plain("API_URL", "https://api"), secret("API_KEY"), secret("TOKEN")]));
    discloseSecrets.mockResolvedValue({
      items: [
        { name: "API_KEY", value: "synthetic-key" },
        { name: "TOKEN", value: "synthetic$(id)" },
      ],
      withheld: [],
    });
    await open();
    expect(all("export-unwritable")).toHaveLength(0);
    await act(async () => one("export-include-secrets").props.onChange({ target: { checked: true } }));
    const file = await download();
    expect(file).toContain("API_KEY=synthetic-key");
    expect(file).toContain("# TOKEN: not written");
    // Both reads say they were made for an export.
    expect(effectiveConfiguration).toHaveBeenCalledWith("acme", "api", "development", { includeValues: true, purpose: "export" });
    expect(discloseSecrets.mock.calls[0]?.[3]).toMatchObject({ purpose: "export" });
    expect(file).not.toContain("$(id)");
    expect(text(one("export-not-written"))).toContain("TOKEN");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes after a download that wrote every value", async () => {
    effectiveConfiguration.mockResolvedValue(config([plain("API_URL", "https://api"), plain("NAME", "two words")]));
    await open();
    expect(all("export-unwritable")).toHaveLength(0);
    const file = await download();
    expect(file).toContain("NAME='two words'");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
