// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditExport, AuditExportStatus } from "@varlatch/sdk";

/**
 * The audit export on the Security page (ADR-0056 Decision 11): what an
 * export shows (health, destination, retention and Object Lock, the
 * heartbeat, what the key may read, a checklist), the states that need a
 * person (stopped by the host, failing, behind, stopped on a conflict or a
 * format, draining after a deletion), and the flows: set up with a check,
 * change (saying when it needs an approval), a new key, removal named
 * again, the check of the live destination. The secret is never shown.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  confirm: vi.fn(),
  toasts: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, identityId: "idn_ada" }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({ success: (t: string) => fake.toasts.push(t), error: (t: string) => fake.toasts.push(t) }),
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, title, children, footer, "data-testid": id }: Record<string, unknown> & { open: boolean }) =>
    open ? (
      <div data-testid={id as string}>
        <h2>{title as React.ReactNode}</h2>
        {children as React.ReactNode}
        <footer>{footer as React.ReactNode}</footer>
      </div>
    ) : null,
  useConfirm: () => fake.confirm,
}));

import { AuditExportCard, exportHealth, retentionLoosens } from "../src/features/security-controls/AuditExportCard";

const NOW = Date.now();
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function exportOf(over: Partial<AuditExport> = {}): AuditExport {
  return {
    id: "aex_1",
    organizationId: "org_acme",
    destination: { endpoint: "https://s3.eu-central-1.amazonaws.com", region: "eu-central-1", bucket: "acme-audit", prefix: "acme/", pathStyle: false },
    retention: { mode: "compliance", days: 400 },
    state: "active",
    streamId: "aes_1",
    cursor: "42",
    version: 3,
    lastAttemptAt: iso(60_000),
    lastSuccessAt: iso(60_000),
    lastHeartbeatAt: iso(20 * 60_000),
    lastError: null,
    failingSince: null,
    keyCanRead: false,
    retentionReadable: true,
    stoppedReason: null,
    conditionalCheckedAt: iso(86_400_000),
    lockVerified: true,
    drainDeadline: null,
    createdBy: "idn_ada",
    createdAt: iso(86_400_000),
    removedAt: null,
    lag: { pending: 0, oldestPendingAt: null },
    objectLock: "verified",
    unsupportedPlanFormat: null,
    ...over,
  };
}

let root: ReactTestRenderer;
async function mount(status: AuditExportStatus) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AuditExportCard org="acme" status={status} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}
const settle = async () => {
  for (let i = 0; i < 5; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string) => {
  const found = all(id);
  expect(found, id).toHaveLength(1);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const click = async (id: string) => {
  await act(async () => one(id).props.onClick());
  await settle();
};
const type = async (id: string, value: string) => {
  await act(async () => one(id).props.onChange({ target: { value } }));
};

beforeEach(() => {
  fake.toasts = [];
  fake.confirm.mockReset();
  fake.api = {
    createAuditExport: vi.fn(async () => exportOf({ version: 1 })),
    changeAuditExport: vi.fn(async () => ({ export: exportOf({ version: 4 }), changed: true, loosened: true })),
    replaceAuditExportCredential: vi.fn(async () => exportOf({ version: 4 })),
    removeAuditExport: vi.fn(async () => exportOf({ state: "removed", lag: null })),
    checkAuditExport: vi.fn(async () => ({ ok: true, message: null, conditionalCreation: true, objectLock: "verified", keyCanRead: false, retentionReadable: true })),
  };
});

describe("a live export", () => {
  it("shows its health, destination, retention, heartbeat and what the key may read, never the key", async () => {
    await mount({ enabled: true, export: exportOf() });
    expect(text(one("audit-export-health"))).toBe("Delivering");
    expect(text(one("audit-export-destination"))).toContain("s3.eu-central-1.amazonaws.com, bucket acme-audit, prefix acme/");
    expect(text(one("audit-export-retention"))).toContain("compliance, 400 days; Object Lock verified");
    expect(text(one("audit-export-heartbeat"))).toContain("last at");
    expect(text(one("audit-export-heartbeat"))).not.toContain("none in the last two hours");
    expect(text(one("audit-export-key-flags"))).toBe("The keywrite-only, can read retention");
    const checklist = text(one("audit-export-checklist"));
    expect(checklist).toContain("Compliance retention for at least 400 days");
    expect(checklist).toContain("an account the host operator does not control");
    expect(checklist).toContain("watching the heartbeat");
    expect(JSON.stringify(root.toJSON())).not.toContain("secret");
  });

  it("says when it is behind, failing, has no recent heartbeat, or has no retention", async () => {
    await mount({
      enabled: true,
      export: exportOf({
        retention: null,
        objectLock: "not-set",
        lastHeartbeatAt: iso(3 * 3_600_000),
        lastError: "Upload failed (S3 error AccessDenied, HTTP 403): the key may not do this; check that it can access this bucket",
        failingSince: iso(20 * 60_000),
        lag: { pending: 12, oldestPendingAt: iso(2 * 3_600_000) },
        keyCanRead: null,
        retentionReadable: null,
      }),
    });
    expect(text(one("audit-export-health"))).toBe("Failing");
    expect(text(one("audit-export-error"))).toContain("Upload failed (S3 error AccessDenied, HTTP 403)");
    expect(text(one("audit-export-lag"))).toContain("over an hour ago");
    expect(text(one("audit-export-heartbeat"))).toContain("none in the last two hours");
    expect(text(one("audit-export-retention"))).toBe("Retentionnone; no retention; versioning not verified");
    expect(text(one("audit-export-key-flags"))).toBe("The keyread access not determined");
  });

  it("names a stop that needs a person: an object conflict, a format this release cannot upload", async () => {
    await mount({ enabled: true, export: exportOf({ stoppedReason: "object_conflict", unsupportedPlanFormat: 2 }) });
    expect(text(one("audit-export-health"))).toBe("Stopped");
    expect(text(one("audit-export-conflict"))).toContain("Nothing was overwritten");
    expect(text(one("audit-export-format"))).toContain("varlatchd admin audit-export discard-plan");
  });

  it("while draining after the deletion: the deadline, and no changes offered", async () => {
    await mount({ enabled: true, export: exportOf({ state: "draining", drainDeadline: "2026-12-13T10:00:00.000Z" }) });
    expect(text(one("audit-export-draining"))).toContain("at the latest until");
    expect(all("audit-export-change")).toHaveLength(0);
    expect(all("audit-export-remove")).toHaveLength(0);
  });

  it("stopped by the host operator: said, changes disabled, removal still possible", async () => {
    await mount({ enabled: false, export: exportOf() });
    expect(text(one("audit-export-off"))).toContain("VARLATCH_AUDIT_EXPORT=off");
    expect(text(one("audit-export-health"))).toBe("Stopped by the host operator");
    for (const id of ["audit-export-check", "audit-export-change", "audit-export-key"]) expect(one(id).props.disabled, id).toBe(true);
    expect(one("audit-export-remove").props.disabled).not.toBe(true);
  });

  it("checks its own destination with the stored key, sending no key", async () => {
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-check");
    expect(fake.api.checkAuditExport).toHaveBeenCalledWith("acme", { destination: exportOf().destination, retention: { mode: "compliance", days: 400 } });
    expect(text(one("audit-export-check-result"))).toContain("passed the check");
  });

  it("removes only after the organization is named again", async () => {
    await mount({ enabled: true, export: exportOf() });
    fake.confirm.mockResolvedValue(false);
    await click("audit-export-remove");
    const asked = fake.confirm.mock.calls[0]![0] as { typeToConfirm: string; consequences: { text: string }[]; tone: string };
    expect(asked).toMatchObject({ typeToConfirm: "acme", tone: "danger" });
    expect(asked.consequences.map((c) => c.text).join(" ")).toContain("What it delivered stays in acme-audit");
    expect(fake.api.removeAuditExport).not.toHaveBeenCalled();
    fake.confirm.mockResolvedValue(true);
    await click("audit-export-remove");
    expect(fake.api.removeAuditExport).toHaveBeenCalledWith("acme", 3);
    expect(fake.toasts).toEqual(["Audit export removed"]);
  });

  it("a change says when it needs an approval, and sends only what changed", async () => {
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-change");
    expect(all("audit-export-needs-approval")).toHaveLength(0);
    expect(one("audit-export-save").props.disabled).toBe(true);
    // Lengthening: no approval.
    await type("audit-export-days", "500");
    expect(all("audit-export-needs-approval")).toHaveLength(0);
    expect(text(one("audit-export-save"))).toBe("Save");
    // Shortening: an approval.
    await type("audit-export-days", "30");
    expect(text(one("audit-export-needs-approval"))).toContain("A shorter or weaker retention needs your approval");
    expect(text(one("audit-export-save"))).toBe("Approve and save…");
    await type("audit-export-days", "400");
    await type("audit-export-bucket", "acme-audit-2");
    expect(text(one("audit-export-needs-approval"))).toContain("A new destination needs your approval");
    await click("audit-export-save");
    expect(fake.api.changeAuditExport).toHaveBeenCalledWith("acme", { expectedVersion: 3, destination: { bucket: "acme-audit-2" } });
    expect(fake.toasts).toEqual(["Audit export changed"]);
  });

  it("a new key goes in a password field and is sent once", async () => {
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-key");
    expect(one("audit-export-new-secret").props.type).toBe("password");
    expect(one("audit-export-key-save").props.disabled).toBe(true);
    await type("audit-export-new-key-id", "AKIA0002");
    await type("audit-export-new-secret", "new-secret-value");
    await click("audit-export-key-save");
    expect(fake.api.replaceAuditExportCredential).toHaveBeenCalledWith("acme", { expectedVersion: 3, credential: { accessKeyId: "AKIA0002", secretAccessKey: "new-secret-value" } });
    expect(all("audit-export-key-dialog")).toHaveLength(0);
  });
});

describe("no export", () => {
  it("says it is not set up; setting up checks first if asked, then creates with what was typed", async () => {
    await mount({ enabled: true, export: null });
    expect(text(one("audit-export-none"))).toContain("Not set up.");
    await click("audit-export-create");
    expect(one("audit-export-save").props.disabled).toBe(true);
    expect(one("audit-export-secret").props.type).toBe("password");
    await type("audit-export-endpoint", "https://s3.eu-central-1.amazonaws.com");
    await type("audit-export-region", "eu-central-1");
    await type("audit-export-bucket", "acme-audit");
    await type("audit-export-key-id", "AKIA0001");
    await type("audit-export-secret", "the-secret");
    expect(one("audit-export-save").props.disabled).toBe(false);
    await click("audit-export-dialog-check");
    const destination = { endpoint: "https://s3.eu-central-1.amazonaws.com", region: "eu-central-1", bucket: "acme-audit", prefix: "", pathStyle: false };
    expect(fake.api.checkAuditExport).toHaveBeenCalledWith("acme", {
      destination,
      retention: { mode: "compliance", days: 400 },
      credential: { accessKeyId: "AKIA0001", secretAccessKey: "the-secret" },
    });
    expect(text(one("audit-export-check-result"))).toContain("passed the check");
    await click("audit-export-save");
    expect(fake.api.createAuditExport).toHaveBeenCalledWith("acme", {
      destination,
      credential: { accessKeyId: "AKIA0001", secretAccessKey: "the-secret" },
      retention: { mode: "compliance", days: 400 },
      from: "beginning",
    });
    expect(fake.toasts).toEqual(["Audit export set up"]);
  });

  it("an ended export: says so; switched off: cannot be set up", async () => {
    await mount({ enabled: false, export: exportOf({ state: "removed", removedAt: "2026-11-12T10:00:00.000Z", lag: null }) });
    expect(text(one("audit-export-none"))).toContain("The last export was removed on");
    expect(one("audit-export-create").props.disabled).toBe(true);
    expect(text(one("audit-export-off"))).not.toContain("can still be removed");
  });
});

describe("the words", () => {
  it("classifies retention changes as the server does", () => {
    const r = (mode: "compliance" | "governance", days: number) => ({ mode, days });
    expect(retentionLoosens(null, r("governance", 1))).toBe(false);
    expect(retentionLoosens(r("governance", 10), r("compliance", 10))).toBe(false);
    expect(retentionLoosens(r("compliance", 10), r("governance", 10))).toBe(true);
    expect(retentionLoosens(r("compliance", 10), r("compliance", 9))).toBe(true);
    expect(retentionLoosens(r("compliance", 10), null)).toBe(true);
  });

  it("names the health", () => {
    expect(exportHealth(exportOf(), true, NOW).label).toBe("Delivering");
    expect(exportHealth(exportOf({ lag: { pending: 3, oldestPendingAt: iso(2 * 3_600_000) } }), true, NOW).label).toBe("Behind");
    expect(exportHealth(exportOf({ state: "completed" }), true, NOW).label).toBe("Completed");
    expect(exportHealth(exportOf({ state: "abandoned" }), true, NOW).label).toBe("Abandoned");
  });
});
