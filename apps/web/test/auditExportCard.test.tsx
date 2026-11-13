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

import { AuditExportCard, exportHealth, normalizedDestination, normalizedEndpoint, retentionLoosens } from "../src/features/security-controls/AuditExportCard";

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
let client: QueryClient;
const tree = (status: AuditExportStatus) => (
  <QueryClientProvider client={client}>
    <MemoryRouter>
      <AuditExportCard org="acme" status={status} />
    </MemoryRouter>
  </QueryClientProvider>
);
async function mount(status: AuditExportStatus) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root = create(tree(status));
  });
  await settle();
}
/** The page's query answering again, with a newer export. */
async function rerender(status: AuditExportStatus) {
  await act(async () => root.update(tree(status)));
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
    // No retention configured: nothing to say about reading it.
    expect(text(one("audit-export-key-flags"))).toBe("The keyobject read not determined");
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

describe("after the review of #147", () => {
  it("a check result goes once the export changes: a new destination, or a new key", async () => {
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-check");
    expect(all("audit-export-check-result")).toHaveLength(1);
    expect(one("audit-export-check-result").props.role).toBe("status");
    // Re-read with the same export: the result stays.
    await rerender({ enabled: true, export: exportOf() });
    expect(all("audit-export-check-result")).toHaveLength(1);
    // A new key (a new version, the same destination): gone.
    await rerender({ enabled: true, export: exportOf({ version: 4 }) });
    expect(all("audit-export-check-result")).toHaveLength(0);
    await click("audit-export-check");
    expect(all("audit-export-check-result")).toHaveLength(1);
    // A new destination: gone.
    await rerender({ enabled: true, export: exportOf({ version: 5, destination: { ...exportOf().destination, bucket: "acme-audit-2" } }) });
    expect(all("audit-export-check-result")).toHaveLength(0);
  });

  it("compares what the server would store: an endpoint's trailing slash or a prefix without one is no change, and needs no approval", async () => {
    expect(normalizedDestination({ endpoint: "https://S3.eu-central-1.amazonaws.com/", region: " eu-central-1 ", bucket: "acme-audit", prefix: "acme", pathStyle: false }))
      .toEqual({ endpoint: "https://s3.eu-central-1.amazonaws.com", region: "eu-central-1", bucket: "acme-audit", prefix: "acme/", pathStyle: false });
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-change");
    await type("audit-export-endpoint", "https://s3.eu-central-1.amazonaws.com/");
    await type("audit-export-prefix", "acme");
    expect(all("audit-export-needs-approval")).toHaveLength(0);
    expect(one("audit-export-save").props.disabled).toBe(true);
    // A real change still asks, and sends the stored form.
    await type("audit-export-prefix", "audit");
    expect(all("audit-export-needs-approval")).toHaveLength(1);
    await click("audit-export-save");
    expect(fake.api.changeAuditExport).toHaveBeenCalledWith("acme", { expectedVersion: 3, destination: { prefix: "audit/" } });
  });

  it("marks the lag as a live status and the checklist marks as images", async () => {
    await mount({ enabled: true, export: exportOf({ lag: { pending: 3, oldestPendingAt: iso(2 * 3_600_000) } }) });
    expect(one("audit-export-lag").props.role).toBe("status");
    const marks = root.root.findAll((n) => n.props["aria-label"] === "Done" || n.props["aria-label"] === "Varlatch cannot check this");
    expect(marks.length).toBeGreaterThan(0);
    for (const m of marks) expect(m.props.role).toBe("img");
  });

  it("a new export waits for its first heartbeat; an older one without any is flagged", async () => {
    await mount({ enabled: true, export: exportOf({ createdAt: iso(10 * 60_000), lastHeartbeatAt: null }) });
    expect(text(one("audit-export-heartbeat"))).toContain("waiting for the first heartbeat");
    expect(text(one("audit-export-heartbeat"))).not.toContain("none in the last two hours");
    await mount({ enabled: true, export: exportOf({ createdAt: iso(3 * 3_600_000), lastHeartbeatAt: null }) });
    expect(text(one("audit-export-heartbeat"))).toContain("none yet (none in the last two hours)");
  });

  it("the secret is on screen only while typed: gone after saving, and in no error", async () => {
    const SECRET = "the-secret-access-key-0001";
    fake.api.createAuditExport.mockRejectedValueOnce(new Error("The test write failed (S3 error AccessDenied, HTTP 403): the key may not do this"));
    await mount({ enabled: true, export: null });
    await click("audit-export-create");
    await type("audit-export-endpoint", "https://s3.eu-central-1.amazonaws.com");
    await type("audit-export-region", "eu-central-1");
    await type("audit-export-bucket", "acme-audit");
    await type("audit-export-key-id", "AKIA0001");
    await type("audit-export-secret", SECRET);
    // The test below is not vacuous: the typed secret is in the tree now.
    expect(JSON.stringify(root.toJSON())).toContain(SECRET);
    // A refused save: the error is shown, without the secret.
    await click("audit-export-save");
    expect(text(one("audit-export-save-error"))).toContain("The test write failed");
    expect(text(one("audit-export-save-error"))).not.toContain(SECRET);
    // A save that works: the dialog closes and the secret is nowhere.
    await click("audit-export-save");
    expect(fake.api.createAuditExport).toHaveBeenCalledTimes(2);
    expect(all("audit-export-dialog")).toHaveLength(0);
    expect(JSON.stringify(root.toJSON())).not.toContain(SECRET);
    // Opening the dialog again starts empty.
    await click("audit-export-create");
    expect(one("audit-export-secret").props.value).toBe("");
  });
});

describe("after the review of #150", () => {
  it("uses an endpoint's origin only where the server would accept it; otherwise sends what was typed", () => {
    expect(normalizedEndpoint(" https://S3.eu-central-1.amazonaws.com/ ")).toBe("https://s3.eu-central-1.amazonaws.com");
    expect(normalizedEndpoint("http://127.0.0.1:9000")).toBe("http://127.0.0.1:9000");
    // The server refuses these; its message must reach the person, unchanged.
    for (const typed of ["https://u:p@s3.example.com", "https://s3.example.com/x", "https://s3.example.com/?q=1", "https://s3.example.com/#f", "localhost:9000", "ftp://s3.example.com", "not a url"]) {
      expect(normalizedEndpoint(typed), typed).toBe(typed);
    }
  });

  it("the change dialog sends an endpoint it cannot normalize as typed, so the server's refusal is shown", async () => {
    fake.api.changeAuditExport.mockRejectedValueOnce(new Error("endpoint: must not carry user info"));
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-change");
    await type("audit-export-endpoint", "https://u:p@s3.eu-central-1.amazonaws.com");
    expect(all("audit-export-needs-approval")).toHaveLength(1);
    await click("audit-export-save");
    expect(fake.api.changeAuditExport).toHaveBeenCalledWith("acme", { expectedVersion: 3, destination: { endpoint: "https://u:p@s3.eu-central-1.amazonaws.com" } });
    expect(text(one("audit-export-save-error"))).toContain("must not carry user info");
    await type("audit-export-endpoint", "localhost:9000");
    await click("audit-export-save");
    expect(fake.api.changeAuditExport).toHaveBeenLastCalledWith("acme", { expectedVersion: 3, destination: { endpoint: "localhost:9000" } });
  });

  it("waits for a first heartbeat only while the export is active", async () => {
    await mount({ enabled: true, export: exportOf({ state: "draining", drainDeadline: "2026-12-13T10:00:00.000Z", createdAt: iso(10 * 60_000), lastHeartbeatAt: null }) });
    expect(text(one("audit-export-heartbeat"))).not.toContain("waiting for the first heartbeat");
  });

  it("says what the key may read about retention only when retention is configured", async () => {
    await mount({ enabled: true, export: exportOf({ retention: null, objectLock: "not-set", keyCanRead: true, retentionReadable: null }) });
    expect(text(one("audit-export-key-flags"))).toBe("The keycan read objects");
    await mount({ enabled: true, export: exportOf({ keyCanRead: true, retentionReadable: null }) });
    expect(text(one("audit-export-key-flags"))).toBe("The keycan read objects, retention read not determined");
  });

  it("announces a failed check as an alert", async () => {
    fake.api.checkAuditExport.mockResolvedValueOnce({ ok: false, message: "This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)", conditionalCreation: false, objectLock: null, keyCanRead: null, retentionReadable: null });
    await mount({ enabled: true, export: exportOf() });
    await click("audit-export-check");
    expect(one("audit-export-check-result").props.role).toBe("alert");
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
