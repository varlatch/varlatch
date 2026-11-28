// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InstallationRelease, UpgradeRequestState } from "@varlatch/protocol";

/**
 * The one-click upgrade on a systemd host (ADR-0065 phase 2): the button
 * only when every pre-flight line passes, the helper's among them; the
 * confirmation with the downtime; the request (whose passkey step-up the
 * session's dialog handles); the progress, the cancel, "too late", and each
 * failure in words. And every dashboard's restart notice.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown>, capable: true }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", {
    setInterval: g.setInterval.bind(g),
    clearInterval: g.clearInterval.bind(g),
    setTimeout: g.setTimeout.bind(g),
    clearTimeout: g.clearTimeout.bind(g),
    location: { reload: () => {} },
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/features/projects/hooks", () => ({ useCapability: () => fake.capable }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, children, footer, title }: { open: boolean; children: React.ReactNode; footer?: React.ReactNode; title: React.ReactNode }) =>
    open ? (
      <div data-testid="dialog">
        <p>{title}</p>
        {children}
        {footer}
      </div>
    ) : null,
}));

import { ReleaseReport } from "../src/features/installation/ReleaseTab";
import { WebUpgrade } from "../src/features/installation/WebUpgrade";
import { failedStep, newRequestId, oneClickVersion, opened, outcomeText } from "../src/features/installation/webUpgradeStatus";
import { SignalStream, type EventSourceLike } from "../src/lib/sse";
import { SseContext } from "../src/lib/sseProvider";
import { RestartNotice } from "../src/components/RestartNotice";

const NOW = Date.now();
const ago = (ms: number) => new Date(NOW - ms).toISOString();
type Line = NonNullable<InstallationRelease["preflight"]>[number];
const pass = (id: Line["id"]): Line => ({ id, status: "pass", title: `${id} title`, detail: `${id} passes.`, remedy: null });
const IDS = ["release-check", "backup", "custody", "disk", "in-the-way", "rollback-safe", "helper"] as const;

const ready = (over: { deployment?: "systemd" | "image"; lines?: Line[]; previous?: string } = {}): InstallationRelease => ({
  running: "0.51.0",
  newer: true,
  latest: { version: "0.52.0", publishedAt: ago(86_400_000), url: "https://github.com/varlatch/varlatch/releases/tag/v0.52.0", repo: "varlatch/varlatch", releaseSet: true, checkedAt: ago(3600_000) },
  lastAttempt: { checkedAt: ago(3600_000), repo: "varlatch/varlatch", failed: null },
  unreadable: false,
  deployment: over.deployment ?? "systemd",
  schemaVersion: 7,
  target: {
    version: "0.52.0",
    checkedAt: ago(3600_000),
    failed: null,
    verified: { schemaVersion: 8, compatibleFrom: 7, rollbackSafe: true, previous: { version: over.previous ?? "0.51.0", schemaVersion: 7 }, endsRollbackWindow: false, image: "img" },
  },
  rollbackSafe: (over.previous ?? "0.51.0") === "0.51.0",
  preflight: over.lines ?? IDS.map(pass),
});

const state = (over: Partial<UpgradeRequestState> = {}): UpgradeRequestState => ({
  request: { id: "upr_" + "a".repeat(26), from: "0.51.0", version: "0.52.0", requestedBy: "idn_a", requestedAt: ago(10_000), expiresAt: ago(-590_000) },
  state: "waiting",
  reason: null,
  journalId: null,
  updatedAt: null,
  noAnswer: false,
  ...over,
});
const none: UpgradeRequestState = { request: null, state: "none", reason: null, journalId: null, updatedAt: null, noAnswer: false };

describe("one click is offered", () => {
  it("only on a systemd host with every line passing, the helper's among them, for one release's step", () => {
    expect(oneClickVersion(ready())).toBe("0.52.0");
    expect(oneClickVersion(ready({ deployment: "image" }))).toBeNull();
    expect(oneClickVersion(ready({ lines: IDS.filter((i) => i !== "helper").map(pass) }))).toBeNull();
    expect(oneClickVersion(ready({ lines: IDS.map((i) => (i === "helper" ? { ...pass(i), status: "fail" as const } : pass(i))) }))).toBeNull();
    expect(oneClickVersion(ready({ lines: IDS.map((i) => (i === "backup" ? { ...pass(i), status: "unknown" as const } : pass(i))) }))).toBeNull();
    expect(oneClickVersion(ready({ previous: "0.51.1" }))).toBeNull();
    expect(oneClickVersion({ ...ready(), newer: false })).toBeNull();
  });

  it("makes request ids the server takes", () => {
    const id = newRequestId();
    expect(id).toMatch(/^upr_[a-z2-7]{26}$/);
    expect(newRequestId()).not.toBe(id);
  });
});

describe("what the host did, in words", () => {
  it("says each outcome, and where it stopped", () => {
    expect(outcomeText(state({ state: "done" }))?.text).toContain("Upgraded to 0.52.0");
    expect(outcomeText(state({ state: "refused", reason: "undone" }))?.text).toContain("already undid an upgrade to this version");
    expect(outcomeText(state({ state: "refused", reason: "no-backup-destination" }))?.text).toContain("no backup destination is configured");
    expect(outcomeText(state({ state: "failed", reason: "backup" }))?.text).toContain("Varlatch never stopped");
    expect(outcomeText(state({ state: "failed", reason: "verification" }))?.text).toContain("did not verify");
    expect(outcomeText(state({ state: "undone", reason: "health" }))?.text).toContain("0.51.0 serves, on its database as it was");
    expect(outcomeText(state({ state: "interrupted" }))?.text).toContain("finishes or undoes it at its next start, or with sudo varlatch upgrade");
    expect(outcomeText(state({ state: "taken" }), true)?.text).toContain("Too late to cancel: the host has taken this request");
    expect(outcomeText(state({ state: "verifying" }))).toBeNull();
    expect(failedStep(state({ state: "failed", reason: "backup" }))).toBe(2);
    expect(failedStep(state({ state: "undone", reason: "health" }))).toBe(4);
    expect(failedStep(state({ state: "done" }))).toBe(-1);
    expect(opened("0.51.0", "0.52.0")).toBe(true);
    expect(opened("0.51.0", "0.51.0")).toBe(false);
  });
});

let root: ReactTestRenderer | undefined;
afterEach(async () => {
  await act(async () => root?.unmount());
  root = undefined;
  fake.api = {};
  fake.capable = true;
});
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const one = (id: string) => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return text(found[0]!);
};
const click = async (id: string) => act(async () => all(id)[0]!.props.onClick());
const flush = () => act(async () => new Promise((r) => setTimeout(r, 0)));

async function showTab(r: InstallationRelease) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ReleaseReport release={r} now={NOW} oneClick={<WebUpgrade release={r} />} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await flush();
}

describe("the Release tab's one click", () => {
  it("asks, with the downtime, then files the request and follows it", async () => {
    const requests: unknown[][] = [];
    fake.api = {
      getUpgradeRequest: async () => none,
      requestUpgrade: async (...args: never[]) => (requests.push(args), state()),
      cancelUpgradeRequest: async () => ({ ...state({ state: "cancelled" }), cancelled: true }),
    };
    await showTab(ready());
    expect(one("web-upgrade-button")).toBe("Upgrade to 0.52.0");
    expect(all("release-upgrade-command")).toHaveLength(1); // the commands stay
    await click("web-upgrade-button");
    expect(one("web-upgrade-downtime")).toContain("unavailable for about a minute");
    expect(one("web-upgrade-confirm-steps")).toContain("delivers it to your backup destination and checks the delivered copy");
    await click("web-upgrade-confirm-button");
    await flush();
    expect(requests).toHaveLength(1);
    expect(requests[0]![0]).toBe("0.52.0");
    expect(String(requests[0]![1])).toMatch(/^upr_[a-z2-7]{26}$/);
    expect(all("web-upgrade-progress")[0]!.props["data-state"]).toBe("waiting");
    await click("web-upgrade-cancel");
    await flush();
    expect(one("web-upgrade-outcome")).toContain("Cancelled before the host took it");
  });

  it("says too late when the host had taken it", async () => {
    fake.api = {
      getUpgradeRequest: async () => state(),
      cancelUpgradeRequest: async () => ({ ...state({ state: "taken" }), cancelled: false }),
    };
    await showTab(ready());
    await click("web-upgrade-cancel");
    await flush();
    expect(one("web-upgrade-outcome")).toContain("Too late to cancel");
    expect(all("web-upgrade-cancel")).toHaveLength(0);
  });

  it("shows the host's steps, and when it does not answer", async () => {
    fake.api = { getUpgradeRequest: async () => state({ state: "backing-up", journalId: "0123456789abcdef", updatedAt: ago(5000) }) };
    await showTab(ready());
    expect(all("web-upgrade-step-0")[0]!.props["data-done"]).toBe(true);
    expect(all("web-upgrade-step-1")[0]!.props["data-done"]).toBe(true);
    expect(all("web-upgrade-step-2")[0]!.props["data-done"]).toBe(false);
    expect(all("web-upgrade-cancel")).toHaveLength(0);
    await act(async () => root?.unmount());
    fake.api = { getUpgradeRequest: async () => state({ noAnswer: true }) };
    await showTab(ready());
    expect(one("web-upgrade-no-answer")).toContain("sudo systemctl status varlatch-upgrade.path varlatch-upgrade.service");
  });

  it("shows a failure with what it changed", async () => {
    fake.api = { getUpgradeRequest: async () => state({ state: "undone", reason: "health", updatedAt: ago(60_000) }) };
    await showTab(ready());
    expect(one("web-upgrade-outcome")).toContain("0.51.0 serves");
    expect(all("web-upgrade-step-4")[0]!.props["data-done"]).toBe(false);
  });

  it("shows no button when a line fails, or without the capability, and the commands stay", async () => {
    fake.api = { getUpgradeRequest: async () => none };
    await showTab(ready({ lines: IDS.map((i) => (i === "helper" ? { ...pass(i), status: "fail" as const, remedy: "Install it" } : pass(i))) }));
    expect(all("web-upgrade-button")).toHaveLength(0);
    expect(one("preflight-helper-remedy")).toContain("Upgrading from the web app");
    expect(one("release-upgrade-command")).toBe("sudo varlatch upgrade 0.52.0");
    await act(async () => root?.unmount());
    fake.capable = false;
    await showTab(ready());
    expect(all("web-upgrade-button")).toHaveLength(0);
  });
});

class FakeSource implements EventSourceLike {
  onerror: ((event: Event) => void) | null = null;
  private listeners = new Map<string, ((e: MessageEvent) => void)[]>();
  addEventListener(type: string, listener: (e: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  close() {}
  emit(type: string, data: unknown) {
    for (const l of this.listeners.get(type) ?? []) l({ data: JSON.stringify(data) } as MessageEvent);
  }
}

describe("every dashboard's restart notice", () => {
  it("shows while the host restarts Varlatch, and goes with the next stream", async () => {
    const sources: FakeSource[] = [];
    const stream = new SignalStream({
      open: () => {
        const s = new FakeSource();
        sources.push(s);
        return s;
      },
      setTimer: () => 0,
      clearTimer: () => {},
    });
    stream.start();
    await act(async () => {
      root = create(
        <SseContext.Provider value={stream}>
          <RestartNotice />
        </SseContext.Provider>,
      );
    });
    expect(all("restart-notice")).toHaveLength(0);
    await act(async () => sources[0]!.emit("ready", { identityId: "idn_a" }));
    await act(async () => sources[0]!.emit("installation", { notice: "upgrade-restarting", version: "0.52.0" }));
    expect(one("restart-notice")).toContain("Varlatch is restarting for an upgrade to 0.52.0.");
    await act(async () => sources[0]!.emit("installation", { notice: null }));
    expect(all("restart-notice")).toHaveLength(0);
    await act(async () => sources[0]!.emit("installation", { notice: "upgrade-restarting", version: "0.52.0" }));
    // The server back: the stream's ready, and no notice stands.
    await act(async () => sources[0]!.emit("ready", { identityId: "idn_a" }));
    expect(all("restart-notice")).toHaveLength(0);
    stream.stop();
  });
});
