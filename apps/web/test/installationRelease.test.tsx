// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InstallationRelease } from "@varlatch/protocol";

/**
 * Installation → Release (ADR-0049) shows what the host last found and how
 * to upgrade on the host. It reports what was checked and when, never "up to
 * date"; it names the repository checked, in the command too; and only
 * Installation Admins ask for it.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", {
    setInterval: g.setInterval.bind(g),
    clearInterval: g.clearInterval.bind(g),
    setTimeout: g.setTimeout.bind(g),
    clearTimeout: g.clearTimeout.bind(g),
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));

import { checkLines, lastFailure, releaseSummary, upgradeLines } from "../src/features/installation/releaseStatus";
import { ReleaseReport } from "../src/features/installation/ReleaseTab";
import { useInstallationRelease } from "../src/features/installation/releaseNotice";

const NOW = Date.parse("2026-10-22T12:00:00Z");
const DAY = 24 * 3600_000;
const ago = (ms: number) => new Date(NOW - ms).toISOString();

const release = (over: { newer?: boolean | null; checked?: number; repo?: string; releaseSet?: boolean; failed?: InstallationRelease["lastAttempt"] } = {}): InstallationRelease => {
  const repo = over.repo ?? "varlatch/varlatch";
  const newer = over.newer === undefined ? true : over.newer;
  return {
    running: "0.18.1",
    newer,
    latest: {
      version: newer ? "0.19.0" : "0.18.1",
      publishedAt: ago(2 * DAY),
      url: `https://github.com/${repo}/releases/tag/v0.19.0`,
      repo,
      releaseSet: over.releaseSet ?? true,
      checkedAt: ago(over.checked ?? 3600_000),
    },
    lastAttempt: over.failed ?? { checkedAt: ago(over.checked ?? 3600_000), repo, failed: null },
    unreadable: false,
  };
};
const none: InstallationRelease = { running: "0.18.1", newer: null, latest: null, lastAttempt: null, unreadable: false };

describe("releaseSummary", () => {
  it("says not checked, or unreadable, without a successful check", () => {
    expect(releaseSummary(none, NOW)).toMatchObject({ tone: "muted", headline: "Not checked" });
    expect(releaseSummary({ ...none, unreadable: true }, NOW)).toMatchObject({ tone: "muted", headline: "The check record is unreadable" });
  });

  it("names the newer release, however old the check that found it", () => {
    expect(releaseSummary(release(), NOW)).toMatchObject({ tone: "warn", headline: "0.19.0 is available", stale: false });
    expect(releaseSummary(release({ checked: 40 * DAY }), NOW)).toMatchObject({ tone: "warn", headline: "0.19.0 is available" });
  });

  it("reports none newer as of the check, never 'up to date', and not at all once the check is older than 14 days", () => {
    const fresh = releaseSummary(release({ newer: false, checked: 13 * DAY }), NOW);
    expect(fresh).toMatchObject({ tone: "ok", stale: false });
    expect(fresh.headline).toMatch(/^No newer release as of /);
    const stale = releaseSummary(release({ newer: false, checked: 15 * DAY }), NOW);
    expect(stale).toMatchObject({ tone: "muted", headline: "Not checked recently", stale: true });
    for (const s of [fresh, stale]) expect(`${s.headline} ${s.detail}`).not.toMatch(/up to date/i);
  });

  it("states a failed last attempt", () => {
    expect(lastFailure(release(), NOW)).toBeNull();
    expect(lastFailure(release({ failed: { checkedAt: ago(DAY), repo: "varlatch/varlatch", failed: "unreachable" } }), NOW)).toBe(
      "The last check, yesterday, failed: GitHub could not be reached.",
    );
  });
});

describe("the commands to copy", () => {
  it("upgrades a Compose release set with the backup keys, and names a repository other than the default", () => {
    expect(upgradeLines(release().latest!)).toEqual([
      "varlatch upgrade --dir /srv/varlatch \\",
      "  --bek-file /secure/operator/backup-key \\",
      "  --kek-file /secure/operator/root-kek-copy",
    ]);
    expect(upgradeLines(release({ repo: "acme/varlatch-fork" }).latest!)).toEqual([
      "varlatch upgrade --dir /srv/varlatch \\",
      "  --repo acme/varlatch-fork \\",
      "  --bek-file /secure/operator/backup-key \\",
      "  --kek-file /secure/operator/root-kek-copy",
    ]);
    expect(checkLines("varlatch/varlatch")).toEqual(["varlatch upgrade --check --dir /srv/varlatch"]);
    expect(checkLines("acme/varlatch-fork")).toEqual(["varlatch upgrade --check --dir /srv/varlatch --repo acme/varlatch-fork"]);
  });

  it("offers no varlatch upgrade where the checked directory is no release set", () => {
    expect(upgradeLines(release({ releaseSet: false }).latest!)).toBeNull();
  });
});

let root: ReactTestRenderer | undefined;
afterEach(async () => {
  await act(async () => root?.unmount());
  root = undefined;
});
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const one = (id: string) => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return text(found[0]!);
};
async function show(r: InstallationRelease) {
  await act(async () => {
    root = create(
      <MemoryRouter>
        <ReleaseReport release={r} now={NOW} />
      </MemoryRouter>,
    );
  });
}

describe("Release tab", () => {
  it("names the checked repository, on the tab and in the command", async () => {
    await show(release({ repo: "acme/varlatch-fork" }));
    expect(one("release-repo")).toBe("acme/varlatch-fork");
    expect(one("release-upgrade-command")).toContain("--repo acme/varlatch-fork");
    expect(one("release-check-command")).toContain("--repo acme/varlatch-fork");
    expect(one("release-running")).toBe("0.18.1");
  });

  it("shows no upgrade when nothing newer is known", async () => {
    await show(release({ newer: false }));
    expect(all("release-upgrade")).toHaveLength(0);
    await show(none);
    expect(all("release-upgrade")).toHaveLength(0);
    expect(one("release-summary")).toContain("Not checked");
  });

  it("points a deployment without a release set to its own instructions", async () => {
    await show(release({ releaseSet: false }));
    expect(all("release-upgrade-command")).toHaveLength(0);
    expect(one("release-upgrade-elsewhere")).toContain("does not apply there");
  });

  it("shows a failed attempt next to the last success", async () => {
    await show(release({ failed: { checkedAt: ago(DAY), repo: "varlatch/varlatch", failed: "rate-limited" } }));
    expect(one("release-failure")).toContain("GitHub's rate limit was reached");
    expect(one("release-failure")).toContain("from the last check that succeeded");
    expect(one("release-summary")).toContain("0.19.0 is available");
  });
});

describe("who asks", () => {
  function Probe({ admin }: { admin: boolean }) {
    const r = useInstallationRelease(admin);
    return <span data-testid="probe">{r.data?.newer ? "newer" : "nothing"}</span>;
  }
  async function probe(admin: boolean, capabilities: string[]) {
    const getInstallationRelease = vi.fn(async () => release());
    fake.api = { meta: async () => ({ apiMajor: 1, serverVersion: "0.18.1", capabilities }), getInstallationRelease };
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await act(async () => {
      root = create(
        <QueryClientProvider client={client}>
          <Probe admin={admin} />
        </QueryClientProvider>,
      );
    });
    for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    return getInstallationRelease;
  }

  it("asks for Installation Admins on a server that reports release checks", async () => {
    expect(await probe(true, ["installation.release"])).toHaveBeenCalledOnce();
    expect(one("probe")).toBe("newer");
  });

  it("never asks for a member, or a server without the capability", async () => {
    expect(await probe(false, ["installation.release"])).not.toHaveBeenCalled();
    expect(one("probe")).toBe("nothing");
    await act(async () => root?.unmount());
    expect(await probe(true, [])).not.toHaveBeenCalled();
  });
});
