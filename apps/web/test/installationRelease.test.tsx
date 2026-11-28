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

import { checkLines, imageByDigest, lastFailure, releaseSummary, rollbackSentence, upgradeGuide } from "../src/features/installation/releaseStatus";
import { ReleaseReport } from "../src/features/installation/ReleaseTab";
import { useInstallationRelease } from "../src/features/installation/releaseNotice";
import { InstallationPage } from "../src/features/installation/InstallationPage";

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

const DIGEST = `sha256:${"0123456789abcdef".repeat(4)}`;
const IMAGE = `ghcr.io/varlatch/varlatchd:0.19.0@${DIGEST}`;
type Line = NonNullable<InstallationRelease["preflight"]>[number];
const pass = (id: Line["id"]): Line => ({ id, status: "pass", title: `${id} title`, detail: `${id} passes.`, remedy: null });

/** What the Go server answers with its host's facts (ADR-0065 phase 1): verified, against `previous`. */
const preflighted = (over: { deployment?: "systemd" | "image"; previous?: string; lines?: Line[] } = {}): InstallationRelease => {
  const previous = over.previous ?? "0.18.1";
  return {
    ...release(),
    deployment: over.deployment ?? "systemd",
    schemaVersion: 7,
    target: {
      version: "0.19.0",
      checkedAt: ago(3600_000),
      failed: null,
      verified: { schemaVersion: 8, compatibleFrom: 7, rollbackSafe: true, previous: { version: previous, schemaVersion: 7 }, endsRollbackWindow: false, image: IMAGE },
    },
    rollbackSafe: previous === "0.18.1",
    preflight: over.lines ?? (["release-check", "backup", "custody", "disk", "in-the-way", "rollback-safe"] as const).map(pass),
  };
};

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
  it("checks on the host, or in the container", () => {
    expect(checkLines("host")).toEqual(["sudo varlatch upgrade --check"]);
    expect(checkLines("container")).toEqual(["docker exec <container> varlatch upgrade --check"]);
  });

  it("upgrades a service to the named release, one step at a time for a jump", () => {
    const step = upgradeGuide(preflighted(), "host")!;
    expect(step.oneAtATime).toBeNull();
    expect(step.sections.flatMap((s) => s.steps.flatMap((x) => x.lines ?? []))).toEqual(["sudo varlatch upgrade 0.19.0"]);
    const jump = upgradeGuide(preflighted({ previous: "0.18.2" }), "host")!;
    expect(jump.oneAtATime).toMatch(/one release at a time \(sudo varlatch upgrade <version> for each release after 0\.18\.1, oldest first\)/);
    expect(jump.sections[0]!.steps.map((x) => x.lines)).toEqual([["sudo varlatch upgrade <version>"], ["sudo varlatch upgrade 0.19.0"]]);
    expect(upgradeGuide(none, "host")).toBeNull();
  });

  it("upgrades an image by the verified digest, on Coolify and with Docker", () => {
    expect(imageByDigest(IMAGE)).toBe(`ghcr.io/varlatch/varlatchd@${DIGEST}`);
    const guide = upgradeGuide(preflighted({ deployment: "image" }), "container")!;
    const lines = (title: string) => guide.sections.find((s) => s.title === title)!.steps.flatMap((x) => x.lines ?? []);
    expect(lines("Coolify")).toContain(`VARLATCH_VARLATCHD_DIGEST=${DIGEST}`);
    expect(lines("Coolify")).toContain("docker exec <container> varlatchd admin backup run");
    expect(lines("Coolify").join("\n")).toContain(`ghcr.io/varlatch/varlatchd@${DIGEST} admin schema status`);
    expect(lines("Docker Compose or docker run")).toContain(`VARLATCH_VARLATCHD_DIGEST=${DIGEST} docker compose up -d`);
    // Without a verified target, the digest is the release notes'.
    expect(upgradeGuide(release(), "container")!.sections[0]!.steps.flatMap((x) => x.lines ?? [])).toContain(
      "VARLATCH_VARLATCHD_DIGEST=sha256:<the digest its release notes name>",
    );
  });

  it("says whether going back needs a restore", () => {
    expect(rollbackSentence(preflighted())).toEqual({ tone: "ok", text: "Rollback-safe: going back needs no restore." });
    expect(rollbackSentence(preflighted({ previous: "0.18.2" })).text).toBe(
      "Not rollback-safe for 0.18.1: 0.19.0 was checked against 0.18.2. Upgrade one release at a time.",
    );
    expect(rollbackSentence(release()).tone).toBe("muted");
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
  it("names the checked repository", async () => {
    await show(release({ repo: "acme/varlatch-fork" }));
    expect(one("release-repo")).toBe("acme/varlatch-fork");
    expect(one("release-upgrade-command")).toContain("sudo varlatch upgrade");
    expect(one("release-check-command")).toContain("sudo varlatch upgrade --check");
    expect(one("release-running")).toBe("0.18.1");
  });

  it("shows no upgrade when nothing newer is known", async () => {
    await show(release({ newer: false }));
    expect(all("release-upgrade")).toHaveLength(0);
    await show(none);
    expect(all("release-upgrade")).toHaveLength(0);
    expect(one("release-summary")).toContain("Not checked");
  });

  it("points an installation in a container to deploying the new image, where the server does not say how it runs", async () => {
    await show(release());
    await act(async () => all("deployment-container")[0]!.props.onClick());
    expect(all("release-upgrade-command")).toHaveLength(0);
    expect(one("release-guide-coolify")).toContain("VARLATCH_VARLATCHD_DIGEST=sha256:<the digest its release notes name>");
    expect(one("release-check-command")).toContain("docker exec <container> varlatch upgrade --check");
  });

  it("knows how varlatchd runs when the server says, and asks nothing", async () => {
    await show(preflighted({ deployment: "image" }));
    expect(all("deployment-container")).toHaveLength(0);
    expect(one("release-deployment")).toContain("in a container");
    expect(one("release-guide-docker")).toContain(`VARLATCH_VARLATCHD_DIGEST=${DIGEST} docker compose up -d`);
    expect(one("release-check-command")).toContain("docker exec <container> varlatch upgrade --check");
  });

  it("shows the pre-flight checklist, each failure with what to do, and no upgrade button", async () => {
    const lines = preflighted().preflight!.map((l) =>
      l.id === "release-check"
        ? { ...l, status: "fail" as const, detail: "The release check last ran 3 days ago.", remedy: "Schedule it on the host" }
        : l.id === "disk"
          ? { ...l, status: "unknown" as const, detail: "The data directory's free space cannot be read." }
          : l,
    );
    await show(preflighted({ lines }));
    expect(all("release-preflight")).toHaveLength(1);
    expect(all("preflight-release-check")[0]!.props["data-status"]).toBe("fail");
    expect(one("preflight-release-check")).toContain("The release check last ran 3 days ago.");
    expect(one("preflight-release-check-remedy")).toContain("Schedule it on the host.");
    expect(one("preflight-release-check-remedy")).toContain("Scheduling the release check");
    expect(all("preflight-disk")[0]!.props["data-status"]).toBe("unknown");
    expect(all("preflight-backup-remedy")).toHaveLength(0);
    expect(one("release-rollback")).toContain("going back needs no restore");
    expect(one("release-upgrade-command")).toBe("sudo varlatch upgrade 0.19.0");
    const buttons = root!.root.findAll((n) => n.type === "button" && text(n).includes("Upgrade to"));
    expect(buttons).toHaveLength(0);
  });

  it("tells a jump to go one release at a time", async () => {
    const lines = preflighted().preflight!.map((l) =>
      l.id === "rollback-safe"
        ? { ...l, status: "fail" as const, detail: "0.19.0 was checked against 0.18.2, not 0.18.1: upgrade one release at a time.", remedy: "Upgrade one release at a time" }
        : l,
    );
    await show(preflighted({ previous: "0.18.2", lines }));
    expect(one("preflight-rollback-safe")).toContain("0.19.0 was checked against 0.18.2, not 0.18.1: upgrade one release at a time.");
    expect(one("release-one-at-a-time")).toContain("for each release after 0.18.1, oldest first");
    expect(one("release-guide-host")).toContain("sudo varlatch upgrade <version>");
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

describe("the Installation page's Release tab", () => {
  async function page(backups: () => Promise<unknown>) {
    const getInstallationRelease = vi.fn(async () => release());
    fake.api = {
      meta: async () => ({ apiMajor: 1, serverVersion: "0.18.1", capabilities: ["installation.release"] }),
      getInstallationBackups: backups,
      getInstallationRelease,
    };
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await act(async () => {
      root = create(
        <QueryClientProvider client={client}>
          <MemoryRouter initialEntries={["/installation/settings?tab=release"]}>
            <InstallationPage />
          </MemoryRouter>
        </QueryClientProvider>,
      );
    });
    for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    return getInstallationRelease;
  }

  it("asks nothing while the admin-only backups read is pending", async () => {
    expect(await page(() => new Promise(() => {}))).not.toHaveBeenCalled();
    expect(all("release-status")).toHaveLength(0);
  });

  it("asks nothing when that read is refused, and says why", async () => {
    expect(await page(async () => Promise.reject(new Error("Installation Admin required")))).not.toHaveBeenCalled();
    expect(one("release-error")).toContain("Installation Admin authority is required");
  });

  it("asks once that read succeeded, and shows the release", async () => {
    expect(await page(async () => ({ archives: [], warnings: [] }))).toHaveBeenCalledOnce();
    expect(one("release-summary")).toContain("0.19.0 is available");
  });
});
