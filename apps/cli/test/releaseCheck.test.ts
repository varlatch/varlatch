// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReleaseCheckInput } from "@varlatch/backup";
import { fetchRelease, recordReleaseCheck, ReleaseLookupError, runUpgrade, type UpgradeOptions } from "../src/upgrade.js";

/**
 * ADR-0049: an unpinned `varlatch upgrade --check` records what GitHub
 * answered as soon as it answered, for the dashboard. Whether the release
 * then applies here is the command's business: it keeps its output and exit
 * status, and the record keeps the discovery.
 */

const manifest = (version: string) =>
  JSON.stringify({ schemaVersion: 1, version, apiMajor: 1, migrationVersion: 31, supportedPostgresMajor: 17, supportedRestoreSources: [], images: {} });
const latest = (tag: string, extra: Record<string, unknown> = {}) => ({
  tag_name: tag,
  html_url: "https://github.com/varlatch/varlatch/releases/tag/" + tag,
  published_at: "2026-10-21T12:00:00Z",
  assets: [{ name: "varlatch-release.json", url: "https://assets/manifest" }],
  ...extra,
});

let dir: string;
let recorded: ReleaseCheckInput[];
let log: string[];
const recordCheck = async (_dir: string, input: ReleaseCheckInput) => {
  recorded.push(input);
};
const check = (over: Partial<UpgradeOptions> = {}): UpgradeOptions => ({
  dir,
  repo: "varlatch/varlatch",
  yes: false,
  skipDbBackup: false,
  kekBackupVerified: false,
  checkOnly: true,
  recordCheck,
  ...over,
});
/** GitHub answering `releases/latest` with `answer`, and the release's manifest asset with `asset`. */
function github(answer: () => Response | Promise<Response>, asset: () => Response = () => new Response(manifest("0.19.0"))) {
  vi.stubGlobal("fetch", async (input: unknown) => (String(input) === "https://assets/manifest" ? asset() : answer()));
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "varlatch-release-check-"));
  writeFileSync(join(dir, "docker-compose.yml"), "services: {}\n");
  recorded = [];
  log = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    log.push(args.join(" "));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  rmSync(dir, { recursive: true, force: true });
});

describe("what an unpinned check records", () => {
  it("records the latest release, and whether the directory is a release set", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.18.1"));
    github(() => Response.json(latest("v0.19.0")));
    await runUpgrade(check());
    expect(recorded).toEqual([
      { outcome: "found", repo: "varlatch/varlatch", latest: { version: "0.19.0", publishedAt: "2026-10-21T12:00:00.000Z" }, releaseSet: true },
    ]);
    expect(log).toContain("Recorded for the dashboard (Installation → Release).");
    expect(log.some((l) => l.startsWith("Target:    0.19.0"))).toBe(true);
  });

  it("records without a local varlatch-release.json, as no release set", async () => {
    github(() => Response.json(latest("v0.19.0", { published_at: null })));
    await runUpgrade(check());
    expect(recorded).toEqual([{ outcome: "found", repo: "varlatch/varlatch", latest: { version: "0.19.0", publishedAt: null }, releaseSet: false }]);
  });

  it("records when the same version is already running", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.19.0"));
    github(() => Response.json(latest("v0.19.0")));
    await runUpgrade(check());
    expect(recorded).toHaveLength(1);
    expect(log).toContain("Already on this release — nothing to do.");
  });

  it("records when a newer prerelease runs, and the command still refuses the downgrade", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.20.0-rc1"));
    github(() => Response.json(latest("v0.19.0")));
    await expect(runUpgrade(check())).rejects.toThrow(/Refusing downgrade 0\.20\.0-rc1 -> 0\.19\.0/);
    expect(recorded).toEqual([expect.objectContaining({ outcome: "found", latest: expect.objectContaining({ version: "0.19.0" }) })]);
  });

  it("records the discovery when an asset then fails to download, and the command still fails", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.18.1"));
    github(() => Response.json(latest("v0.19.0")), () => new Response("", { status: 502 }));
    await expect(runUpgrade(check())).rejects.toThrow(/Downloading varlatch-release\.json failed/);
    expect(recorded).toEqual([expect.objectContaining({ outcome: "found" })]);
  });

  it("records the checked repository", async () => {
    github(() => Response.json(latest("v0.19.0")));
    await runUpgrade(check({ repo: "acme/varlatch-fork" }));
    expect(recorded[0]?.repo).toBe("acme/varlatch-fork");
  });
});

describe("what a failed check records", () => {
  const failsWith = async (answer: () => Response | Promise<Response>, reason: string, message: RegExp) => {
    github(answer);
    const run = runUpgrade(check());
    await expect(run).rejects.toThrow(message);
    await expect(run).rejects.toBeInstanceOf(ReleaseLookupError);
    expect(recorded).toEqual([{ outcome: "failed", repo: "varlatch/varlatch", failed: reason }]);
  };

  it("unreachable: the request fails", () =>
    failsWith(() => Promise.reject(new TypeError("fetch failed")), "unreachable", /Could not reach GitHub/));
  it("unreachable: GitHub answers 5xx", () => failsWith(() => new Response("", { status: 502 }), "unreachable", /GitHub API 502/));
  it("rate-limited: 403 with no requests left", () =>
    failsWith(() => new Response("", { status: 403, headers: { "x-ratelimit-remaining": "0" } }), "rate-limited", /rate limit/));
  it("rate-limited: 429", () => failsWith(() => new Response("", { status: 429 }), "rate-limited", /rate limit/));
  it("not-found: no published release", () => failsWith(() => new Response("", { status: 404 }), "not-found", /No releases found/));
  it("invalid-answer: not JSON", () => failsWith(() => new Response("<html>"), "invalid-answer", /not GitHub's release JSON/));
  it("invalid-answer: a tag that names no release version", () =>
    failsWith(() => Response.json(latest("nightly")), "invalid-answer", /does not name a release version/));
  it("invalid-answer: JSON null", () => failsWith(() => new Response("null"), "invalid-answer", /not GitHub's release JSON/));
  it("invalid-answer: JSON that is no release", async () => {
    for (const body of ["[]", '"v0.19.0"', JSON.stringify({ tag_name: 19, assets: [] }), JSON.stringify({ tag_name: "v0.19.0" })]) {
      recorded = [];
      await failsWith(() => new Response(body), "invalid-answer", /not GitHub's release JSON/);
    }
  });

  it("bounds the answer's body too: a body that stalls after the headers is unreachable", async () => {
    vi.stubGlobal("fetch", async (_input: unknown, init?: RequestInit) =>
      new Response(new ReadableStream({ start: (c) => init?.signal?.addEventListener("abort", () => c.error(init.signal!.reason)) })));
    const lookup = fetchRelease("varlatch/varlatch", undefined, 20);
    await expect(lookup).rejects.toThrow(/did not answer within 0\.02 s/);
    await expect(lookup).rejects.toMatchObject({ reason: "unreachable" });
  });

  it("bounds the request: an unanswered lookup is unreachable", async () => {
    vi.stubGlobal("fetch", (_input: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason))));
    const lookup = fetchRelease("varlatch/varlatch", undefined, 20);
    await expect(lookup).rejects.toThrow(/did not answer within 0\.02 s/);
    await expect(lookup).rejects.toMatchObject({ reason: "unreachable" });
  });
});

describe("what records nothing", () => {
  it("a check of a pinned version, older or a prerelease", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.18.1"));
    for (const version of ["0.17.0", "0.19.0-rc1"]) {
      github(() => Response.json(latest(`v${version}`)), () => new Response(manifest(version)));
      await runUpgrade(check({ version })).catch(() => {});
    }
    expect(recorded).toEqual([]);
    expect(log.filter((l) => l.startsWith("Not recorded for the dashboard"))).toHaveLength(2);
  });

  it("a check of a staged release directory", async () => {
    const staged = join(dir, "staged");
    mkdirSync(staged);
    writeFileSync(join(staged, "varlatch-release.json"), manifest("0.19.0"));
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await runUpgrade(check({ releaseDir: staged }));
    expect(fetch).not.toHaveBeenCalled();
    expect(recorded).toEqual([]);
    expect(log.some((l) => l.startsWith("Not recorded for the dashboard"))).toBe(true);
  });

  it("an upgrade, as opposed to a check", async () => {
    writeFileSync(join(dir, "varlatch-release.json"), manifest("0.18.1"));
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      if (url === "https://assets/manifest") return new Response(manifest("0.19.0"));
      if (url === "https://assets/compose") return new Response("x: ${NEEDED_HERE:?set it}\n");
      return Response.json(latest("v0.19.0", { assets: [{ name: "varlatch-release.json", url: "https://assets/manifest" }, { name: "docker-compose.release.yml", url: "https://assets/compose" }] }));
    });
    await expect(runUpgrade(check({ checkOnly: false }))).rejects.toThrow(/requires NEEDED_HERE/);
    expect(recorded).toEqual([]);
  });
});

describe("recordReleaseCheck", () => {
  const input: ReleaseCheckInput = { outcome: "found", repo: "varlatch/varlatch", latest: { version: "0.19.0", publishedAt: null }, releaseSet: true };

  it("records nothing outside a Compose project, and says so", async () => {
    rmSync(join(dir, "docker-compose.yml"));
    const record = vi.fn();
    await recordReleaseCheck(dir, input, record);
    expect(record).not.toHaveBeenCalled();
    expect(log).toEqual([`Not recorded for the dashboard: no Compose project in ${dir} (pass --dir).`]);
  });

  it("says when the installation's varlatchd predates release checks, without failing", async () => {
    await recordReleaseCheck(dir, input, async () => {
      throw new Error("Unknown backup control command");
    });
    expect(log).toEqual(["Not recorded for the dashboard: this installation's varlatchd predates release checks."]);
  });

  it("refuses a repository that is not owner/name before contacting the installation", async () => {
    const record = vi.fn();
    await recordReleaseCheck(dir, { ...input, repo: "https://example.com/x" }, record);
    expect(record).not.toHaveBeenCalled();
  });

  it("sends the check to the running varlatchd's control (the default recorder)", async () => {
    const bin = join(dir, "bin");
    mkdirSync(bin);
    // `docker compose exec -T varlatchd …`: the light control entry exists and takes the command on stdin.
    writeFileSync(
      join(bin, "docker"),
      `#!/bin/sh
case "$*" in
  "compose exec -T varlatchd test -f dist/control-entry.js") exit 0 ;;
  "compose exec -T varlatchd node dist/control-entry.js release-check") cat > control-input.json; echo '{"recorded":true}' ;;
  *) exit 3 ;;
esac
`,
      { mode: 0o700 },
    );
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    await recordReleaseCheck(dir, input);
    expect(JSON.parse(readFileSync(join(dir, "control-input.json"), "utf8"))).toEqual({ releaseCheck: input });
    expect(log).toEqual(["Recorded for the dashboard (Installation → Release)."]);
  });
});
