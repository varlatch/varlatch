// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Maintenance, RELEASE_CHECK_FILE, readReleaseCheck, recordReleaseCheck } from "@varlatch/backup";
import { control, startBackupControl } from "../src/backup/control.js";
import { generateKey } from "../src/crypto/aead.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import { issueCredential } from "../src/auth/credentials.js";
import { buildApp, SERVER_VERSION } from "../src/http/app.js";
import { checkReleaseLatest } from "../src/doctor.js";
import { migratedTestDb } from "./helpers/pglite.js";
import type { AppCtx } from "../src/domain/ctx.js";

/**
 * ADR-0049: the host records its look for a newer release through the
 * backup control; varlatchd shows it to Installation Admins, compared with
 * its own version when asked, and reports it as an advisory doctor check.
 */

const NOW = Date.parse("2026-10-22T12:00:00Z");
const DAY = 24 * 3600_000;
const [major, minor, patch] = SERVER_VERSION.split(".").map(Number) as [number, number, number];
const NEWER = `${major}.${minor + 1}.0`;
const found = (version: string, repo = "varlatch/varlatch", releaseSet = true) => ({
  outcome: "found" as const,
  repo,
  latest: { version, publishedAt: "2026-10-21T12:00:00.000Z" },
  releaseSet,
});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "varlatch-release-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("GET /v1/installation/release", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let admin: string;
  let member: string;
  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), maintenance: new Maintenance(dir), close: db.close };
    await ensureInstallation(ctx);
    await ctx.db.query("INSERT INTO identities(id, kind, name, installation_admin) VALUES ('id_admin','human','Admin',true), ('id_member','human','Member',false)");
    admin = (await issueCredential(ctx.db, { identityId: "id_admin", kind: "cli" })).token;
    member = (await issueCredential(ctx.db, { identityId: "id_member", kind: "cli" })).token;
  });
  afterEach(async () => {
    await ctx.close();
  });
  const get = (app: ReturnType<typeof buildApp>, token?: string) =>
    app.request("/v1/installation/release", token ? { headers: { Authorization: `Bearer ${token}` } } : {});

  it("answers Installation Admins only", async () => {
    const app = buildApp(ctx);
    expect((await get(app)).status).toBe(401);
    expect((await get(app, member)).status).toBe(403);
    expect((await get(app, admin)).status).toBe(200);
  });

  it("says not checked, never a guess, before the first check and without a backup supervisor", async () => {
    const empty = { running: SERVER_VERSION, newer: null, latest: null, lastAttempt: null, unreadable: false };
    expect(await (await get(buildApp(ctx), admin)).json()).toEqual(empty);
    const { maintenance: _m, ...withoutSupervisor } = ctx;
    expect(await (await get(buildApp(withoutSupervisor), admin)).json()).toEqual(empty);
  });

  it("reports a newer release, with the link built from the checked repository and version", async () => {
    recordReleaseCheck(dir, found(NEWER, "acme/varlatch-fork", false), NOW);
    expect(await (await get(buildApp(ctx), admin)).json()).toEqual({
      running: SERVER_VERSION,
      newer: true,
      latest: {
        version: NEWER,
        publishedAt: "2026-10-21T12:00:00.000Z",
        url: `https://github.com/acme/varlatch-fork/releases/tag/v${NEWER}`,
        repo: "acme/varlatch-fork",
        releaseSet: false,
        checkedAt: "2026-10-22T12:00:00.000Z",
      },
      lastAttempt: { checkedAt: "2026-10-22T12:00:00.000Z", repo: "acme/varlatch-fork", failed: null },
      unreadable: false,
    });
  });

  it("compares with the running version when asked: a record naming the running version is not newer", async () => {
    recordReleaseCheck(dir, found(SERVER_VERSION), NOW);
    expect((await (await get(buildApp(ctx), admin)).json()).newer).toBe(false);
    // An installation upgraded past what the host last saw: nothing newer.
    recordReleaseCheck(dir, found(`${major}.${Math.max(0, minor - 1)}.0`), NOW);
    expect((await (await get(buildApp(ctx), admin)).json()).newer).toBe(false);
  });

  it("keeps the last success next to a failed attempt", async () => {
    recordReleaseCheck(dir, found(NEWER), NOW - DAY);
    recordReleaseCheck(dir, { outcome: "failed", repo: "varlatch/varlatch", failed: "unreachable" }, NOW);
    const body = await (await get(buildApp(ctx), admin)).json();
    expect(body.newer).toBe(true);
    expect(body.latest.checkedAt).toBe("2026-10-21T12:00:00.000Z");
    expect(body.lastAttempt).toEqual({ checkedAt: "2026-10-22T12:00:00.000Z", repo: "varlatch/varlatch", failed: "unreachable" });
  });

  it("says when the record is unreadable", async () => {
    writeFileSync(join(dir, RELEASE_CHECK_FILE), '{"lastAttempt":{"checkedAt":"x"}');
    expect(await (await get(buildApp(ctx), admin)).json()).toMatchObject({ newer: null, latest: null, unreadable: true });
  });
});

describe("release-check control command", () => {
  it("records what the host found, and refuses anything else", async () => {
    const db = await migratedTestDb();
    try {
      startBackupControl({ db, rootKek: generateKey() }, new Maintenance(dir), null);
      await new Promise((r) => setTimeout(r, 50));
      await expect(control({ command: "release-check", releaseCheck: found(NEWER) }, dir)).resolves.toEqual({ recorded: true });
      expect(readReleaseCheck(dir)?.lastSuccess?.latest.version).toBe(NEWER);
      await expect(control({ command: "release-check", releaseCheck: { ...found(NEWER), url: "https://evil.example" } }, dir)).rejects.toThrow("Invalid release check");
      await expect(control({ command: "release-check" }, dir)).rejects.toThrow("Invalid release check");
      expect(readReleaseCheck(dir)?.lastSuccess?.latest.version).toBe(NEWER);
    } finally {
      await db.close();
    }
  });
});

describe("doctor: release.latest", () => {
  it("is unknown before any successful check, and names a failed one", () => {
    expect(checkReleaseLatest(dir, "0.18.1", NOW)).toMatchObject({ id: "release.latest", class: "advisory", status: "unknown" });
    recordReleaseCheck(dir, { outcome: "failed", repo: "varlatch/varlatch", failed: "rate-limited" }, NOW);
    expect(checkReleaseLatest(dir, "0.18.1", NOW)).toMatchObject({ status: "unknown", detail: expect.stringContaining("rate-limited") });
  });

  it("fails, advisory, when a newer release is known, however old the check", () => {
    recordReleaseCheck(dir, found("0.19.0"), NOW - 30 * DAY);
    const check = checkReleaseLatest(dir, "0.18.1", NOW);
    expect(check).toMatchObject({ status: "fail", class: "advisory", remedy: "varlatch upgrade --dir <dir>" });
    expect(check.detail).toContain("0.19.0 is available, 0.18.1 is running");
  });

  it("names the checked repository in the remedy, and no command where varlatch upgrade does not apply", () => {
    recordReleaseCheck(dir, found("0.19.0", "acme/varlatch-fork"), NOW);
    expect(checkReleaseLatest(dir, "0.18.1", NOW).remedy).toBe("varlatch upgrade --dir <dir> --repo acme/varlatch-fork");
    recordReleaseCheck(dir, found("0.19.0", "varlatch/varlatch", false), NOW);
    expect(checkReleaseLatest(dir, "0.18.1", NOW).remedy).not.toContain("varlatch upgrade");
  });

  it("passes on a recent check with nothing newer, and is unknown once that check is older than 14 days", () => {
    recordReleaseCheck(dir, found("0.18.1"), NOW - 13 * DAY);
    expect(checkReleaseLatest(dir, "0.18.1", NOW).status).toBe("pass");
    recordReleaseCheck(dir, found("0.18.1"), NOW - 15 * DAY);
    expect(checkReleaseLatest(dir, "0.18.1", NOW)).toMatchObject({ status: "unknown", detail: expect.stringContaining("older than 14 days") });
  });

  it("is unknown when the record is unreadable", () => {
    writeFileSync(join(dir, RELEASE_CHECK_FILE), "not json");
    expect(checkReleaseLatest(dir, "0.18.1", NOW)).toMatchObject({ status: "unknown", detail: "the release check record is unreadable" });
  });
});
