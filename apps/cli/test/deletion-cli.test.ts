// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DeletionUsageError, deletionStateLines, orgDeleteMode } from "../src/deletion.js";
import { EXIT } from "../src/exitCodes.js";

/**
 * Deleting Projects and Organizations from the CLI (ADR-0051 Decision 11):
 * strict options, the target named again with --confirm and checked before
 * any request, assisted mode refusing with the human's command, and the
 * deleted Organization's audit export for its readers.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-deletion-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const outside = join(dir, "outside");
/** A repository whose configuration cannot be read. */
const broken = join(dir, "broken");
const ORG = "/v1/organizations/acme";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let requests: { method: string; url: string; body: unknown }[] = [];
let open: Record<string, unknown> | null = null;

const DELETION = {
  id: "odl_1",
  requestedBy: "idn_ada",
  scheduledAt: "2026-10-30T12:00:00.000Z",
  runAfter: "2026-11-06T12:00:00.000Z",
  approvalRequired: true,
  approvedBy: null,
  approvedAt: null,
  cancelledAt: null,
  completedAt: null,
};

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    // The CLI never asks for "/"; a local tool probing new ports might.
    if (url !== "/") requests.push({ method: req.method ?? "", url, body });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.20.0", capabilities });
    if (url === ORG && req.method === "GET") return json(200, { id: "org_acme", slug: "acme", name: "Acme" });
    if (url === `${ORG}/projects/api` && req.method === "DELETE") {
      return json(200, { projectId: "prj_1", slug: "api", environments: 3, values: 4, versionsErased: 9, capabilitiesRevoked: 1, targetsRevoked: 2, teamLinksRemoved: 1 });
    }
    if (url === `${ORG}/deletion` && req.method === "GET") return json(200, { deletion: open });
    if (url === `${ORG}/deletion` && req.method === "POST") {
      const days = (body?.afterDays as number | undefined) ?? 7;
      return json(201, { ...DELETION, runAfter: new Date(Date.parse(DELETION.scheduledAt) + days * 86_400_000).toISOString() });
    }
    if (url === `${ORG}/deletion/odl_1/approve`) return json(200, { ...DELETION, approvedBy: "idn_bob", approvedAt: "2026-10-31T09:00:00.000Z" });
    if (url === `${ORG}/deletion/odl_1/cancel`) return json(200, { ...DELETION, cancelledAt: "2026-10-31T09:00:00.000Z" });
    if (url === "/v1/deleted-organizations/org_gone/audit-events/export") {
      res.writeHead(200, { "Content-Type": "application/x-ndjson" });
      res.end('{"id":"aud_1","eventType":"organization.deleted"}\n');
      return;
    }
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Not found", requestId: "req_1" } });
  });
}

beforeAll(async () => {
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile: bundle,
    logLevel: "silent",
  });
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  mkdirSync(outside);
  mkdirSync(broken);
  writeFileSync(join(broken, "varlatch.toml"), "organization = \"acme\"\nthis is not toml\n");
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["projects.delete", "organizations.delete"];
  open = null;
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], env: Record<string, string> = {}, cwd = repo): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const changes = () => requests.filter((r) => r.method !== "GET");

describe("org delete options", () => {
  const modes = (pairs: [string, string][]) => orgDeleteMode("acme", new Map(pairs));

  it("takes one mode, --after with scheduling only, and the slug exactly", () => {
    expect(modes([["--confirm", "acme"]])).toEqual({ mode: "schedule" });
    expect(modes([["--confirm", "acme"], ["--after", "3"]])).toEqual({ mode: "schedule", afterDays: 3 });
    expect(modes([["--approve", "odl_1"]])).toEqual({ mode: "approve", deletionId: "odl_1", confirmed: false });
    expect(modes([["--approve", "odl_1"], ["--confirm", "acme"]])).toEqual({ mode: "approve", deletionId: "odl_1", confirmed: true });
    expect(modes([["--cancel", "odl_1"]])).toEqual({ mode: "cancel", deletionId: "odl_1" });
    for (const bad of [
      [["--confirm", "Acme"]],
      [["--approve", "odl_1"], ["--cancel", "odl_1"]],
      [["--cancel", "odl_1"], ["--confirm", "acme"]],
      [["--cancel", "odl_1"], ["--after", "3"]],
      [["--approve", "odl_1"], ["--after", "3"]],
      [["--confirm", "acme"], ["--after", "0"]],
      [["--confirm", "acme"], ["--after", "31"]],
      [["--confirm", "acme"], ["--after", "2.5"]],
    ] as [string, string][][]) {
      expect(() => modes(bad), JSON.stringify(bad)).toThrow(DeletionUsageError);
    }
  });

  it("says when an overdue request waits for approval and never runs without it", () => {
    const lines = deletionStateLines(DELETION, "acme", new Date("2026-11-07T00:00:00.000Z")).join("\n");
    expect(lines).toContain("never runs without it: varlatch org delete acme --approve odl_1");
    const early = deletionStateLines(DELETION, "acme", new Date("2026-11-01T00:00:00.000Z")).join("\n");
    expect(early).not.toContain("never runs without it");
  });
});

describe("varlatch project delete", () => {
  it("deletes with --confirm and says what it erased and what it cannot reach", async () => {
    const r = await cli(["project", "delete", "api", "--confirm", "api"]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "DELETE", url: `${ORG}/projects/api`, body: undefined }]);
    expect(r.stdout).toContain("Project api deleted from acme.");
    expect(r.stdout).toContain("Erased 9 value versions of 4 items in 3 environments; revoked 1 Capabilities and 2 Sync Targets; removed 1 Team links.");
    expect(r.stdout).toContain("backups taken before it completes");
    expect(r.stdout).toContain("values already pushed to platforms: they stay there");
    expect(r.stdout).toContain("its replicas and snapshots of its volume");
    expect(r.stdout).toContain("may still hold their keys or values in memory;");
    expect(r.stdout).toContain("restoring one brings it back");
    expect(r.stdout).not.toContain("GitHub App");
  });

  it("refuses without --confirm or with another slug, before any request; assisted mode gives the human's command", async () => {
    const plain = await cli(["project", "delete", "api"]);
    expect(plain.code).toBe(EXIT.usage);
    expect(plain.stderr).toContain("there is no undo");
    expect(plain.stderr).toContain("varlatch project delete api --confirm api --org acme");
    const other = await cli(["project", "delete", "api", "--confirm", "web"]);
    expect(other.code).toBe(EXIT.usage);
    expect(other.stderr).toContain("approval for one Project never covers another");
    const typo = await cli(["project", "delete", "api", "--confrim", "api"]);
    expect(typo.code).toBe(EXIT.usage);
    const assisted = await cli(["project", "delete", "api"], { VARLATCH_ASSISTED: "1" });
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain("That is the human's decision. With their approval, add --confirm api.");
    expect(assisted.stderr).toContain("Nothing was deleted.");
    expect(requests).toEqual([]);
  });

  it("with --org and --server, never reads a repository's configuration, even to refuse", async () => {
    const r = await cli(["project", "delete", "api", "--confirm", "api", "--org", "acme", "--server", origin], {}, broken);
    expect(r.code, r.stderr).toBe(0);
    const assisted = await cli(["project", "delete", "api", "--org", "acme", "--server", origin], { VARLATCH_ASSISTED: "1" }, broken);
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain(`varlatch project delete api --confirm api --org acme --server ${origin}`);
    // Nothing to name the Organization with: the refusal still holds, with a placeholder.
    const unnamed = await cli(["project", "delete", "api"], { VARLATCH_ASSISTED: "1" }, broken);
    expect(unnamed.code).toBe(EXIT.config);
    expect(unnamed.stderr).toContain("varlatch project delete api --confirm api --org <org>");
    const org = await cli(["org", "delete", "acme", "--confirm", "acme", "--server", origin], {}, broken);
    expect(org.code, org.stderr).toBe(0);
    const orgRefused = await cli(["org", "delete", "acme"], { VARLATCH_ASSISTED: "1" }, broken);
    expect(orgRefused.code).toBe(EXIT.config);
    expect(requests.map((q) => q.url).filter((u) => u !== "/v1/meta" && u !== ORG)).toEqual([`${ORG}/projects/api`, `${ORG}/deletion`]);
  });

  it("works outside a repository with --org and --server, and refuses an older server", async () => {
    const r = await cli(["project", "delete", "api", "--confirm", "api", "--org", "acme", "--server", origin], {}, outside);
    expect(r.code, r.stderr).toBe(0);
    capabilities = [];
    requests = [];
    const old = await cli(["project", "delete", "api", "--confirm", "api"]);
    expect(old.code).toBe(EXIT.failure);
    expect(old.stderr).toContain("needs Varlatch 0.20.0 or later. Nothing was deleted.");
    expect(changes()).toEqual([]);
  });
});

describe("varlatch org delete", () => {
  it("schedules with --confirm and --after, and says how to approve, cancel and export the audit log", async () => {
    const r = await cli(["org", "delete", "acme", "--confirm", "acme", "--after", "3"]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "POST", url: `${ORG}/deletion`, body: { afterDays: 3 } }]);
    expect(r.stdout).toContain("Deletion of acme scheduled.");
    expect(r.stdout).toContain("It runs no earlier than 2026-11-02T12:00:00.000Z.");
    expect(r.stdout).toContain("varlatch org delete acme --approve odl_1");
    expect(r.stdout).toContain("varlatch org delete acme --cancel odl_1");
    expect(r.stdout).toContain("varlatch audit export --deleted-org org_acme");
    expect(r.stdout).toContain("uninstall it or delete it there");
    expect(r.stdout).toContain("Installation tokens already issued stay valid until they expire.");
    expect(r.stdout).toContain("one in flight when the deletion runs may still complete");
  });

  it("refuses without --confirm before any request; assisted mode refuses scheduling and approval without it", async () => {
    const plain = await cli(["org", "delete", "acme"]);
    expect(plain.code).toBe(EXIT.usage);
    expect(plain.stderr).toContain("varlatch org delete acme --confirm acme");
    const assisted = await cli(["org", "delete", "acme", "--after", "5"], { VARLATCH_ASSISTED: "1" });
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain("  varlatch org delete acme --confirm acme --after 5\nNothing was changed.");
    const approve = await cli(["org", "delete", "acme", "--approve", "odl_1"], { VARLATCH_ASSISTED: "1" });
    expect(approve.code).toBe(EXIT.config);
    expect(approve.stderr).toContain("  varlatch org delete acme --approve odl_1\nNothing was changed.");
    const both = await cli(["org", "delete", "acme", "--approve", "odl_1", "--cancel", "odl_1"]);
    expect(both.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
  });

  it("approves and cancels a named request; assisted mode cancels without --confirm", async () => {
    const approved = await cli(["org", "delete", "acme", "--approve", "odl_1"]);
    expect(approved.code, approved.stderr).toBe(0);
    expect(approved.stdout).toContain("Approved by idn_bob at 2026-10-31T09:00:00.000Z.");
    const agentApproved = await cli(["org", "delete", "acme", "--approve", "odl_1", "--confirm", "acme"], { VARLATCH_ASSISTED: "1" });
    expect(agentApproved.code, agentApproved.stderr).toBe(0);
    const cancelled = await cli(["org", "delete", "acme", "--cancel", "odl_1"], { VARLATCH_ASSISTED: "1" });
    expect(cancelled.code, cancelled.stderr).toBe(0);
    expect(cancelled.stdout).toContain("Deletion odl_1 of acme cancelled; acme is no longer frozen.");
    expect(cancelled.stdout).toContain("Sync Targets stay paused");
    expect(changes().map((c) => c.url)).toEqual([`${ORG}/deletion/odl_1/approve`, `${ORG}/deletion/odl_1/approve`, `${ORG}/deletion/odl_1/cancel`]);
  });
});

describe("varlatch org deletion", () => {
  it("shows the open request, or none", async () => {
    const none = await cli(["org", "deletion", "acme"]);
    expect(none.stdout).toContain("No deletion of acme is scheduled.");
    open = DELETION;
    const r = await cli(["org", "deletion", "acme"]);
    expect(r.stdout).toContain("Deletion odl_1 of acme: scheduled 2026-10-30T12:00:00.000Z by idn_ada.");
    expect(r.stdout).toContain("It waits for another admin's approval");
    const json = JSON.parse((await cli(["org", "deletion", "acme", "--json"])).stdout);
    expect(json).toMatchObject({ organization: "acme", deletion: { id: "odl_1" } });
    expect(changes()).toEqual([]);
  });
});

describe("varlatch audit export --deleted-org", () => {
  it("streams the deleted Organization's log, outside a repository too", async () => {
    const r = await cli(["audit", "export", "--deleted-org", "org_gone", "--server", origin], {}, outside);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe('{"id":"aud_1","eventType":"organization.deleted"}\n');
    const missing = await cli(["audit", "export", "--deleted-org", "org_gone"], {}, outside);
    expect(missing.code).toBe(EXIT.usage);
  });
});
