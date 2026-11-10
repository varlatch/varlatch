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
import type { CredentialReview } from "@varlatch/protocol";
import { EXIT } from "../src/exitCodes.js";
import { ago, credentialReviewLines } from "../src/securityReport.js";
import { commandHelp } from "../src/usage.js";

/**
 * `varlatch security report` end to end against a local server (ADR-0054
 * Decision 8): the credential review grouped by reason, with identity names
 * and last use; --json for the whole document; exit 0 whatever it lists.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-security-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const outside = join(dir, "outside");
const DAY = 86400_000;

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let review: CredentialReview;
let requests: string[] = [];

const at = (daysAgo: number) => new Date(Date.now() - daysAgo * DAY).toISOString();

function fullReview(): CredentialReview {
  return {
    generatedAt: at(0),
    idleDays: 30,
    summary: { reviewed: 5, listed: 3, neverUsed: 1, idle: 1, noExpiry: 2 },
    items: [
      {
        id: "crd_deploy",
        name: "deployer credential",
        kind: "service",
        createdAt: at(3),
        expiresAt: null,
        lastUsedAt: null,
        issuedBy: { id: "idn_ada", name: "Ada" },
        identity: { id: "idn_deploy", name: "deployer", kind: "service", state: "live", disabledReason: null },
        reasons: ["never-used", "no-expiry"],
      },
      {
        id: "crd_old",
        name: "nightly",
        kind: "service",
        createdAt: at(90),
        expiresAt: "2027-06-01T00:00:00.000Z",
        lastUsedAt: at(40),
        issuedBy: null,
        identity: { id: "idn_runner", name: "runner", kind: "workload", state: "live", disabledReason: null },
        reasons: ["idle"],
      },
      {
        id: "crd_doomed",
        name: null,
        kind: "service",
        createdAt: at(10),
        expiresAt: null,
        lastUsedAt: at(1),
        issuedBy: null,
        identity: { id: "idn_doomed", name: "doomed", kind: "broker", state: "disabled", disabledReason: "organization-deletion" },
        reasons: ["no-expiry"],
      },
    ],
  };
}

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = req.url ?? "";
  requests.push(`${req.method} ${url}`);
  const json = (status: number, payload: unknown) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  };
  if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.20.1", capabilities });
  if (url === "/v1/organizations/acme/security/credential-review") return json(200, review);
  if (url === "/v1/organizations/other/security/credential-review") {
    return json(200, { ...fullReview(), summary: { reviewed: 0, listed: 0, neverUsed: 0, idle: 0, noExpiry: 0 }, items: [] });
  }
  json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Not found", requestId: "req_1" } });
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
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["security.credential-review"];
  review = fullReview();
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd = repo): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      // An explicit mode for this suite (assisted mode is on under a coding agent's session).
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("varlatch security report", () => {
  it("prints the review grouped by reason, with identities and last use, and exits 0", async () => {
    const r = await cli(["security", "report"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toBe("");
    expect(requests).toEqual(["GET /v1/meta", "GET /v1/organizations/acme/security/credential-review"]);
    const lines = r.stdout.trimEnd().split("\n");
    expect(lines).toEqual([
      "Credential review for acme: 3 of 5 machine credentials need a look.",
      "",
      "Never used (1)",
      "  crd_deploy  deployer credential  for deployer (idn_deploy, service): last used never, no expiry, created 3 days ago, issued by Ada",
      "",
      "Unused for 30 days or more (1)",
      "  crd_old  nightly  for runner (idn_runner, workload): last used 40 days ago, expires 2027-06-01T00:00:00.000Z, created 90 days ago",
      "",
      "No expiry (2)",
      "  crd_deploy  deployer credential  for deployer (idn_deploy, service): last used never, no expiry, created 3 days ago, issued by Ada",
      "  crd_doomed  unnamed  for doomed (idn_doomed, broker, suspended by the organization's deletion): last used 1 day ago, no expiry, created 10 days ago",
      "",
      "Reporting only: nothing is revoked or retired automatically. To revoke one: varlatch credential revoke <identity-id> <credential-id>",
    ]);
  });

  it("--json prints the whole review as one document", async () => {
    const r = await cli(["security", "report", "--json"]);
    expect(r.code, r.stderr).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc).toEqual({ version: expect.any(Number), organization: "acme", credentialReview: review });
    expect(r.stdout).not.toContain("vlt_");
  });

  it("says when nothing needs a look; --org and --server work outside a repository", async () => {
    const r = await cli(["security", "report", "--org", "other", "--server", origin], outside);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe(
      "Credential review for other: none of 0 machine credentials needs a look.\n\n" +
        "Reporting only: nothing is revoked or retired automatically.\n",
    );
  });

  it("fails, naming the capability, on a server without the review", async () => {
    capabilities = [];
    const r = await cli(["security", "report"]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("lacks the security.credential-review capability");
    expect(requests).toEqual(["GET /v1/meta"]);
  });

  it("refuses a wrong command line before any request (exit 64)", async () => {
    for (const args of [["security"], ["security", "status"], ["security", "report", "--jsno"], ["security", "report", "extra"]]) {
      const r = await cli(args);
      expect(r.code, args.join(" ")).toBe(EXIT.usage);
      expect(r.stderr).toContain("varlatch security report");
    }
    const lost = await cli(["security", "report"], outside);
    expect(lost.code).toBe(EXIT.usage);
    expect(lost.stderr).toContain("pass --org <organization> and --server <url>");
    expect(requests).toEqual([]);
  });

  it("has a help entry", () => {
    expect(commandHelp("security")).toContain("varlatch security report [--json]");
  });
});

describe("credential review format", () => {
  it("says relative times coarsely", () => {
    const now = Date.parse("2026-11-10T12:00:00.000Z");
    expect(ago("2026-11-10T11:59:30.000Z", now)).toBe("just now");
    expect(ago("2026-11-10T11:59:00.000Z", now)).toBe("1 minute ago");
    expect(ago("2026-11-10T07:00:00.000Z", now)).toBe("5 hours ago");
    expect(ago("2026-10-01T12:00:00.000Z", now)).toBe("40 days ago");
  });

  it("names a retired machine's state", () => {
    const r = fullReview();
    r.items = [{ ...r.items[0]!, identity: { ...r.items[0]!.identity, state: "retired" } }];
    r.summary = { reviewed: 1, listed: 1, neverUsed: 1, idle: 0, noExpiry: 1 };
    const lines = credentialReviewLines("acme", r, Date.now());
    expect(lines[0]).toBe("Credential review for acme: 1 of 1 machine credential needs a look.");
    expect(lines).toContain(
      "  crd_deploy  deployer credential  for deployer (idn_deploy, service, retired): last used never, no expiry, created 3 days ago, issued by Ada",
    );
  });
});
