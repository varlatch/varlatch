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
import type { ApprovalKeys, CredentialReview, SecurityControl, SecurityControlReport } from "@varlatch/protocol";
import { EXIT } from "../src/exitCodes.js";
import { CHECKLIST, CONTROL_EXPLANATIONS, securityStatusLines, until, type SecurityStatus } from "../src/securityStatus.js";
import { commandHelp } from "../src/usage.js";

/**
 * `varlatch security status` end to end against a local server (ADR-0054
 * Decision 11): the Security page as text and as one JSON document. Each
 * part needs its own permission; a part the caller cannot read is named,
 * not shown, and the command still exits 0.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-security-status-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const outside = join(dir, "outside");
const DAY = 86400_000;

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let refused: Set<string>;
let held: string[] = [];
let requests: string[] = [];

const control = (name: SecurityControl["control"], over: Partial<SecurityControl> = {}): SecurityControl => ({
  control: name,
  mode: "off",
  config: null,
  version: 0,
  changedAt: null,
  changedBy: null,
  ...over,
});

const CONTROLS = [
  control("requirement-protection"),
  control("admin-step-up", { mode: "report", version: 1, changedAt: "2026-11-01T00:00:00.000Z", changedBy: { id: "idn_ada", name: "Ada" } }),
  control("passkey-verification"),
  control("credential-lifetime", { mode: "report", version: 2, config: { defaultTtlSeconds: 86400, maxTtlSeconds: 30 * 86400 } }),
];

const entry = (operation: string, count: number, actor = { id: "idn_ada", name: "Ada", kind: "human" }) => ({
  configVersion: 1,
  operation,
  reason: "no-approval" as const,
  actor,
  count,
  firstSeen: "2026-11-05T10:00:00.000Z",
  lastSeen: "2026-11-09T10:00:00.000Z",
});

function report(): SecurityControlReport {
  const counts = (c: SecurityControl, over: Partial<SecurityControlReport["controls"][number]> = {}) => ({
    control: c.control,
    mode: c.mode,
    version: c.version,
    total: 0,
    currentHour: 0,
    pending: 0,
    entries: [],
    ...over,
  });
  return {
    organizationId: "org_acme",
    days: 30,
    since: "2026-10-11T23:00:00.000Z",
    generatedAt: "2026-11-10T23:00:00.000Z",
    summaryDelayMinutes: 10,
    controls: [
      counts(CONTROLS[0]!),
      counts(CONTROLS[1]!, {
        total: 14,
        currentHour: 2,
        pending: 2,
        entries: [
          entry("grant.create", 7),
          entry("identity.create", 4),
          entry("credential.issue", 2, { id: "idn_ci", name: "deployer", kind: "service" }),
          entry("webhook.update", 1),
        ],
      }),
      counts(CONTROLS[2]!),
      counts(CONTROLS[3]!, { total: 1, entries: [{ ...entry("identity.create", 1), configVersion: 2, reason: "would-default" }] }),
    ],
  };
}

const KEYS: ApprovalKeys = {
  generatedAt: "2026-11-10T23:00:00.000Z",
  summary: { admins: 2, withTrustedKey: 1, withoutTrustedKey: 1 },
  items: [
    {
      identity: { id: "idn_ada", name: "Ada" },
      trusted: 2,
      unconfirmed: 1,
      lastConfirmedAt: "2026-11-02T00:00:00.000Z",
      passkeys: [
        { name: "Laptop", trust: "trusted", trustedVia: "existing-at-upgrade", createdAt: "2026-09-01T00:00:00.000Z", trustedAt: "2026-11-01T00:00:00.000Z" },
        { name: "Phone", trust: "trusted", trustedVia: "confirmed", createdAt: "2026-11-02T00:00:00.000Z", trustedAt: "2026-11-02T00:00:00.000Z" },
        { name: "Tablet", trust: "unconfirmed", trustedVia: null, createdAt: "2026-11-03T00:00:00.000Z", trustedAt: null },
      ],
    },
    { identity: { id: "idn_zoe", name: "Zoe" }, trusted: 0, unconfirmed: 1, lastConfirmedAt: null, passkeys: [] },
  ],
};

function review(): CredentialReview {
  const soon = new Date(Date.now() + 3 * DAY).toISOString();
  return {
    generatedAt: new Date().toISOString(),
    idleDays: 30,
    summary: { reviewed: 4, listed: 2, neverUsed: 1, idle: 0, noExpiry: 2 },
    items: [],
    expiry: {
      warningDays: 7,
      summary: { soon: 1, expired: 0 },
      items: [
        {
          id: "crd_deploy",
          name: "deploy",
          kind: "service",
          createdAt: "2026-10-01T00:00:00.000Z",
          expiresAt: soon,
          lastUsedAt: null,
          issuedBy: null,
          identity: { id: "idn_deploy", name: "deployer", kind: "service", state: "live", disabledReason: null },
          state: "soon",
        },
      ],
    },
  };
}

const REQUIREMENTS = [
  {
    id: "req_1",
    kind: "tailnet",
    target: { kind: "tier", tier: "production" },
    selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    createdAt: "2026-10-01T00:00:00.000Z",
    version: 1,
    updatedAt: null,
  },
];

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = req.url ?? "";
  requests.push(`${req.method} ${url}`);
  const json = (status: number, payload: unknown) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  };
  const path = url.split("?")[0]!;
  if (refused.has(path)) return json(403, { error: { code: "PERMISSION_DENIED", message: "Not allowed", requestId: "req_1" } });
  if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.21.0", capabilities });
  if (url === "/v1/organizations/acme/me/permissions") return json(200, { organizationId: "org_acme", role: "member", actions: held });
  if (url === "/v1/organizations/acme/security/controls") return json(200, { items: CONTROLS, availableModes: ["off", "report"] });
  if (url === "/v1/organizations/acme/security/control-report?days=30") return json(200, report());
  if (url === "/v1/organizations/acme/security/approval-keys") return json(200, KEYS);
  if (url === "/v1/organizations/acme/security/credential-review") return json(200, review());
  if (url === "/v1/organizations/acme/requirements") return json(200, { items: REQUIREMENTS, nextCursor: null });
  if (url === "/v1/organizations/acme/incident-freeze") {
    return json(200, {
      freeze: { id: "ofz_1", frozenAt: "2026-11-11T10:00:00.000Z", frozenBy: { id: "idn_ada", name: "Ada" }, reason: "A CI token leaked", liftedAt: null, liftedBy: null, liftMethod: null },
      resumingTargets: [],
      history: [],
    });
  }
  if (url === "/v1/organizations/quiet/security/controls") return json(200, { items: CONTROLS.map((c) => control(c.control)), availableModes: ["off", "report"] });
  if (url === "/v1/organizations/broken/security/controls") return json(200, { items: CONTROLS, availableModes: ["off", "report"] });
  if (url.startsWith("/v1/organizations/broken/")) return json(500, { error: { code: "INTERNAL", message: "boom", requestId: "req_2" } });
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
  refused = new Set();
  capabilities = ["security.controls", "security.report", "security.approval-keys", "security.credential-review"];
});

interface Result {
  code: number | null;
  /** The signal that ended the CLI, if one did: printed with a failed exit-code assertion. */
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/** The CLI's exit, with what killed it if a signal did, for assertion messages. */
const why = (r: Result) => `${r.signal ? `killed by ${r.signal}; ` : ""}stderr: ${r.stderr}`;

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
    child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

describe("varlatch security status", () => {
  it("shows an open incident freeze first (ADR-0055)", async () => {
    capabilities = [...capabilities, "organizations.incident-freeze"];
    const r = await cli(["security", "status"]);
    expect(r.code, why(r)).toBe(0);
    const lines = r.stdout.split("\n");
    expect(lines[1]).toBe("FROZEN for an incident since 2026-11-11T10:00:00.000Z by Ada: A CI token leaked");
    expect(lines[2]).toContain("Lift it: varlatch org unfreeze acme");
    const doc = JSON.parse((await cli(["security", "status", "--json"])).stdout);
    expect(doc.incidentFreeze).toMatchObject({ id: "ofz_1", reason: "A CI token leaked" });
  });

  it("prints every part, grouped and short, for an admin, and exits 0", async () => {
    const r = await cli(["security", "status"]);
    expect(r.code, why(r)).toBe(0);
    expect(r.stderr).toBe("");
    expect(requests).toEqual([
      "GET /v1/meta",
      "GET /v1/organizations/acme/security/controls",
      "GET /v1/organizations/acme/security/control-report?days=30",
      "GET /v1/organizations/acme/security/approval-keys",
      "GET /v1/organizations/acme/security/credential-review",
      "GET /v1/organizations/acme/requirements",
    ]);
    const out = r.stdout;
    expect(out).toMatch(/^Security for acme\nEvery control is off by default\. Turned on here: admin-step-up \(report\), credential-lifetime \(report\)\.\n/);
    expect(out).toContain("Controls (counts of the last 30 days)");
    expect(out).toContain("  requirement-protection  off     nothing counted\n");
    expect(out).toContain("  admin-step-up           report  14 counted, 2 this hour\n");
    expect(out).toContain("      grant.create  no-approval  by Ada: 7\n");
    expect(out).toContain("      credential.issue  no-approval  by deployer (service): 2\n");
    expect(out).not.toContain("webhook.update");
    expect(out).toContain("      and 1 more entry (--json lists all)\n");
    expect(out).toContain("  credential-lifetime     report  default 1 day, at most 30 days; 1 counted\n");
    expect(out).toContain("  Modes: off, report. Enforce: coming in a later release.\n");
    expect(out).toContain("  Ada  2 trusted, 1 unconfirmed\n");
    expect(out).toContain("  Zoe  0 trusted, 1 unconfirmed: cannot approve anything yet\n");
    expect(out).toContain("varlatch admin reenroll --identity <id>");
    expect(out).toContain("  Use and expiry policy: 2 of 4 machine credentials are never used, unused for 30 days, or without expiry.\n");
    expect(out).toContain("  Expiry warnings: 1 service credential expires within 7 days.\n");
    expect(out).toMatch(/ {2}crd_deploy {2}deploy {2}for deployer: expires in 3 days \(/);
    expect(out).toContain("  1 requirement. requirement-protection is off.\n");
    expect(out).toContain("Checklist\n");
    for (const item of CHECKLIST) expect(out).toContain(item.url);
    expect(out).not.toContain("Not shown");
    expect(out).not.toContain("vlt_");
  });

  it("--json prints one versioned document with every part", async () => {
    const r = await cli(["security", "status", "--json"]);
    expect(r.code, why(r)).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(Object.keys(doc)).toEqual([
      "version", "organization", "enforceAvailable", "enforceable", "controls", "approvalKeys", "credentialReview", "requirements", "checklist", "unavailable", "incidentFreeze",
    ]);
    expect(doc).toMatchObject({ version: expect.any(Number), organization: "acme", enforceAvailable: false, enforceable: [], unavailable: [] });
    expect(doc.controls.availableModes).toEqual(["off", "report"]);
    expect(doc.controls.window).toEqual({ days: 30, since: "2026-10-11T23:00:00.000Z", generatedAt: "2026-11-10T23:00:00.000Z" });
    expect(doc.controls.items.map((c: { control: string }) => c.control)).toEqual([
      "requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime",
    ]);
    const step = doc.controls.items[1];
    expect(step).toMatchObject({ control: "admin-step-up", mode: "report", version: 1, counts: { total: 14, currentHour: 2, pending: 2 } });
    expect(step.counts.entries).toHaveLength(4);
    expect(step.explanation.report).toContain("without an approval");
    expect(step.explanation.enforce).toContain("approval with a trusted passkey");
    const passkey = doc.controls.items[2];
    expect(passkey.explanation.report).toContain("Only requests that were allowed and succeeded count");
    expect(passkey.explanation.report).toContain("best-effort");
    expect(doc.approvalKeys).toEqual(KEYS);
    expect(doc.credentialReview.expiry.items[0].id).toBe("crd_deploy");
    expect(doc.requirements).toEqual({ count: 1, protectedBy: "requirement-protection", items: REQUIREMENTS });
    expect(doc.checklist).toEqual(CHECKLIST);
  });

  it("for a member, names the parts it cannot read and still exits 0, asking for the approval keys only after the counts", async () => {
    refused = new Set([
      "/v1/organizations/acme/security/control-report",
      "/v1/organizations/acme/security/approval-keys",
      "/v1/organizations/acme/security/credential-review",
      "/v1/organizations/acme/requirements",
    ]);
    const r = await cli(["security", "status", "--json"]);
    expect(r.code, why(r)).toBe(0);
    // The approval keys need what the counts need: not asked again.
    expect(requests).not.toContain("GET /v1/organizations/acme/security/approval-keys");
    const doc = JSON.parse(r.stdout);
    expect(doc.unavailable).toEqual([
      { section: "controlReport", reason: "not-permitted" },
      { section: "approvalKeys", reason: "not-permitted" },
      { section: "credentialReview", reason: "not-permitted" },
      { section: "requirements", reason: "not-permitted" },
    ]);
    expect(doc).toMatchObject({ approvalKeys: null, credentialReview: null, requirements: null, controls: { window: null } });
    expect(doc.controls.items.every((c: { counts: unknown }) => c.counts === null)).toBe(true);

    const text = await cli(["security", "status"]);
    expect(text.code, why(text)).toBe(0);
    expect(text.stdout).toContain("  admin-step-up           report\n");
    expect(text.stdout).not.toContain("Approval keys");
    expect(text.stdout).toContain("Not shown\n  counts of the controls: needs organization.manage. An organization admin manages this.\n");
    expect(text.stdout).toContain("  credential review: needs identity.manage.");
    expect(text.stdout).toContain("  Tailnet Requirements: needs policy.read.");
  });

  it("asks only for what the caller's own permissions allow, where the server reports them", async () => {
    capabilities = [...capabilities, "organizations.permissions"];
    held = ["organization.read", "project.read", "identity.manage"];
    // Anything else would be refused and audited.
    refused = new Set([
      "/v1/organizations/acme/security/control-report",
      "/v1/organizations/acme/security/approval-keys",
      "/v1/organizations/acme/requirements",
    ]);
    const r = await cli(["security", "status", "--json"]);
    expect(r.code, why(r)).toBe(0);
    expect(requests).toEqual([
      "GET /v1/meta",
      "GET /v1/organizations/acme/me/permissions",
      "GET /v1/organizations/acme/security/controls",
      "GET /v1/organizations/acme/security/credential-review",
    ]);
    const doc = JSON.parse(r.stdout);
    expect(doc.unavailable).toEqual([
      { section: "controlReport", reason: "not-permitted" },
      { section: "approvalKeys", reason: "not-permitted" },
      { section: "requirements", reason: "not-permitted" },
    ]);
    expect(doc.credentialReview.expiry.items[0].id).toBe("crd_deploy");
  });

  it("names the parts an older server cannot give", async () => {
    capabilities = ["security.controls", "security.credential-review"];
    const r = await cli(["security", "status", "--json"]);
    expect(r.code, why(r)).toBe(0);
    expect(JSON.parse(r.stdout).unavailable).toEqual([
      { section: "controlReport", reason: "not-supported" },
      { section: "approvalKeys", reason: "not-supported" },
    ]);
    expect(requests).not.toContain("GET /v1/organizations/acme/security/approval-keys");
  });

  it("says that every control is off when none was turned on; --org and --server work outside a repository", async () => {
    capabilities = ["security.controls"];
    const r = await cli(["security", "status", "--org", "quiet", "--server", origin], outside);
    expect(r.code, why(r)).toBe(0);
    expect(r.stdout).toContain("Every control is off, as it is by default: nothing is counted, refused or changed.\n");
  });

  it("fails on a server without security controls, and on a server error", async () => {
    capabilities = [];
    const old = await cli(["security", "status"]);
    expect(old.code).toBe(EXIT.failure);
    expect(old.stdout).toBe("");
    expect(old.stderr).toContain("lacks the security.controls capability");

    capabilities = ["security.controls", "security.report"];
    const broken = await cli(["security", "status", "--org", "broken"]);
    expect(broken.code).not.toBe(0);
    expect(broken.stdout).toBe("");
  });

  it("refuses a wrong command line before any request (exit 64)", async () => {
    for (const args of [["security", "status", "extra"], ["security", "status", "--jsno"]]) {
      const r = await cli(args);
      expect(r.code, args.join(" ")).toBe(EXIT.usage);
      expect(r.stderr).toContain("varlatch security status");
    }
    expect(requests).toEqual([]);
  });

  it("has a help entry", () => {
    expect(commandHelp("security")).toContain("varlatch security status [--json]");
  });
});

describe("status format", () => {
  it("says beside passkey-verification's counts that access counts are a lower bound, also at zero", () => {
    const status: SecurityStatus = {
      organization: "acme",
      enforceAvailable: false,
      enforceable: [],
      controls: {
        availableModes: ["off", "report"],
        window: { days: 30, since: "2026-10-11T23:00:00.000Z", generatedAt: "2026-11-10T23:00:00.000Z" },
        items: [
          {
            ...control("passkey-verification", { mode: "report", version: 1 }),
            explanation: CONTROL_EXPLANATIONS["passkey-verification"],
            counts: { total: 0, currentHour: 0, pending: 0, entries: [] },
          },
        ],
      },
      approvalKeys: null,
      credentialReview: null,
      requirements: null,
      checklist: CHECKLIST,
      unavailable: [],
    };
    const lines = securityStatusLines(status, Date.now());
    const at = lines.indexOf("  passkey-verification  report  nothing counted");
    expect(at).toBeGreaterThan(0);
    expect(lines[at + 1]).toBe("      only allowed, successful requests count; access counts are best-effort, so this is a lower bound");
  });

  it("names the controls this server can enforce, and says the others come later", () => {
    const item = (name: SecurityControl["control"], modes: ("off" | "report" | "enforce")[]) => ({
      ...control(name, { availableModes: modes }),
      explanation: CONTROL_EXPLANATIONS[name],
      counts: null,
    });
    const status: SecurityStatus = {
      organization: "acme",
      enforceAvailable: true,
      enforceable: ["requirement-protection"],
      controls: {
        availableModes: ["off", "report"],
        window: null,
        items: [item("requirement-protection", ["off", "report", "enforce"]), item("admin-step-up", ["off", "report"])],
      },
      approvalKeys: null,
      credentialReview: null,
      requirements: null,
      checklist: CHECKLIST,
      unavailable: [],
      incidentFreeze: null,
    };
    expect(securityStatusLines(status, Date.now())).toContain(
      "  Modes: off, report, and enforce for requirement-protection. Enforce for the others: coming in a later release.",
    );
  });

  it("says how long until an expiry in whole days", () => {
    const now = Date.parse("2026-11-10T12:00:00.000Z");
    expect(until("2026-11-10T20:00:00.000Z", now)).toBe("within a day");
    expect(until("2026-11-13T11:00:00.000Z", now)).toBe("in 3 days");
  });
});
