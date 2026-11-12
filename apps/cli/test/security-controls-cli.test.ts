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
import type { Approval, SecurityControl, SecurityControlList } from "@varlatch/protocol";
import { EXIT } from "../src/exitCodes.js";
import { commandHelp } from "../src/usage.js";

/**
 * `varlatch security controls` and `varlatch security set` end to end
 * against a local server (ADR-0054 Decisions 1 to 3), with the shared
 * step-up handling: the approval's address on stderr, the wait (polls at
 * the approval's interval, SLOW_DOWN honoured), the request sent again
 * with the Varlatch-Approval header and the identical body; expiry 75,
 * cancelled 77, Ctrl-C 130 with the approval cancelled; assisted mode
 * stops with 75 and resumes with --approval <id>.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-controls-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let controls: SecurityControl[] = [];
/** Whether a PATCH without an approval needs one. */
let loosens = false;
/** The states GET /v1/me/approvals/apr_1 answers, in turn; the last one repeats. "slow" answers SLOW_DOWN. */
let approvalStates: (Approval["state"] | "slow")[] = [];
let approvalCloseReason: Approval["closeReason"] = null;
let expiresInMs = 60_000;
/** Answer every Organization request with PASSKEY_VERIFICATION_REQUIRED for this reason (ADR-0054 Decision 7). */
let verificationRequired: string | null = null;
let requests: { method: string; url: string; approval: string | null; body: string; userAgent: string | null }[] = [];

function control(name: SecurityControl["control"], extra: Partial<SecurityControl> = {}): SecurityControl {
  return { control: name, mode: "off", config: null, version: 0, changedAt: null, changedBy: null, ...extra };
}

function approval(state: Approval["state"]): Approval {
  const created = Date.now();
  return {
    id: "apr_1",
    operation: "security_control.change",
    organization: { id: "org_1", slug: "acme", name: "Acme" },
    summary: {
      title: "Change credential-lifetime in Acme",
      changes: [{ field: "mode", from: "report", to: "off", loosens: true }],
    },
    state,
    closeReason: state === "closed" ? approvalCloseReason : null,
    requestedBy: { credentialKind: "cli", client: "varlatch CLI on Linux" },
    url: "https://varlatch.example/approve/apr_1",
    interval: 1,
    createdAt: new Date(created).toISOString(),
    expiresAt: new Date(created + expiresInMs).toISOString(),
    approvedAt: state === "approved" ? new Date(created).toISOString() : null,
    consumedAt: null,
    closedAt: null,
  };
}

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let body = "";
  req.on("data", (d: Buffer) => (body += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const header = req.headers["varlatch-approval"];
    requests.push({
      method: req.method ?? "",
      url,
      approval: typeof header === "string" ? header : null,
      body,
      userAgent: req.headers["user-agent"] ?? null,
    });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    const error = (status: number, code: string, message: string, details?: Record<string, unknown>) =>
      json(status, { error: { code, message, requestId: "req_1", ...(details ? { details } : {}) } });
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.21.0", capabilities });
    if (verificationRequired && url.startsWith("/v1/organizations/acme")) {
      return error(403, "PASSKEY_VERIFICATION_REQUIRED", "This Organization requires a sign-in with a trusted passkey that verifies you.", {
        control: "passkey-verification",
        reason: verificationRequired,
      });
    }
    if (url === "/v1/organizations/acme/security/controls" && req.method === "GET") {
      const list: SecurityControlList = { items: controls, availableModes: ["off", "report"] };
      return json(200, list);
    }
    const patch = /^\/v1\/organizations\/acme\/security\/controls\/([a-z-]+)$/.exec(url);
    if (patch && req.method === "PATCH") {
      const input = JSON.parse(body) as { mode?: SecurityControl["mode"]; config?: SecurityControl["config"]; expectedVersion: number };
      const current = controls.find((c) => c.control === patch[1])!;
      if (input.expectedVersion !== current.version) return error(409, "VERSION_CONFLICT", "The control changed");
      if (loosens && !header) {
        return error(403, "STEP_UP_REQUIRED", "This change loosens a security control and needs your approval", { approval: approval("pending") });
      }
      if (loosens && header !== "apr_1") return error(409, "APPROVAL_INVALID", "This approval does not fit", { reason: "not-found", approvalId: header });
      const changed = input.mode !== current.mode || (input.config !== undefined && JSON.stringify(input.config) !== JSON.stringify(current.config));
      const next = changed
        ? { ...current, mode: input.mode ?? current.mode, ...(input.config !== undefined ? { config: input.config } : {}), version: current.version + 1, changedAt: "2026-11-10T12:00:00.000Z", changedBy: { id: "idn_ada", name: "Ada" } }
        : current;
      return json(200, { control: next, changed, loosened: changed && loosens });
    }
    if (url === "/v1/me/approvals/apr_1" && req.method === "GET") {
      const state = approvalStates.length > 1 ? approvalStates.shift()! : approvalStates[0] ?? "pending";
      if (state === "slow") return error(429, "SLOW_DOWN", "Polled too soon", { interval: 2 });
      return json(200, approval(state));
    }
    if (url === "/v1/me/approvals/apr_1/cancel" && req.method === "POST") return json(200, approval("closed"));
    if (url.startsWith("/v1/me/approvals/")) return error(404, "RESOURCE_NOT_FOUND", "Approval not found");
    error(404, "RESOURCE_NOT_FOUND", "Not found");
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
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["security.controls"];
  controls = [
    control("requirement-protection"),
    control("admin-step-up", { mode: "report", version: 2, changedAt: "2026-11-09T10:00:00.000Z", changedBy: { id: "idn_ada", name: "Ada" } }),
    control("passkey-verification"),
    control("credential-lifetime", { mode: "report", config: { defaultTtlSeconds: 86400, maxTtlSeconds: 2592000 }, version: 3, changedAt: "2026-11-09T11:00:00.000Z", changedBy: null }),
  ];
  loosens = false;
  verificationRequired = null;
  approvalStates = ["approved"];
  approvalCloseReason = null;
  expiresInMs = 60_000;
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], options: { assisted?: boolean; interruptWhen?: string } = {}): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      // An explicit mode for each run (assisted mode is on under a coding agent's session).
      env: {
        PATH: process.env.PATH,
        HOME: dir,
        VARLATCH_CONFIG_DIR: join(dir, "config"),
        VARLATCH_TOKEN: "vlt_test",
        VARLATCH_ASSISTED: options.assisted ? "1" : "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let interrupted = false;
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
      if (options.interruptWhen && !interrupted && stderr.includes(options.interruptWhen)) {
        interrupted = true;
        child.kill("SIGINT");
      }
    });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const patches = () => requests.filter((r) => r.method === "PATCH");
const polls = () => requests.filter((r) => r.method === "GET" && r.url.startsWith("/v1/me/approvals/"));

describe("varlatch security controls", () => {
  it("lists each control with its mode, lifetimes, version and last change, and says enforce is not available", async () => {
    const r = await cli(["security", "controls"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout.trimEnd().split("\n")).toEqual([
      "Security controls for acme:",
      "  requirement-protection  off      (version 0, never changed)",
      "  admin-step-up           report   (version 2, changed 2026-11-09T10:00:00.000Z by Ada)",
      "  passkey-verification    off      (version 0, never changed)",
      "  credential-lifetime     report   default 1 day, at most 30 days  (version 3, changed 2026-11-09T11:00:00.000Z by the host operator)",
      "",
      "Modes this server offers: off, report. enforce is not available yet.",
      "Loosening a control (a mode towards off, a longer lifetime, cleared settings) needs your approval with a trusted passkey.",
    ]);
  });

  it("--json prints the list as one document", async () => {
    const r = await cli(["security", "controls", "--json"]);
    expect(r.code, r.stderr).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ version: expect.any(Number), organization: "acme", items: controls, availableModes: ["off", "report"] });
  });

  it("fails, naming the capability, on a server without security controls", async () => {
    capabilities = ["security.credential-review"];
    const r = await cli(["security", "controls"]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("lacks the security.controls capability");
    expect(requests.map((q) => q.url)).toEqual(["/v1/meta"]);
  });
});

describe("varlatch security set", () => {
  it("tightens at once, with the current version, and no approval", async () => {
    const r = await cli(["security", "set", "passkey-verification", "report"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe("passkey-verification in acme: off -> report, version 1.\n");
    expect(patches()).toHaveLength(1);
    expect(JSON.parse(patches()[0]!.body)).toEqual({ mode: "report", expectedVersion: 0 });
    expect(patches()[0]!.approval).toBeNull();
    expect(polls()).toEqual([]);
  });

  it("keeps the other lifetime when one is given, and says when nothing changed", async () => {
    const r = await cli(["security", "set", "credential-lifetime", "report", "--max-ttl", "604800"]);
    expect(r.code, r.stderr).toBe(0);
    expect(JSON.parse(patches()[0]!.body)).toEqual({ mode: "report", config: { defaultTtlSeconds: 86400, maxTtlSeconds: 604800 }, expectedVersion: 3 });
    requests = [];
    const same = await cli(["security", "set", "admin-step-up", "report"]);
    expect(same.code, same.stderr).toBe(0);
    expect(same.stdout).toBe("admin-step-up in acme is already report. Nothing was changed.\n");
  });

  it("refuses a mode the server does not offer before sending anything", async () => {
    const r = await cli(["security", "set", "admin-step-up", "enforce"]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("does not offer the mode enforce for admin-step-up yet (it offers off, report)");
    expect(patches()).toEqual([]);
  });

  it("sends enforce for a control the server can enforce, and lists which ones can", async () => {
    controls = controls.map((c) => ({
      ...c,
      availableModes: c.control === "requirement-protection" ? ["off", "report", "enforce"] : ["off", "report"],
    }));
    const listed = await cli(["security", "controls"]);
    expect(listed.code, listed.stderr).toBe(0);
    expect(listed.stdout).toContain("Modes this server offers: off, report, and enforce for requirement-protection.\n");
    requests = [];
    const r = await cli(["security", "set", "requirement-protection", "enforce"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe("requirement-protection in acme: off -> enforce, version 1.\n");
    expect(JSON.parse(patches()[0]!.body)).toEqual({ mode: "enforce", expectedVersion: 0 });
    requests = [];
    const refused = await cli(["security", "set", "admin-step-up", "enforce"]);
    expect(refused.code).toBe(EXIT.failure);
    expect(refused.stderr).toContain("does not offer the mode enforce for admin-step-up yet (it offers off, report)");
    expect(patches()).toEqual([]);
  });

  it("says what turning passkey-verification to enforce does, and how to get back in", async () => {
    controls = controls.map((c) => ({ ...c, availableModes: ["off", "report", "enforce"] }));
    const r = await cli(["security", "set", "passkey-verification", "enforce"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout.split("\n")).toEqual([
      "passkey-verification in acme: off -> enforce, version 1.",
      "From now on acme refuses a person's sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face),",
      "admins included, until they sign in again with one. Machine credentials are not affected.",
      "Someone whose passkeys cannot verify them gets back in only through the host operator: varlatch admin security reset.",
      "",
    ]);
  });

  it("explains a refusal for an unverified sign-in, and exits 77 (ADR-0054 Decision 7)", async () => {
    verificationRequired = "not-user-verified";
    const r = await cli(["security", "controls"]);
    expect(r.code).toBe(EXIT.denied);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("Error PASSKEY_VERIFICATION_REQUIRED: This Organization requires a sign-in with a trusted passkey that verifies you. (request req_1)");
    expect(r.stderr).toContain("  varlatch login --server <url>\n");
    expect(r.stderr).toContain("approve the sign-in in the browser with a trusted passkey that asks for your PIN, fingerprint or face");
    expect(r.stderr).toContain("admin bootstrap or admin recover --cli-credential) is always refused here");
  });

  it("refuses a wrong command line before any request (exit 64)", async () => {
    for (const args of [
      ["security", "set"],
      ["security", "set", "credential-lifetime"],
      ["security", "set", "nonsense", "off"],
      ["security", "set", "admin-step-up", "sometimes"],
      ["security", "set", "admin-step-up", "off", "--max-ttl", "60"],
      ["security", "set", "credential-lifetime", "report", "--max-ttl", "1h"],
      ["security", "set", "credential-lifetime", "report", "--default-ttl", "100", "--max-ttl", "50"],
      ["security", "set", "credential-lifetime", "report", "--clear-config", "--max-ttl", "50"],
      ["security", "controls", "extra"],
      ["--approval"],
    ]) {
      const r = await cli(args);
      expect(r.code, `${args.join(" ")}: ${r.stderr}`).toBe(EXIT.usage);
    }
    expect(requests).toEqual([]);
  });

  it("loosening: prints the approval address on stderr, waits, and sends the identical request with the approval", async () => {
    loosens = true;
    approvalStates = ["pending", "slow", "pending", "approved"];
    const r = await cli(["security", "set", "credential-lifetime", "off"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain("This needs your approval with a trusted passkey: Change credential-lifetime in Acme");
    expect(r.stderr).toContain("  mode: report -> off (loosens)");
    expect(r.stderr).toContain("  https://varlatch.example/approve/apr_1");
    expect(r.stderr).toContain("Waiting for your approval");
    expect(r.stdout).toBe("credential-lifetime in acme: report -> off (default 1 day, at most 30 days), version 4.\nThis loosened the control; your approval was used.\n");
    expect(r.stdout).not.toContain("approve/");
    const [first, second] = patches();
    expect(patches()).toHaveLength(2);
    expect(first!.approval).toBeNull();
    expect(second!.approval).toBe("apr_1");
    expect(second!.body).toBe(first!.body);
    // Every answer was polled, the SLOW_DOWN included; nothing was cancelled.
    expect(polls()).toHaveLength(4);
    expect(requests.some((q) => q.url.endsWith("/cancel"))).toBe(false);
  }, 30_000);

  it("an approval that expires unapproved exits 75 without sending the change again", async () => {
    loosens = true;
    approvalStates = ["pending", "expired"];
    const r = await cli(["security", "set", "credential-lifetime", "off"]);
    expect(r.code, r.stderr).toBe(EXIT.tempfail);
    expect(r.stderr).toContain("expired before it was approved");
    expect(patches()).toHaveLength(1);
  }, 30_000);

  it("a cancelled approval exits 77", async () => {
    loosens = true;
    approvalStates = ["closed"];
    approvalCloseReason = "cancelled";
    const r = await cli(["security", "set", "credential-lifetime", "off"]);
    expect(r.code, r.stderr).toBe(EXIT.denied);
    expect(r.stderr).toContain("Approval apr_1 was cancelled. Nothing was changed.");
    expect(patches()).toHaveLength(1);
  }, 30_000);

  it("Ctrl-C while waiting cancels the approval and exits 130", async () => {
    loosens = true;
    approvalStates = ["pending"];
    const r = await cli(["security", "set", "credential-lifetime", "off"], { interruptWhen: "Waiting for your approval" });
    expect(r.code, r.stderr).toBe(EXIT.interrupted);
    expect(r.stderr).toContain("Stopped waiting. Cancelling approval apr_1; nothing was changed.");
    expect(requests.filter((q) => q.url === "/v1/me/approvals/apr_1/cancel")).toHaveLength(1);
    expect(patches()).toHaveLength(1);
  }, 30_000);

  it("assisted mode: prints the address and the command to run again, exits 75, never polls", async () => {
    loosens = true;
    const r = await cli(["security", "set", "credential-lifetime", "off"], { assisted: true });
    expect(r.code, r.stderr).toBe(EXIT.tempfail);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("https://varlatch.example/approve/apr_1");
    expect(r.stderr).toContain("Coding agent: stop here. Show the address above to the person and ask them to approve it themselves");
    expect(r.stderr).toContain("varlatch --assisted --approval apr_1 security set credential-lifetime off");
    expect(polls()).toEqual([]);
    expect(patches()).toHaveLength(1);
  });

  it("--approval <id> resumes: waits until approved, then sends the change once with the approval", async () => {
    loosens = true;
    approvalStates = ["pending", "approved"];
    const r = await cli(["--approval", "apr_1", "security", "set", "credential-lifetime", "off"], { assisted: true });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("This loosened the control; your approval was used.");
    expect(patches()).toHaveLength(1);
    expect(patches()[0]!.approval).toBe("apr_1");
    expect(polls().length).toBeGreaterThanOrEqual(2);
    // The reads went out without the approval; only the change carried it.
    expect(requests.filter((q) => q.method === "GET").every((q) => q.approval === null)).toBe(true);
  }, 30_000);

  it("--approval with an approval that is not this person's exits 77", async () => {
    loosens = true;
    const r = await cli(["--approval", "apr_other", "security", "set", "credential-lifetime", "off"]);
    expect(r.code, r.stderr).toBe(EXIT.denied);
    expect(r.stderr).toContain("No approval apr_other exists for you");
    expect(patches()).toEqual([]);
  });

  it("has help entries", () => {
    const help = commandHelp("security")!;
    expect(help).toContain("varlatch security controls [--json]");
    expect(help).toContain("varlatch security set <control> <off|report|enforce>");
    expect(commandHelp("admin")).toContain("varlatch admin security reset --org <organization> (--control <name>... | --all)");
  });
});
