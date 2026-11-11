// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { VarlatchApiError, VarlatchClient, type Approval } from "@varlatch/sdk";
import { apiErrorExit, EXIT } from "../src/exitCodes.js";
import { FreezeUsageError, freezeReason } from "../src/freeze.js";
import { retryOnce } from "../src/strictRun.js";
import { commandHelp } from "../src/usage.js";

/**
 * The incident freeze from the CLI (ADR-0055 Decision 11): `org freeze`
 * names the slug again with --confirm (assisted mode prints the person's
 * command), `org unfreeze` lists what resumes and asks for the person's
 * approval, and ORGANIZATION_FROZEN is final for the invocation: never
 * retried, exit 77.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-freeze-"));
const bundle = join(dir, "varlatch.cjs");
const ORG = "/v1/organizations/acme";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let requests: { method: string; url: string; body: unknown; approval: string | null }[] = [];
let frozen = true;
/** Whether the caller may list the Sync Targets (config.sync.manage). */
let listsTargets = true;

const FREEZE = {
  id: "ofz_1",
  frozenAt: "2026-11-11T10:00:00.000Z",
  frozenBy: { id: "idn_ada", name: "Ada" },
  reason: "A CI token leaked",
  liftedAt: null,
  liftedBy: null,
  liftMethod: null,
};
const TARGET = { id: "snt_1", projectSlug: "api", environmentName: "production", platform: "coolify", destination: "app1" };

function approval(state: Approval["state"]): Approval {
  const created = Date.now();
  return {
    id: "apr_1",
    operation: "organization.unfreeze",
    organization: { id: "org_1", slug: "acme", name: "Acme" },
    summary: { title: "Lift the incident freeze of Acme", changes: [{ field: "freeze", from: "frozen", to: "lifted", loosens: true }] },
    state,
    closeReason: null,
    requestedBy: { credentialKind: "cli", client: "varlatch CLI on Linux" },
    url: "https://varlatch.example/approve/apr_1",
    interval: 1,
    createdAt: new Date(created).toISOString(),
    expiresAt: new Date(created + 600_000).toISOString(),
    approvedAt: state === "approved" ? new Date(created).toISOString() : null,
    consumedAt: null,
    closedAt: null,
  };
}

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const header = req.headers["varlatch-approval"];
    if (url !== "/") requests.push({ method: req.method ?? "", url, body: raw ? JSON.parse(raw) : undefined, approval: typeof header === "string" ? header : null });
    const json = (status: number, payload: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...headers });
      res.end(JSON.stringify(payload));
    };
    const error = (status: number, code: string, message: string, details?: Record<string, unknown>, headers: Record<string, string> = {}) =>
      json(status, { error: { code, message, requestId: "req_1", ...(details ? { details } : {}) } }, headers);
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.22.0", capabilities });
    if (url === `${ORG}/incident-freeze` && req.method === "POST") return json(201, { ...FREEZE, reason: (JSON.parse(raw) as { reason: string }).reason });
    if (url === `${ORG}/incident-freeze` && req.method === "GET") {
      return json(200, { freeze: frozen ? FREEZE : null, resumingTargets: listsTargets ? (frozen ? [TARGET] : []) : null, history: [] });
    }
    if (url === `${ORG}/incident-freeze/ofz_1/lift` && req.method === "POST") {
      if (!header) return error(403, "STEP_UP_REQUIRED", "This needs your approval with a trusted passkey", { approval: approval("pending") });
      return json(200, { freeze: { ...FREEZE, liftedAt: "2026-11-11T11:00:00.000Z", liftedBy: FREEZE.frozenBy, liftMethod: "approval" }, resumingTargets: listsTargets ? [TARGET] : null });
    }
    if (url === "/v1/me/approvals/apr_1" && req.method === "GET") return json(200, approval("approved"));
    if (url === `${ORG}/deletion` && req.method === "GET") {
      return error(409, "ORGANIZATION_FROZEN", "This Organization is frozen for an incident since 2026-11-11T10:00:00.000Z. Nothing was read, changed or sent.", { freezeId: "ofz_1", frozenAt: FREEZE.frozenAt }, { "Retry-After": "300" });
    }
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
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["organizations.incident-freeze", "organizations.delete"];
  frozen = true;
  listsTargets = true;
});

function cli(args: string[], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: dir,
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

describe("varlatch org freeze", () => {
  it("freezes with --reason and --confirm, and says what stops", async () => {
    const r = await cli(["org", "freeze", "acme", "--reason", "A CI token leaked", "--confirm", "acme", "--server", origin]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "POST", url: `${ORG}/incident-freeze`, body: { reason: "A CI token leaked" }, approval: null }]);
    expect(r.stdout).toContain("acme is frozen for an incident since 2026-11-11T10:00:00.000Z [ofz_1].");
    expect(r.stdout).toContain("keep a break-glass credential outside Varlatch first");
    expect(r.stdout).toContain("Lift it with your approval: varlatch org unfreeze acme");
  });

  it("refuses without --confirm or --reason before any request; assisted mode gives the person's command", async () => {
    const plain = await cli(["org", "freeze", "acme", "--reason", "leak", "--server", origin]);
    expect(plain.code).toBe(EXIT.usage);
    expect(plain.stderr).toContain(`varlatch org freeze acme --reason leak --confirm acme --server ${origin}`);
    const other = await cli(["org", "freeze", "acme", "--reason", "leak", "--confirm", "beta", "--server", origin]);
    expect(other.code).toBe(EXIT.usage);
    const noReason = await cli(["org", "freeze", "acme", "--confirm", "acme", "--server", origin]);
    expect(noReason.code).toBe(EXIT.usage);
    expect(noReason.stderr).toContain("--reason is required");
    const assisted = await cli(["org", "freeze", "acme", "--reason", "leak", "--server", origin], { VARLATCH_ASSISTED: "1" });
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain("That is the human's decision. With their approval, add --confirm acme.");
    expect(assisted.stderr).toContain("Nothing was changed.");
    expect(requests).toEqual([]);
  });

  it("fails on a server without the incident freeze", async () => {
    capabilities = [];
    const r = await cli(["org", "freeze", "acme", "--reason", "leak", "--confirm", "acme", "--server", origin]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("has no incident freeze");
    expect(changes()).toEqual([]);
  });

  it("has help entries, the host operator's lift included", () => {
    expect(commandHelp("org")).toContain("varlatch org freeze <slug> --reason <text> --confirm <slug>");
    expect(commandHelp("org")).toContain("varlatch org unfreeze <slug>");
    expect(commandHelp("admin")).toContain("varlatch admin unfreeze --org <slug> --confirm <slug>");
  });

  it("checks the reason", () => {
    expect(freezeReason("  leak  ")).toBe("leak");
    expect(() => freezeReason("   ")).toThrow(FreezeUsageError);
    expect(() => freezeReason("x".repeat(201))).toThrow(FreezeUsageError);
  });
});

describe("varlatch org unfreeze", () => {
  it("lists the Targets that resume, asks for the approval, waits, and lifts with it", async () => {
    const r = await cli(["org", "unfreeze", "acme", "--server", origin]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain("acme is frozen since 2026-11-11T10:00:00.000Z by Ada: A CI token leaked");
    expect(r.stderr).toContain("api/production -> coolify app1 [snt_1]");
    expect(r.stderr).toContain("https://varlatch.example/approve/apr_1");
    expect(changes().map((c) => [c.url, c.approval])).toEqual([
      [`${ORG}/incident-freeze/ofz_1/lift`, null],
      [`${ORG}/incident-freeze/ofz_1/lift`, "apr_1"],
    ]);
    expect(r.stdout).toContain("Freeze of acme lifted at 2026-11-11T11:00:00.000Z [ofz_1].");
  });

  it("does not name the Sync Targets to a caller who may not list them", async () => {
    listsTargets = false;
    const r = await cli(["org", "unfreeze", "acme", "--server", origin]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain("Sync Targets that were not paused or revoked resume pushing (listing them needs config.sync.manage).");
    expect(r.stderr).not.toContain("snt_1");
    expect(r.stdout).toContain("Freeze of acme lifted");
    expect(r.stdout).not.toContain("snt_1");
  });

  it("in assisted mode stops at the approval with exit 75", async () => {
    const r = await cli(["org", "unfreeze", "acme", "--server", origin], { VARLATCH_ASSISTED: "1" });
    expect(r.code).toBe(EXIT.tempfail);
    expect(r.stderr).toContain("https://varlatch.example/approve/apr_1");
    expect(changes()).toHaveLength(1);
  });

  it("says when the organization is not frozen", async () => {
    frozen = false;
    const r = await cli(["org", "unfreeze", "acme", "--server", origin]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("acme is not frozen.");
    expect(changes()).toEqual([]);
  });
});

describe("ORGANIZATION_FROZEN", () => {
  it("is final for the invocation: one request, exit 77, the message shown", async () => {
    const r = await cli(["org", "deletion", "acme", "--server", origin]);
    expect(r.code).toBe(EXIT.denied);
    expect(r.stderr).toContain("frozen for an incident");
    expect(requests.filter((q) => q.url === `${ORG}/deletion`)).toHaveLength(1);
  });

  it("is never retried by the SDK or by the retrieval's one retry", async () => {
    let calls = 0;
    const api = new VarlatchClient({
      server: "http://varlatch.invalid",
      token: "vlt_test",
      fetch: (async () => {
        calls++;
        return new Response(JSON.stringify({ error: { code: "ORGANIZATION_FROZEN", message: "frozen", requestId: "r" } }), {
          status: 409,
          headers: { "Content-Type": "application/json", "Retry-After": "300" },
        });
      }) as typeof fetch,
    });
    const err = await retryOnce(() => api.strictRetrieval("acme", "api", "production")).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VarlatchApiError);
    expect((err as VarlatchApiError).code).toBe("ORGANIZATION_FROZEN");
    expect(calls).toBe(1);
    expect(apiErrorExit(err as VarlatchApiError)).toBe(EXIT.denied);
  });
});
